package policy

// Structural analysis of a policy's rule ordering.
//
// Check (check.go) answers one question: can a self-asserted identity label
// bypass a mode restriction? This file answers the other questions that matter
// when a policy is *edited* rather than merely evaluated, all of which come from
// the same property — the rule list is ordered and the first match decides:
//
//   - A rule can be unreachable, because an earlier rule already matches
//     everything it matches. Nothing it says has any effect, and a reader who
//     does not simulate the order will believe it does.
//   - A rule can shadow a later one, matching some or all of the later rule's
//     requests first — silently changing the later rule's meaning without
//     touching its text.
//   - A rule can be redundant, saying the same thing an earlier rule already
//     said with the same allow/deny outcome.
//
// None of this is visible in a JSON diff. Two policies that differ by one
// appended rule can differ by nothing at all in effective authorization, or by
// far more than the rule appears to grant.
//
// **Coverage is approximated, deliberately.** Exact glob intersection is not
// decidable with this matcher, so coverage is tested by the same
// literal-against-pattern method secretsOverlap uses (see check.go's note): it
// recognises identical patterns and a broader pattern containing a narrower one,
// which is how policies are written in practice. The bias is the same as
// Check's — over-report rather than under-report, because the cost of a false
// positive is a second look and the cost of a false negative is a credential in
// a transcript.

import (
	"fmt"
	"slices"
	"strings"
)

// Severity separates findings that must block an automatic edit from findings
// worth showing the operator. The distinction is not about how alarming a
// finding sounds: it is about whether applying the policy anyway would install
// something whose effective authorization differs from what was presented.
type Severity int

const (
	// SeverityWarning describes a policy that means what it says, but says it
	// wastefully or in a way likely to surprise later — a redundant rule, a
	// rule that broadens access beyond what was asked for.
	SeverityWarning Severity = iota
	// SeverityError describes a policy whose text and effect disagree: a rule
	// that cannot fire at all, or one that silently changes another's meaning.
	SeverityError
)

func (s Severity) String() string {
	if s == SeverityError {
		return "error"
	}
	return "warning"
}

// Finding kinds. These are compared programmatically by callers deciding
// whether to block, so they are named constants rather than free text.
const (
	// FindingUnreachable: an earlier rule fully covers this one, so it never fires.
	FindingUnreachable = "unreachable"
	// FindingShadows: this rule matches some requests a later rule was written
	// for. A warning: it is how an exception-before-general policy is written.
	FindingShadows = "shadows"
	// FindingRedundant: an earlier rule fully covers this one AND reaches the same
	// allow/deny outcome, so removing this rule changes nothing.
	FindingRedundant = "redundant"
	// FindingGetGranted: this allow-rule permits raw `get` on some ref.
	FindingGetGranted = "get-granted"
	// FindingBypassableModes: a mode restriction defeated by an overlapping rule
	// (Check's finding, surfaced here so one report carries everything).
	FindingBypassableModes = "bypassable-modes"
	// FindingAgentAssertableGet: the set of identity labels that reach raw `get`
	// somewhere in this policy. Every one of them is a string an AI agent's tool
	// shell can type, whatever the rule's description says the caller is.
	FindingAgentAssertableGet = "agent-assertable-get"
	// FindingDenyAgentsNoop: deny_agents on a deny-rule, which already refuses
	// every request it matches, agent or not. Harmless, but it reads as if it
	// did something.
	FindingDenyAgentsNoop = "deny-agents-noop"
	// FindingDenyAgentsIdentityScoped: a deny_agents rule limited to particular
	// identities. An agent asserting any other --as label does not match it,
	// so the denial holds for a ref only if no other rule grants that label.
	FindingDenyAgentsIdentityScoped = "deny-agents-identity-scoped"
)

// contextDiff reports how two rules' outcomes compare across the two contexts a
// request can be evaluated in. Coverage and intersection do not depend on
// context — deny_agents never changes whether a rule matches — but the outcome
// does, so every ordering finding is judged in both.
type contextDiff struct {
	nonAgent bool // the rules decide differently for a request with no agent detected
	agent    bool // the rules decide differently for a request from an agent context
}

func (d contextDiff) any() bool { return d.nonAgent || d.agent }

func compareOutcomes(a, b Rule) contextDiff {
	return contextDiff{
		nonAgent: a.outcome(false) != b.outcome(false),
		agent:    a.outcome(true) != b.outcome(true),
	}
}

// contextLabel names the context a finding applies in, for a message. Only an
// agent-only difference is qualified: a difference for ordinary requests is the
// finding the analysis always reported, and is described as it always was.
func (d contextDiff) contextLabel() (suffix string, agent bool) {
	if d.nonAgent {
		return "", false
	}
	return " for agent contexts", true
}

// Finding is one structural observation about a policy.
type Finding struct {
	Kind     string // one of the Finding* constants
	Severity Severity
	Rule     int    // the rule the finding is about
	Other    int    // the related rule, or -1 when the finding involves only one
	Message  string // one line, written for an operator reading a terminal
}

// Analysis is the full structural report for a policy.
type Analysis struct {
	Findings []Finding
}

// Errors returns only the findings that should block an automatic apply.
func (a Analysis) Errors() []Finding {
	var out []Finding
	for _, f := range a.Findings {
		if f.Severity == SeverityError {
			out = append(out, f)
		}
	}
	return out
}

// Warnings returns only the non-blocking findings.
func (a Analysis) Warnings() []Finding {
	var out []Finding
	for _, f := range a.Findings {
		if f.Severity == SeverityWarning {
			out = append(out, f)
		}
	}
	return out
}

// OK reports whether the policy carries no blocking finding.
func (a Analysis) OK() bool { return len(a.Errors()) == 0 }

// Analyze runs the full structural analysis: ordering problems from this file,
// plus the leak-containment findings from Check, in one report.
//
// It folds Check in rather than leaving callers to run both because the two
// answer the same operator question — "is this policy going to do what I think"
// — and a caller that ran only one of them would give a clean bill of health on
// a policy the other rejects.
func (p *Policy) Analyze() Analysis {
	var a Analysis

	// Ordering: for each rule, ask what the rules *before* it already do.
	for i := range p.Rules {
		covered, by := p.coveredBefore(i)
		if !covered {
			continue
		}
		diff := compareOutcomes(p.Rules[by], p.Rules[i])
		if !diff.any() {
			// Same outcome in both contexts: the rule is dead weight rather
			// than a lie.
			a.Findings = append(a.Findings, Finding{
				Kind: FindingRedundant, Severity: SeverityWarning, Rule: i, Other: by,
				Message: fmt.Sprintf("rule %d is redundant: rule %d already matches everything it matches, with the same %s outcome",
					i, by, allowWord(p.Rules[i].Allow)),
			})
			continue
		}
		// Different outcome in at least one context: the rule claims to do
		// something it cannot do. An agent-only difference is the case that
		// matters most for deny_agents — an earlier allow covering a later
		// agent-denying rule means the denial never takes effect.
		suffix, agentCtx := diff.contextLabel()
		a.Findings = append(a.Findings, Finding{
			Kind: FindingUnreachable, Severity: SeverityError, Rule: i, Other: by,
			Message: fmt.Sprintf("rule %d is unreachable%s: rule %d matches everything it matches first and %s, so this rule's %s never takes effect",
				i, suffix, by, allowVerb(p.Rules[by].outcome(agentCtx)), outcomeWord(p.Rules[i], agentCtx)),
		})
	}

	// Shadowing: a partial overlap that changes a later rule's meaning without
	// making it wholly unreachable. Full coverage is already reported above, so
	// only the partial case is added here — reporting both would name the same
	// pair twice with two different explanations.
	for i := range p.Rules {
		for j := i + 1; j < len(p.Rules); j++ {
			diff := compareOutcomes(p.Rules[i], p.Rules[j])
			if !diff.any() {
				continue // same outcome in both contexts: order does not change the result
			}
			if ruleCovers(p.Rules[i], p.Rules[j]) {
				continue // reported as unreachable above
			}
			if !rulesIntersect(p.Rules[i], p.Rules[j]) {
				continue
			}
			// A warning, not an error, and deliberately so. Putting a narrow
			// exception above a general rule is the standard way to write a
			// first-match policy — "deny agent-x this token, allow every other
			// agent-*" is a partial overlap with the opposite outcome, and it is
			// correct. Nothing in the policy distinguishes that from an
			// accidental overlap, so the finding is reported and the operator
			// decides. Treating it as blocking would make this tool refuse to
			// write ordinary, correct policies.
			suffix, agentCtx := diff.contextLabel()
			a.Findings = append(a.Findings, Finding{
				Kind: FindingShadows, Severity: SeverityWarning, Rule: i, Other: j,
				Message: fmt.Sprintf("rule %d shadows part of rule %d%s: requests matching both are decided by rule %d (%s), not rule %d (%s) — deliberate if rule %d is an exception to rule %d, a mistake if not",
					i, j, suffix, i, outcomeWord(p.Rules[i], agentCtx), j, outcomeWord(p.Rules[j], agentCtx), i, j),
			})
		}
	}

	// deny_agents placement. Neither finding blocks: the first is a no-op and the
	// second is a correct policy whenever no other rule grants the ref to the
	// labels it leaves out — which only the operator knows is intended.
	for i, r := range p.Rules {
		if !r.DenyAgents {
			continue
		}
		if !r.Allow {
			a.Findings = append(a.Findings, Finding{
				Kind: FindingDenyAgentsNoop, Severity: SeverityWarning, Rule: i, Other: -1,
				Message: fmt.Sprintf("rule %d sets deny_agents on a deny-rule, which already refuses every request it matches — the field has no effect here", i),
			})
			continue
		}
		if len(r.Identities) > 0 && !slices.Contains(r.Identities, "*") {
			a.Findings = append(a.Findings, Finding{
				Kind: FindingDenyAgentsIdentityScoped, Severity: SeverityWarning, Rule: i, Other: -1,
				Message: fmt.Sprintf("rule %d denies agent contexts only for identities=%s — identity labels are self-asserted, so an agent passing another --as label is not stopped by this rule; to deny agents on secrets=%s whatever label they assert, drop the identities condition and place the rule above every broader grant",
					i, patternList(r.Identities), patternList(r.Secrets)),
			})
		}
	}

	// Leak containment, from check.go.
	rep := p.Check()
	for _, g := range rep.GetOpen {
		cond := ""
		if g.Conditional {
			cond = ", within its time window"
		}
		a.Findings = append(a.Findings, Finding{
			Kind: FindingGetGranted, Severity: SeverityWarning, Rule: g.Rule, Other: -1,
			Message: fmt.Sprintf("rule %d permits raw `get` on secrets=%s for identities=%s%s — the caller receives the value itself, not brokered use of it",
				g.Rule, patternList(g.Secrets), patternList(g.Identities), cond),
		})
	}
	for _, w := range rep.Weakened {
		a.Findings = append(a.Findings, Finding{
			Kind: FindingBypassableModes, Severity: SeverityError, Rule: w.RestrictedRule, Other: w.OpenRule,
			Message: fmt.Sprintf("rule %d restricts identities=%s to brokered delivery on %s, but rule %d permits `get` on an overlapping ref for identities=%s — identity labels are self-asserted, so the restriction does not hold",
				w.RestrictedRule, patternList(w.RestrictedIDs), patternList(w.Secrets), w.OpenRule, patternList(w.OpenIDs)),
		})
	}
	if labels := agentAssertableGetLabels(rep); len(labels) > 0 {
		a.Findings = append(a.Findings, Finding{
			Kind: FindingAgentAssertableGet, Severity: SeverityWarning, Rule: -1, Other: -1,
			Message: fmt.Sprintf("%d identity label(s) reach raw `get` somewhere in this policy: %s — each is a string an AI agent's tool shell can assert, whatever a rule's description says the caller is. A `get` from an agent shell is refused at runtime (see internal/agent), but nothing stops a human, a script, or an unrecognised harness from asserting these",
				len(labels), strings.Join(labels, " ")),
		})
	}

	return a
}

// agentAssertableGetLabels returns the union of identity patterns that reach raw
// `get`, sorted, with the "matches every identity" case rendered as "*".
//
// The per-rule get-granted findings above answer "which rules hand back a raw
// value". This answers a different question: which labels can be typed to
// obtain one. That is a set union across rules, and reading it
// off a list of per-rule findings is exactly the manual step an operator skips.
func agentAssertableGetLabels(rep Report) []string {
	seen := map[string]bool{}
	for _, g := range rep.GetOpen {
		if len(g.Identities) == 0 {
			// A rule with no identities matches every label, including one
			// nobody has thought of yet.
			seen["*"] = true
			continue
		}
		for _, id := range g.Identities {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// coveredBefore reports whether some rule before index i fully covers rule i,
// and which one. "Fully covers" means every request rule i matches is also
// matched by the earlier rule — so the earlier rule always decides first and
// rule i never fires.
func (p *Policy) coveredBefore(i int) (bool, int) {
	for j := range i {
		if ruleCovers(p.Rules[j], p.Rules[i]) {
			return true, j
		}
	}
	return false, -1
}

// ruleCovers reports whether every request matching inner also matches outer.
//
// Each dimension is independent, and an empty condition list means "matches
// anything on this dimension", so outer covers inner exactly when outer is at
// least as permissive on every dimension at once.
//
// Time conditions are handled the same way but are worth naming separately: an
// unconditional outer rule covers a time-limited inner rule (the window is a
// subset of always), while a time-limited outer rule is never treated as
// covering anything, because outside its window it matches nothing at all.
func ruleCovers(outer, inner Rule) bool {
	return patternsCover(outer.Secrets, inner.Secrets) &&
		patternsCover(outer.Identities, inner.Identities) &&
		patternsCover(outer.Modes, inner.Modes) &&
		timeCovers(outer, inner)
}

// patternsCover reports whether every value the inner pattern list accepts is
// also accepted by the outer list.
//
// An empty outer list accepts everything and so covers any inner list. A
// non-empty outer list against an empty inner list is the reverse — inner
// accepts everything, and a constrained outer cannot cover that.
//
// For the both-non-empty case, each inner pattern is tested as a literal
// against the outer list. This is the approximation described at the top of the
// file: "bao:app/*" covers "bao:app/gitea#token", and an identical pattern
// covers itself, but an exotic partial overlap between two globs is not
// modelled.
func patternsCover(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, in := range inner {
		if !anyWildcard(outer, in) {
			return false
		}
	}
	return true
}

// timeCovers reports whether outer's schedule restriction is at least as
// permissive as inner's. A rule with no weekday, monthday or hours condition
// applies at every instant; any of the three narrows it.
//
// Anything short of "outer is unconditional, or outer and inner carry the same
// conditions" is reported as not covering. Modelling partial overlap between two
// schedules (does Mon-Fri 08:00-18:00 cover Wed 09:00-17:00?) would be sound to
// add later, but guessing wrong here would silently suppress a real finding, and
// under-claiming coverage only costs an extra reported overlap.
func timeCovers(outer, inner Rule) bool {
	if !ruleIsScheduled(outer) {
		return true
	}
	return sameStrings(outer.Weekdays, inner.Weekdays) &&
		sameInts(outer.Monthdays, inner.Monthdays) &&
		outer.Hours == inner.Hours
}

// ruleIsScheduled reports whether a rule is limited to particular days or hours.
func ruleIsScheduled(r Rule) bool {
	return len(r.Weekdays) > 0 || len(r.Monthdays) > 0 || r.Hours != ""
}

// rulesIntersect reports whether two rules can both match some single request.
//
// Unlike ruleCovers this is symmetric and only asks whether a common request
// exists. Schedules are treated as potentially overlapping unless one is
// restricted and the other is restricted differently on the same dimension —
// again the conservative direction, since a missed intersection is a missed
// warning.
func rulesIntersect(a, b Rule) bool {
	return secretsOverlap(a.Secrets, b.Secrets) &&
		secretsOverlap(a.Identities, b.Identities) &&
		secretsOverlap(a.Modes, b.Modes) &&
		schedulesMayOverlap(a, b)
}

// schedulesMayOverlap reports whether two rules' time conditions can both hold
// at some instant. An unconditional rule overlaps everything; two rules with
// differing explicit conditions are assumed to overlap unless they name
// disjoint weekday or monthday sets, which is the one case that is cheap and
// exact.
func schedulesMayOverlap(a, b Rule) bool {
	if len(a.Weekdays) > 0 && len(b.Weekdays) > 0 && !weekdaySetsOverlap(a.Weekdays, b.Weekdays) {
		return false
	}
	if len(a.Monthdays) > 0 && len(b.Monthdays) > 0 && !intSetsOverlap(a.Monthdays, b.Monthdays) {
		return false
	}
	return true
}

func weekdaySetsOverlap(a, b []string) bool {
	for _, x := range a {
		wx, ok := weekdayNum(x)
		if !ok {
			continue
		}
		for _, y := range b {
			if wy, ok := weekdayNum(y); ok && wx == wy {
				return true
			}
		}
	}
	return false
}

func intSetsOverlap(a, b []int) bool {
	for _, x := range a {
		if intIn(b, x) {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// allowVerb is allowWord as a third-person verb, so a sentence reads "rule 1
// matches first and denies" rather than gluing an "s" onto the noun.
func allowVerb(allow bool) string {
	if allow {
		return "allows"
	}
	return "denies"
}

// outcomeWord describes what a rule decides in one context, naming deny_agents
// when that is what makes an allow-rule deny.
func outcomeWord(r Rule, agent bool) string {
	if r.Allow && !r.outcome(agent) {
		return "deny (deny_agents)"
	}
	return allowWord(r.outcome(agent))
}

func allowWord(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// patternList renders a glob list for a message; an empty list placed no
// condition and so matches everything.
func patternList(ps []string) string {
	if len(ps) == 0 {
		return "<any>"
	}
	return "[" + strings.Join(ps, " ") + "]"
}
