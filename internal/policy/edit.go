package policy

// Building and placing a rule.
//
// Appending a rule to a first-match-wins list is the wrong default, and it is
// wrong in both directions at once:
//
//   - Appended too late, the new rule can be unreachable. An earlier deny that
//     already matches its requests decides first, and the grant silently does
//     nothing. The file changed; the authorization did not.
//   - Placed too early, the new rule can shadow a narrower rule below it,
//     taking over requests that rule was written to decide — revoking or
//     granting access nobody asked to change.
//
// So placement is computed rather than chosen: find the range of indices at
// which the rule both fires and disturbs nothing, and refuse when that range is
// empty. Refusing is the point. An editor that guesses at placement produces a
// valid JSON file whose effective authorization the operator never agreed to,
// which is precisely the failure this package exists to prevent.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// GrantRequest is the intent behind a proposed rule, in the operator's terms.
type GrantRequest struct {
	// Tool names the consumer needing access — a command, service or agent. It
	// is recorded in the rule's description, never matched on.
	Tool string
	// Goal is the human reason access is being granted, likewise recorded only.
	Goal string
	// Secrets are the ref patterns to grant.
	Secrets []string
	// Identities are the identity labels or patterns to grant to.
	Identities []string
	// Modes are the delivery modes. Empty means the safe default below.
	Modes []string
	// Weekdays, Monthdays and Hours optionally limit when the rule applies.
	Weekdays  []string
	Monthdays []int
	Hours     string
}

// DefaultModes is what a grant gets when the caller names no modes: brokered
// delivery only.
//
// Raw `get` is deliberately absent. It hands the caller the secret's value,
// which can then reach anything the caller writes to — a log, a terminal, CI
// output, an AI agent's transcript — while exec and mount place the value in a
// file the consumer opens and parzival wipes. Granting `get` is a decision an
// operator makes explicitly; it is never what "I didn't say" means.
var DefaultModes = []string{ModeExec, ModeMount}

// GrantsRawGet reports whether a request asks for raw secret retrieval, so a
// caller can warn before the rule is built rather than after it is installed.
func (g GrantRequest) GrantsRawGet() bool {
	modes := g.Modes
	if len(modes) == 0 {
		modes = DefaultModes
	}
	for _, m := range modes {
		if m == ModeGet {
			return true
		}
	}
	return false
}

// BuildGrantRule turns a GrantRequest into a Rule, applying the safe mode
// default and validating every field the policy parser would reject later.
//
// Validation happens here rather than only at parse time so a bad request is
// refused while it is still the operator's typo, with the field named — instead
// of surfacing as a rejected candidate file several steps downstream.
func BuildGrantRule(g GrantRequest) (Rule, error) {
	if len(g.Secrets) == 0 {
		return Rule{}, errors.New("a grant needs at least one secret reference: an allow-rule with no secrets matches every ref in the store")
	}
	if len(g.Identities) == 0 {
		return Rule{}, errors.New("a grant needs at least one identity: an allow-rule with no identities matches every caller, including ones you have not thought of")
	}

	modes := g.Modes
	if len(modes) == 0 {
		modes = append([]string(nil), DefaultModes...)
	}
	for _, m := range modes {
		if !knownMode(m) {
			return Rule{}, fmt.Errorf("unknown mode %q (want %s, %s or %s)", m, ModeGet, ModeExec, ModeMount)
		}
	}

	r := Rule{
		Allow:       true,
		Description: describeGrant(g),
		Secrets:     append([]string(nil), g.Secrets...),
		Identities:  append([]string(nil), g.Identities...),
		Modes:       modes,
		Weekdays:    append([]string(nil), g.Weekdays...),
		Monthdays:   append([]int(nil), g.Monthdays...),
		Hours:       g.Hours,
	}

	// Reuse the policy's own validation rather than re-checking weekdays, month
	// days and hours here: a second implementation is a second thing to drift.
	probe := &Policy{Schema: SchemaVersion, Rules: []Rule{r}}
	if err := probe.validate("proposed rule"); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// describeGrant writes the rule's description from the operator's stated tool
// and goal. The description is never matched on, but it is the only place the
// reason survives: a rule read six months later says what it permits and, with
// this, why someone wanted that.
func describeGrant(g GrantRequest) string {
	switch {
	case g.Tool != "" && g.Goal != "":
		return fmt.Sprintf("%s: %s", g.Tool, g.Goal)
	case g.Tool != "":
		return g.Tool
	case g.Goal != "":
		return g.Goal
	}
	return ""
}

// Placement is the result of working out where a rule can go.
type Placement struct {
	// Index is the position to insert at, valid only when Err is nil.
	Index int
	// Low and High are the bounds Index was chosen from: the rule may be
	// inserted at any index in [Low, High]. Reported so an operator can see how
	// much room the constraints left.
	Low, High int
	// BlockedBy names existing rules that match everything the proposal matches
	// and decide the other way. The proposal has to sit above each of them or it
	// never fires at all — this is what produced High.
	BlockedBy []int
	// WouldBlock names existing rules the proposal matches everything of, and
	// decides the other way. The proposal has to sit below each of them or they
	// never fire again — this is what produced Low.
	WouldBlock []int
	// Ambiguous names rules that overlap the proposal partially — neither covers
	// the other — with the opposite outcome. Placement cannot resolve these:
	// whichever rule comes first wins for the overlapping requests, and both
	// orders are defensible. They block an automatic placement.
	Ambiguous []int
	// CoveredBy names an existing rule that already reaches the same outcome for
	// everything the proposal covers, making it redundant. -1 when there is none.
	CoveredBy int
	// Err is set when no safe position could be determined.
	Err error
}

// Redundant reports whether an existing rule already grants what is proposed.
func (p Placement) Redundant() bool { return p.CoveredBy >= 0 }

// AnalyzeRuleInsertion works out where proposed can be inserted into p.
//
// Inserting at index i puts the proposal at position i, with everything from the
// old index i onwards shifted down. Two hard constraints bound i, and they are
// deliberately *asymmetric* — each is about one rule wholly swallowing the
// other, not about the two merely overlapping:
//
//	High — the proposal must sit at or above the first existing rule that
//	       covers it with the opposite outcome. Placed below such a rule, the
//	       proposal never fires: the file changed and the authorization did not.
//	Low  — the proposal must sit below every existing rule that it covers with
//	       the opposite outcome. Placed above such a rule, that rule never fires
//	       again, revoking or granting something nobody asked to change.
//
// When Low <= High every index in that range is safe and Low is chosen: the
// earliest safe position, which keeps the rule as near the top as its
// constraints allow and makes the reason for its position readable.
//
// Two situations produce no answer, and both are returned as errors rather than
// resolved by guessing:
//
//   - Low > High. Two different existing rules pull opposite ways and the
//     proposal would have to be in two places at once.
//   - A partial overlap with the opposite outcome. Neither rule covers the
//     other, so ordering them decides only the requests they share, and nothing
//     in the proposal says which way that should go.
//
// Both resolutions are editorial decisions about the existing policy — narrow a
// rule, split it, reorder it, or state the index explicitly — and belong to the
// operator, not to this function.
func (p *Policy) AnalyzeRuleInsertion(proposed Rule) Placement {
	pl := Placement{CoveredBy: -1, Low: 0, High: len(p.Rules)}

	for i, existing := range p.Rules {
		sameOutcome := existing.Allow == proposed.Allow

		// Redundancy: an existing rule already reaching the same outcome for
		// everything the proposal would cover. Checked across the whole list —
		// a duplicate below the insertion point is still worth reporting.
		if sameOutcome && pl.CoveredBy < 0 && ruleCovers(existing, proposed) {
			pl.CoveredBy = i
		}
		if sameOutcome || !rulesIntersect(existing, proposed) {
			continue
		}

		switch {
		case ruleCovers(existing, proposed):
			// This rule swallows the proposal. Everything at index > i is too
			// late, so the proposal must go at or above i.
			pl.BlockedBy = append(pl.BlockedBy, i)
			if i < pl.High {
				pl.High = i
			}
		case ruleCovers(proposed, existing):
			// The proposal swallows this rule. Anything at index <= i would
			// leave it dead, so the proposal must go below it.
			pl.WouldBlock = append(pl.WouldBlock, i)
			if i+1 > pl.Low {
				pl.Low = i + 1
			}
		default:
			pl.Ambiguous = append(pl.Ambiguous, i)
		}
	}

	if len(pl.Ambiguous) > 0 {
		// Both orders are legitimate policies, which is exactly why this is not
		// decided here. Naming the two indices makes the choice a single flag
		// rather than a puzzle: the usual answer is to keep the more specific
		// rule first, which for a narrow existing exception means placing the
		// proposal below it.
		below := pl.Ambiguous[len(pl.Ambiguous)-1] + 1
		above := pl.Ambiguous[0]
		pl.Err = fmt.Errorf(
			"cannot place the rule automatically: it overlaps %s partially, with the opposite outcome, and neither rule contains the other.\n"+
				"Ordering them decides only the requests they share, and the proposal does not say which way that should go.\n"+
				"  --at %d  puts it below, so %s keeps deciding the requests they share (the usual choice when the existing rule is a narrow exception)\n"+
				"  --at %d  puts it above, so this rule wins for those requests instead\n"+
				"Or narrow the proposal, or the existing rule, so one clearly contains the other",
			ruleList(pl.Ambiguous), below, ruleList(pl.Ambiguous), above)
		return pl
	}

	if pl.Low > pl.High {
		pl.Err = fmt.Errorf(
			"cannot place the rule safely: it must sit at or above %s (which would otherwise decide its requests first) and below %s (which it would otherwise leave unreachable).\n"+
				"Those cannot both hold. Resolve it in the existing policy — narrow one of those rules, split it, or reorder them — then propose the grant again",
			ruleList(pl.BlockedBy), ruleList(pl.WouldBlock))
		return pl
	}

	pl.Index = pl.Low
	return pl
}

// ruleList renders rule indices for an error message.
func ruleList(idx []int) string {
	switch len(idx) {
	case 0:
		return "no rule"
	case 1:
		return fmt.Sprintf("rule %d", idx[0])
	}
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = strconv.Itoa(n)
	}
	return "rules " + strings.Join(parts, ", ")
}

// InsertRule returns a copy of p with r inserted at index i.
//
// It copies rather than mutating in place because a candidate policy is built,
// analysed and possibly discarded — a caller that analysed a mutated original
// would have nothing left to compare the candidate against, and the
// authorization delta is exactly that comparison.
func (p *Policy) InsertRule(r Rule, i int) (*Policy, error) {
	if i < 0 || i > len(p.Rules) {
		return nil, fmt.Errorf("insertion index %d out of range 0..%d", i, len(p.Rules))
	}
	out := &Policy{Schema: p.Schema, Rules: make([]Rule, 0, len(p.Rules)+1)}
	out.Rules = append(out.Rules, p.Rules[:i]...)
	out.Rules = append(out.Rules, r)
	out.Rules = append(out.Rules, p.Rules[i:]...)

	// A policy written without a schema is schema 1 in practice; stamping it on
	// the way out means an edited policy declares the version it was edited
	// against rather than inheriting an omission.
	if out.Schema == 0 {
		out.Schema = SchemaVersion
	}
	return out, nil
}
