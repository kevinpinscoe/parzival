package policy

// Authorization delta: what actually changes between two policies.
//
// A textual diff of policy.json answers "what did the file change to". It does
// not answer the question an operator is really asking, which is "what can now
// be fetched that could not be fetched before, and what stopped working". Those
// come apart badly in a first-match-wins list: appending a broad allow can grant
// far more than its text suggests, and inserting a rule above another can revoke
// access without any line of the revoked rule being touched.
//
// The delta is computed by evaluating both policies over the same set of
// requests and reporting where the decisions differ.
//
// **Why a probe set rather than a proof.** The request space is unbounded —
// refs and identities are arbitrary strings, matched by globs — so no finite
// evaluation proves two policies equivalent. The honest construction is to
// probe the space at the points the policies themselves care about: every ref
// pattern, every identity pattern, and every mode named by either policy, plus
// anything the caller explicitly asks about. A pattern is probed as its own
// literal text, which is exact for a literal ref and a representative for a
// glob.
//
// What this catches: any decision change on a request either policy explicitly
// mentions — which is where drafting mistakes actually live, because a rule
// nobody wrote about is a rule nobody changed. What it can miss: a change
// reachable only at a ref no rule in either policy names, and a change that
// exists only inside a time window (probes are evaluated at one instant; rules
// carrying weekday/monthday/hours conditions are reported separately so the
// operator knows the delta is a snapshot rather than a schedule).

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Probe is one request the delta is evaluated at.
type Probe struct {
	Ref      string
	Identity string
	Mode     string
}

func (p Probe) String() string {
	id := p.Identity
	if id == "" {
		id = "(none)"
	}
	return fmt.Sprintf("%s / %s / %s", id, p.Mode, p.Ref)
}

// Change is one probe whose decision differs between two policies.
type Change struct {
	Probe    Probe
	WasAllow bool
	NowAllow bool
	WasRule  int // matching rule index in the old policy, -1 for default deny
	NowRule  int // matching rule index in the new policy, -1 for default deny
}

// Granted reports whether the change opened access that was previously refused.
func (c Change) Granted() bool { return !c.WasAllow && c.NowAllow }

// Delta is the authorization difference between two policies.
type Delta struct {
	Changes []Change
	// Probed is how many requests were evaluated, so a caller can say what the
	// delta is based on rather than implying it is exhaustive.
	Probed int
	// TimeConditional lists rules in the new policy whose effect depends on the
	// day or hour. The delta was computed at one instant, so a rule that did not
	// match at that instant contributed nothing — and the operator needs to know
	// that rather than reading an empty delta as "nothing changed, ever".
	TimeConditional []int
	// At is the instant the probes were evaluated at.
	At time.Time
}

// Empty reports whether no probed request changed decision.
func (d Delta) Empty() bool { return len(d.Changes) == 0 }

// Grants returns only the changes that opened access.
func (d Delta) Grants() []Change {
	var out []Change
	for _, c := range d.Changes {
		if c.Granted() {
			out = append(out, c)
		}
	}
	return out
}

// Revocations returns only the changes that closed access.
func (d Delta) Revocations() []Change {
	var out []Change
	for _, c := range d.Changes {
		if c.WasAllow && !c.NowAllow {
			out = append(out, c)
		}
	}
	return out
}

// Unexpected returns the changes that are not in want — the side effects.
//
// This is the distinction the operator is shown: "the access you asked for" as
// against "everything else that moved". A grant request expects a specific set
// of probes to flip to allow; anything else that changed is a side effect, and
// a side effect is the reason an edit gets refused rather than applied.
func (d Delta) Unexpected(want []Probe) []Change {
	expected := make(map[Probe]bool, len(want))
	for _, p := range want {
		expected[p] = true
	}
	var out []Change
	for _, c := range d.Changes {
		if !expected[c.Probe] {
			out = append(out, c)
		}
	}
	return out
}

// DiffAuthorization evaluates old and new over probes and reports the decisions
// that differ. A nil old policy means "nothing was allowed" — the deny-by-default
// state of a host with no policy file at all.
func DiffAuthorization(old, updated *Policy, probes []Probe, at time.Time) Delta {
	d := Delta{Probed: len(probes), At: at}

	if updated != nil {
		for i, r := range updated.Rules {
			if ruleIsScheduled(r) {
				d.TimeConditional = append(d.TimeConditional, i)
			}
		}
	}

	for _, pr := range probes {
		req := Request{Ref: pr.Ref, Identity: pr.Identity, Mode: pr.Mode, Time: at}
		wasAllow, wasRule := decide(old, req)
		nowAllow, nowRule := decide(updated, req)
		if wasAllow == nowAllow {
			continue
		}
		d.Changes = append(d.Changes, Change{
			Probe: pr, WasAllow: wasAllow, NowAllow: nowAllow, WasRule: wasRule, NowRule: nowRule,
		})
	}
	return d
}

// Explain evaluates r and reports both the outcome and the index of the rule
// that produced it, with -1 meaning no rule matched and the default deny
// applied.
//
// It exists alongside Evaluate because Evaluate names the matching rule only
// inside Decision.Reason as prose, and a caller that needs the index — to print
// the rule, or to say "matched rule 12 before your proposed rule 31" — would
// otherwise have to parse that string back into a number.
//
// Unlike Authorize this writes nothing to the audit log. It answers a
// hypothetical, and recording simulated requests beside real ones would make
// the audit log unable to answer what was actually fetched.
func (p *Policy) Explain(r Request) (allow bool, rule int) { return decide(p, r) }

// decide evaluates one request and returns the outcome plus the index of the
// rule that produced it (-1 when no rule matched and the default deny applied).
//
// It duplicates Evaluate's loop rather than calling it because Evaluate reports
// the matching rule only as prose in Decision.Reason, and the delta needs the
// index as a number — "matched rule 12 before proposed rule 31" is the whole
// point of the first-match explanation.
func decide(p *Policy, r Request) (allow bool, rule int) {
	if p == nil {
		return false, -1
	}
	for i, candidate := range p.Rules {
		if candidate.matches(r) {
			return candidate.Allow, i
		}
	}
	return false, -1
}

// ProbeSet builds the request set a delta is evaluated over: every ref pattern,
// identity pattern and mode named by any of the given policies, crossed
// together, plus any extra probes the caller supplies.
//
// Modes are always the full set rather than only the ones policies mention. A
// policy that never names `get` is exactly the policy where an accidentally
// granted `get` matters most, so leaving it unprobed would blind the delta to
// the single change the project most wants caught.
//
// The identity set always includes the empty label. A request with no `--as`
// and no $PARZIVAL_IDENTITY is a real request — the commonest one, in fact —
// and only a rule with no identity condition matches it, so it exercises a
// different path from any named label.
func ProbeSet(policies []*Policy, extra []Probe) []Probe {
	refs := map[string]bool{}
	ids := map[string]bool{"": true}

	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			for _, s := range r.Secrets {
				refs[s] = true
			}
			for _, id := range r.Identities {
				ids[id] = true
			}
		}
	}
	for _, e := range extra {
		refs[e.Ref] = true
		ids[e.Identity] = true
	}

	// A policy of nothing but unconditional rules names no ref at all, and the
	// cross product of an empty set is empty — which would silently produce a
	// delta over zero probes and read as "nothing changed". One placeholder ref
	// keeps such a policy probeable.
	if len(refs) == 0 {
		refs["*"] = true
	}

	modes := []string{ModeGet, ModeExec, ModeMount}
	out := make([]Probe, 0, len(refs)*len(ids)*len(modes))
	for _, ref := range sortedKeys(refs) {
		for _, id := range sortedKeys(ids) {
			for _, m := range modes {
				out = append(out, Probe{Ref: ref, Identity: id, Mode: m})
			}
		}
	}

	// Caller-supplied probes are appended if the cross product missed them —
	// it can, when the caller asks about a concrete ref that no pattern in
	// either policy spells the same way.
	seen := make(map[Probe]bool, len(out))
	for _, p := range out {
		seen[p] = true
	}
	for _, e := range extra {
		if !seen[e] {
			out = append(out, e)
			seen[e] = true
		}
	}
	return out
}

// RuleProbes returns the requests a rule is written to match, as probes: the
// cross product of its own refs, identities and modes.
//
// This is what "the access you asked for" means when a grant is proposed — the
// caller passes it to Delta.Unexpected as the expected set, and anything else
// that moved is a side effect. A rule with no condition on some dimension is
// left as the empty label / the "*" ref on that dimension, which is the widest
// thing it says and therefore what it should be held to.
func RuleProbes(r Rule) []Probe {
	refs := r.Secrets
	if len(refs) == 0 {
		refs = []string{"*"}
	}
	ids := r.Identities
	if len(ids) == 0 {
		ids = []string{""}
	}
	modes := r.Modes
	if len(modes) == 0 {
		modes = []string{ModeGet, ModeExec, ModeMount}
	}

	out := make([]Probe, 0, len(refs)*len(ids)*len(modes))
	for _, ref := range refs {
		for _, id := range ids {
			for _, m := range modes {
				out = append(out, Probe{Ref: ref, Identity: id, Mode: m})
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Describe renders a change as one line for an operator.
func (c Change) Describe() string {
	var b strings.Builder
	if c.Granted() {
		b.WriteString("NEW ALLOW   ")
	} else {
		b.WriteString("NOW DENIED  ")
	}
	b.WriteString(c.Probe.String())
	// Name the rule now responsible for the decision. A denial can come from an
	// explicit deny-rule or from falling off the end of the list, and those are
	// different things to fix, so they are not reported with the same words.
	if c.NowRule >= 0 {
		fmt.Fprintf(&b, "  (rule %d)", c.NowRule)
	} else {
		b.WriteString("  (no matching rule — default deny)")
	}
	return b.String()
}
