package policy

// Leak-containment analysis of a policy.
//
// A rule's "modes" list is the control that lets an identity USE a credential
// without being able to SEE it. It has a sharp edge: identity labels are
// self-asserted (--as / $PARZIVAL_IDENTITY, no process inspection — see
// THREAT-MODEL.md), and rules are first-match-wins. So restricting one identity
// to exec/mount achieves nothing if some other rule permits `get` on the same
// ref — the caller simply asserts the other label.
//
// The robust construction is to restrict the REF rather than the IDENTITY: when
// no allow-rule anywhere permits `get` for a ref, the raw value cannot reach a
// log, a terminal, or an AI transcript regardless of what label the caller
// claims. Check reports where a policy fails that test.

// GetOpen names an allow-rule that permits raw `get` on some ref.
type GetOpen struct {
	Rule        int      // index in Policy.Rules
	Secrets     []string // nil means "every ref"
	Identities  []string // nil means "every identity"
	Conditional bool     // true if the rule is limited by weekday/monthday/hours
}

// Weakened names a mode restriction defeated by an overlapping rule.
type Weakened struct {
	RestrictedRule int      // the rule intending to restrict (get excluded)
	RestrictedIDs  []string // identities it meant to restrict
	Secrets        []string // the overlapping ref patterns
	OpenRule       int      // the rule that permits get on an overlapping ref
	OpenIDs        []string // labels a caller can assert to bypass; nil = any
}

// Report is the outcome of analysing a policy.
type Report struct {
	GetOpen  []GetOpen
	Weakened []Weakened
}

// OK reports whether the policy has no defeated mode restriction.
func (r Report) OK() bool { return len(r.Weakened) == 0 }

// Check analyses p for mode restrictions that a self-asserted identity can
// bypass.
//
// It is deliberately conservative — it over-reports rather than under-reports,
// which is the correct bias for a safety check. Specifically it does not model
// deny-rule shadowing or time windows, so a finding may describe a bypass that
// is only reachable inside some window (Conditional records that) or that an
// earlier deny already blocks. Verify a finding before dismissing it; the cost
// of a false positive is a second look, the cost of a false negative is a
// credential in a transcript.
func (p *Policy) Check() Report {
	var rep Report
	for i, r := range p.Rules {
		if r.Allow && permitsGet(r) {
			rep.GetOpen = append(rep.GetOpen, GetOpen{
				Rule:        i,
				Secrets:     r.Secrets,
				Identities:  r.Identities,
				Conditional: len(r.Weekdays) > 0 || len(r.Monthdays) > 0 || r.Hours != "",
			})
		}
	}

	for i, restricted := range p.Rules {
		// Only an allow-rule that deliberately excludes get is making a claim
		// worth checking.
		if !restricted.Allow || len(restricted.Modes) == 0 || permitsGet(restricted) {
			continue
		}
		for _, open := range rep.GetOpen {
			if open.Rule == i || !secretsOverlap(restricted.Secrets, open.Secrets) {
				continue
			}
			// If the open rule is reachable only by the very identities the
			// restricted rule covers, there is no other label to assert.
			if identitiesSubsumed(open.Identities, restricted.Identities) {
				continue
			}
			rep.Weakened = append(rep.Weakened, Weakened{
				RestrictedRule: i,
				RestrictedIDs:  restricted.Identities,
				Secrets:        restricted.Secrets,
				OpenRule:       open.Rule,
				OpenIDs:        open.Identities,
			})
		}
	}
	return rep
}

// permitsGet reports whether rule r covers ModeGet. An empty Modes list matches
// every mode, so it permits get by omission — the commonest way the control is
// lost.
func permitsGet(r Rule) bool {
	if len(r.Modes) == 0 {
		return true
	}
	return anyWildcard(r.Modes, ModeGet)
}

// secretsOverlap reports whether two ref-pattern sets can name a common ref. An
// empty set means "every ref" and so overlaps everything.
//
// Exact glob intersection is not decidable with this matcher, so this tests each
// pattern against the other as a literal string, in both directions. That is
// approximate: it catches identical patterns, and a broader pattern containing a
// narrower one (bao:app/* vs bao:app/gitea#*), which covers how policies are
// written in practice. It can miss an exotic partial overlap — hence the
// conservative framing on Check.
func secretsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if wildcardMatch(x, y) || wildcardMatch(y, x) {
				return true
			}
		}
	}
	return false
}

// identitiesSubsumed reports whether every label the open rule accepts is already
// one the restricted rule covers — in which case the open rule grants nothing to
// a label the restriction did not already contemplate. An open rule with no
// identity list accepts every label and is never subsumed.
func identitiesSubsumed(open, restricted []string) bool {
	if len(open) == 0 {
		return false
	}
	if len(restricted) == 0 {
		// The restricted rule covers every identity, so any label the open rule
		// accepts was already covered by the restriction it defeats.
		return false
	}
	for _, o := range open {
		if !anyWildcard(restricted, o) {
			return false
		}
	}
	return true
}
