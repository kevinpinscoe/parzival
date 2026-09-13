package policy

import "strconv"

// Why a rule did not match.
//
// "No rule matches, so the default deny applies" is a true answer and usually a
// useless one. The operator writing a policy nearly always has a rule in mind
// that they expected to fire, and what they need to know is which condition on
// it failed — the identity glob, the mode allowlist, the hours window — not that
// the list as a whole came up empty.
//
// A near miss is a rule whose *secret* pattern matches the request but which
// failed on some other dimension. The ref is the right anchor: it is what an
// operator identifies a rule by, and every rule that does not mention the ref at
// all is genuinely irrelevant to the question and would only be noise.

// Mismatch names one rule that nearly matched, and the conditions that stopped it.
type Mismatch struct {
	Rule    int
	Reasons []string // the conditions that failed, in the order Rule.matches tests them
}

// NearMisses returns the rules whose secret pattern covers r.Ref but which did
// not match r, each with the conditions responsible.
//
// A rule with no secrets condition matches every ref, so it is included too:
// it is as relevant to the question as one naming the ref explicitly.
func (p *Policy) NearMisses(r Request) []Mismatch {
	var out []Mismatch
	for i, rule := range p.Rules {
		if len(rule.Secrets) > 0 && !anyWildcard(rule.Secrets, r.Ref) {
			continue // the rule is not about this ref at all
		}
		if rule.matches(r) {
			continue // it matched; nothing to explain
		}
		m := Mismatch{Rule: i}
		if len(rule.Identities) > 0 && !anyWildcard(rule.Identities, r.Identity) {
			m.Reasons = append(m.Reasons, "identity")
		}
		if len(rule.Modes) > 0 && !anyWildcard(rule.Modes, r.Mode) {
			m.Reasons = append(m.Reasons, "mode")
		}
		if len(rule.Weekdays) > 0 && !weekdayMatches(rule.Weekdays, r.Time) {
			m.Reasons = append(m.Reasons, "weekday")
		}
		if len(rule.Monthdays) > 0 && !intIn(rule.Monthdays, r.Time.Day()) {
			m.Reasons = append(m.Reasons, "monthday")
		}
		if rule.Hours != "" && !hoursMatch(rule.Hours, r.Time) {
			m.Reasons = append(m.Reasons, "hours")
		}
		out = append(out, m)
	}
	return out
}

// Explains renders a mismatch's reasons against the rule, saying what the rule
// requires and what the request offered — so the answer is "you asked for get
// and it allows exec, mount", not merely "mode".
func (m Mismatch) Explain(rule Rule, r Request) []string {
	var out []string
	for _, why := range m.Reasons {
		switch why {
		case "identity":
			id := r.Identity
			if id == "" {
				id = "(no --as given)"
			}
			out = append(out, "identity "+id+" is not matched by "+patternList(rule.Identities))
		case "mode":
			out = append(out, "mode "+r.Mode+" is not in "+patternList(rule.Modes))
		case "weekday":
			out = append(out, "the request is on "+r.Time.Format("Mon")+", and the rule is limited to "+patternList(rule.Weekdays))
		case "monthday":
			out = append(out, "the request is on day "+strconv.Itoa(r.Time.Day())+" of the month, and the rule is limited to specific month days")
		case "hours":
			out = append(out, "the request is at "+r.Time.Format("15:04")+", outside the rule's "+rule.Hours+" window")
		}
	}
	return out
}
