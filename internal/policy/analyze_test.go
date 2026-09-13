package policy

import (
	"strings"
	"testing"
)

// hasFinding reports whether the analysis carries a finding of the given kind
// naming the given rule.
func hasFinding(a Analysis, kind string, rule int) bool {
	for _, f := range a.Findings {
		if f.Kind == kind && f.Rule == rule {
			return true
		}
	}
	return false
}

func TestAnalyzeFindsAnUnreachableRule(t *testing.T) {
	// Rule 1 grants what rule 0 already denies, from below it. Nothing rule 1
	// says has any effect, and the JSON gives no hint of that.
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/*"}, nil, nil),
		allow([]string{"bao:app/gitea#token"}, []string{"tea"}, []string{ModeExec}),
	}}
	a := p.Analyze()
	if !hasFinding(a, FindingUnreachable, 1) {
		t.Fatalf("rule 1 was not reported unreachable: %+v", a.Findings)
	}
	if a.OK() {
		t.Error("an unreachable rule must block an automatic apply")
	}
}

func TestAnalyzeFindsARedundantRule(t *testing.T) {
	// Same outcome, so this is waste rather than a lie — a warning, not an error.
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/*"}, []string{"ai"}, nil),
		allow([]string{"bao:app/gitea#token"}, []string{"ai"}, []string{ModeExec}),
	}}
	a := p.Analyze()
	if !hasFinding(a, FindingRedundant, 1) {
		t.Fatalf("rule 1 was not reported redundant: %+v", a.Findings)
	}
	for _, f := range a.Findings {
		if f.Kind == FindingRedundant && f.Severity != SeverityWarning {
			t.Error("redundancy must be a warning, not a blocking error")
		}
	}
}

func TestAnalyzeFindsPartialShadowing(t *testing.T) {
	// Neither rule covers the other, but they overlap and disagree, so ordering
	// silently decides the shared requests.
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/gitea#token"}, []string{"agent-*"}, nil),
		allow([]string{"bao:app/*"}, []string{"agent-x"}, []string{ModeExec}),
	}}
	a := p.Analyze()
	if !hasFinding(a, FindingShadows, 0) {
		t.Fatalf("rule 0 was not reported as shadowing rule 1: %+v", a.Findings)
	}
	// Reported, but not blocking. A narrow exception above a general rule is the
	// standard way to write a first-match policy, and nothing in the policy
	// distinguishes that from an accident — so the operator is told and decides.
	// Blocking here would make the editor refuse to write correct policies.
	if !a.OK() {
		t.Error("partial shadowing must be a warning, not a blocking error")
	}
	for _, f := range a.Findings {
		if f.Kind == FindingShadows && f.Severity != SeverityWarning {
			t.Error("shadowing was recorded at error severity")
		}
	}
}

func TestAnalyzeAcceptsTheExceptionBeforeGeneralIdiom(t *testing.T) {
	// "Deny agent-x this one token; allow every other agent-* brokered use of
	// it" is a correct, ordinary policy. It must validate.
	p := &Policy{Schema: SchemaVersion, Rules: []Rule{
		deny([]string{"bao:app/gitea#token"}, []string{"agent-x"}, nil),
		allow([]string{"bao:app/gitea#token"}, []string{"agent-*"}, []string{ModeExec, ModeMount}),
	}}
	a := p.Analyze()
	if !a.OK() {
		for _, f := range a.Errors() {
			t.Errorf("the exception-before-general idiom was rejected: %s", f.Message)
		}
	}
	// And it must actually behave the way it reads.
	if p.Evaluate(Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: ModeExec}).Allow {
		t.Error("the exception does not hold")
	}
	if !p.Evaluate(Request{Ref: "bao:app/gitea#token", Identity: "agent-y", Mode: ModeExec}).Allow {
		t.Error("the general rule does not fire for a label the exception did not name")
	}
}

func TestAnalyzeDoesNotReportShadowingForRulesThatAgree(t *testing.T) {
	// Two overlapping allows decide the same way, so their order changes nothing.
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/gitea#token"}, []string{"agent-*"}, nil),
		allow([]string{"bao:app/*"}, []string{"agent-x"}, []string{ModeExec}),
	}}
	for _, f := range p.Analyze().Findings {
		if f.Kind == FindingShadows {
			t.Errorf("rules with the same outcome reported as shadowing: %s", f.Message)
		}
	}
}

func TestAnalyzeDoesNotReportDisjointRules(t *testing.T) {
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:prod/*"}, nil, nil),
		allow([]string{"bao:app/gitea#token"}, []string{"tea"}, []string{ModeExec}),
	}}
	for _, f := range p.Analyze().Findings {
		if f.Kind == FindingShadows || f.Kind == FindingUnreachable {
			t.Errorf("disjoint rules produced an ordering finding: %s", f.Message)
		}
	}
}

func TestAnalyzeSurfacesRawGetAndBypassableModes(t *testing.T) {
	// Rule 0 restricts agents to brokered delivery; rule 1 permits get on the
	// same ref for a different label. Since labels are self-asserted, rule 0's
	// restriction does not hold — Check's finding, surfaced through Analyze.
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/gitea#*"}, []string{"agent-*"}, []string{ModeExec, ModeMount}),
		allow([]string{"bao:app/gitea#*"}, []string{"kevin"}, nil),
	}}
	a := p.Analyze()
	if !hasFinding(a, FindingGetGranted, 1) {
		t.Errorf("rule 1's raw get was not reported: %+v", a.Findings)
	}
	if !hasFinding(a, FindingBypassableModes, 0) {
		t.Errorf("rule 0's bypassable restriction was not reported: %+v", a.Findings)
	}
	if a.OK() {
		t.Error("a bypassable mode restriction must block an automatic apply")
	}
}

func TestAnalyzeAcceptsTheShippedExamplePolicyShape(t *testing.T) {
	// The posture the project recommends: a deny first, then brokered-only
	// allows on the same ref, then a deliberate raw-get exception on a ref no
	// non-human identity can reach. It should carry no blocking finding.
	p := &Policy{Schema: SchemaVersion, Rules: []Rule{
		deny([]string{"bao:prod/*"}, nil, nil),
		allow([]string{"bao:app/gitea#*"}, []string{"ai", "agent-*"}, []string{ModeExec, ModeMount}),
		allow([]string{"op://Private/*"}, []string{"kevin"}, nil),
	}}
	a := p.Analyze()
	if !a.OK() {
		for _, f := range a.Errors() {
			t.Errorf("unexpected blocking finding: %s", f.Message)
		}
	}
	// The raw-get exception is still reported, as a warning — it is a real
	// capability the operator should keep seeing.
	if len(a.Warnings()) == 0 {
		t.Error("the deliberate raw-get exception was not reported at all")
	}
}

func TestTimeCoversTreatsAScheduledRuleAsCoveringNothingWider(t *testing.T) {
	// A rule limited to Monday cannot cover an unconditional rule: outside its
	// window it matches nothing.
	// Same secrets on both, so only the time dimension decides the answer.
	scheduled := Rule{Allow: true, Secrets: []string{"bao:app/*"}, Weekdays: []string{"Mon"}}
	always := Rule{Allow: true, Secrets: []string{"bao:app/*"}}
	if ruleCovers(scheduled, always) {
		t.Error("a Monday-only rule was treated as covering an unconditional one")
	}
	if !ruleCovers(always, scheduled) {
		t.Error("an unconditional rule should cover a Monday-only one")
	}
}

func TestSchedulesOnDisjointWeekdaysDoNotOverlap(t *testing.T) {
	mon := Rule{Allow: false, Secrets: []string{"bao:app/*"}, Weekdays: []string{"Mon"}}
	tue := Rule{Allow: true, Secrets: []string{"bao:app/*"}, Weekdays: []string{"Tue"}}
	if rulesIntersect(mon, tue) {
		t.Error("rules on disjoint weekdays were reported as intersecting")
	}
}

// --- agent-assertable get labels ----------------------------

// findingsOfKind returns every finding of one kind, so a test asserts on the
// finding it cares about rather than on the whole report's ordering.
func findingsOfKind(a Analysis, kind string) []Finding {
	var out []Finding
	for _, f := range a.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// The finding this answers: not "which rules hand back a raw value"
// (the per-rule get-granted findings already answer that) but "which labels can
// be typed to obtain one". It is a union across rules, and it is exactly the
// step an operator skips when reading a list of per-rule findings.
func TestAnalyzeReportsGetLabelsAsOneSet(t *testing.T) {
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:a/*"}, []string{"ansible"}, []string{ModeGet}),
		allow([]string{"bao:b/*"}, []string{"gatus-ping", "alert-lib"}, []string{ModeGet}),
		allow([]string{"bao:c/*"}, []string{"ansible"}, []string{ModeGet}),
		allow([]string{"bao:d/*"}, []string{"ai"}, []string{ModeExec, ModeMount}),
	}}

	got := findingsOfKind(p.Analyze(), FindingAgentAssertableGet)
	if len(got) != 1 {
		t.Fatalf("got %d agent-assertable-get findings, want exactly 1 (it is a set, not a per-rule finding)", len(got))
	}
	msg := got[0].Message
	for _, want := range []string{"alert-lib", "ansible", "gatus-ping"} {
		if !strings.Contains(msg, want) {
			t.Errorf("finding does not name %q: %s", want, msg)
		}
	}
	// Duplicated across two rules, reported once: the answer is a set of labels.
	if strings.Count(msg, "ansible") != 1 {
		t.Errorf("ansible appears %d times, want 1: %s", strings.Count(msg, "ansible"), msg)
	}
	// An identity restricted to brokered delivery is not a way to read a raw
	// value, so listing it would misreport the exposure.
	if strings.Contains(msg, " ai ") || strings.HasSuffix(msg, " ai") {
		t.Errorf("finding names a brokered-only identity: %s", msg)
	}
	if got[0].Severity != SeverityWarning {
		t.Errorf("severity %v, want warning — the policy means what it says", got[0].Severity)
	}
}

// A rule with no identities matches every label, including ones nobody has
// thought of yet. Reporting its identity list as empty would read as "no labels
// affected", which is the opposite of the truth.
func TestAnalyzeReportsAnyIdentityGetAsStar(t *testing.T) {
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:a/*"}, nil, []string{ModeGet}),
	}}
	got := findingsOfKind(p.Analyze(), FindingAgentAssertableGet)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "*") {
		t.Errorf("a rule matching every identity was not reported as *: %s", got[0].Message)
	}
}

// A policy that brokers everything has nothing to report here. The finding must
// stay silent rather than emit an empty list, or it becomes noise an operator
// learns to skip past.
func TestAnalyzeReportsNoGetLabelsWhenNoneExist(t *testing.T) {
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:a/*"}, []string{"ai"}, []string{ModeExec, ModeMount}),
	}}
	if got := findingsOfKind(p.Analyze(), FindingAgentAssertableGet); len(got) != 0 {
		t.Errorf("got %d findings on a fully brokered policy, want 0: %+v", len(got), got)
	}
}
