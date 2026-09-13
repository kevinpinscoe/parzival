package policy

import (
	"strings"
	"testing"
)

// These tests evaluate at noon, defined in delta_test.go as 2026-09-08 12:00
// local — a Tuesday, inside a typical working-hours window.

func TestNearMissesIgnoresRulesAboutOtherRefs(t *testing.T) {
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:prod/*"}, nil, nil),
		allow([]string{"bao:app/gitea#*"}, []string{"tea"}, []string{ModeExec}),
	}}
	req := Request{Ref: "bao:app/gitea#token", Identity: "nobody", Mode: ModeExec, Time: noon}

	near := p.NearMisses(req)
	if len(near) != 1 {
		t.Fatalf("got %d near misses, want only the rule naming this ref: %+v", len(near), near)
	}
	if near[0].Rule != 1 {
		t.Errorf("near miss names rule %d, want 1", near[0].Rule)
	}
}

func TestNearMissesNamesTheFailingCondition(t *testing.T) {
	rule := Rule{
		Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"tea"},
		Modes: []string{ModeExec, ModeMount}, Weekdays: []string{"Mon", "Tue"}, Hours: "08:00-18:00",
	}
	p := &Policy{Rules: []Rule{rule}}

	// Right ref, right identity, right day and hour — wrong mode.
	req := Request{Ref: "bao:app/gitea#token", Identity: "tea", Mode: ModeGet, Time: noon}
	near := p.NearMisses(req)
	if len(near) != 1 {
		t.Fatalf("got %d near misses, want 1", len(near))
	}
	if len(near[0].Reasons) != 1 || near[0].Reasons[0] != "mode" {
		t.Fatalf("Reasons = %v, want exactly [mode]", near[0].Reasons)
	}
	got := strings.Join(near[0].Explain(rule, req), "; ")
	if !strings.Contains(got, "mode get is not in [exec mount]") {
		t.Errorf("explanation does not name what was wanted vs offered: %s", got)
	}
}

func TestNearMissesReportsEveryFailingCondition(t *testing.T) {
	rule := Rule{
		Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"tea"},
		Modes: []string{ModeExec}, Weekdays: []string{"Mon"}, Hours: "08:00-18:00",
	}
	p := &Policy{Rules: []Rule{rule}}

	// noon is a Tuesday, so weekday fails too, as do identity and mode.
	req := Request{Ref: "bao:app/gitea#token", Identity: "someone-else", Mode: ModeGet, Time: noon}
	near := p.NearMisses(req)
	if len(near) != 1 {
		t.Fatalf("got %d near misses, want 1", len(near))
	}
	want := map[string]bool{"identity": true, "mode": true, "weekday": true}
	if len(near[0].Reasons) != len(want) {
		t.Fatalf("Reasons = %v, want identity, mode and weekday", near[0].Reasons)
	}
	for _, r := range near[0].Reasons {
		if !want[r] {
			t.Errorf("unexpected reason %q", r)
		}
	}
}

func TestNearMissesExplainsAnEmptyIdentityReadably(t *testing.T) {
	// A caller passing no --as is a real case, and "identity  is not matched by"
	// would read as a formatting bug rather than an answer.
	rule := allow([]string{"bao:app/x#token"}, []string{"tea"}, nil)
	p := &Policy{Rules: []Rule{rule}}
	req := Request{Ref: "bao:app/x#token", Identity: "", Mode: ModeExec, Time: noon}

	near := p.NearMisses(req)
	if len(near) != 1 {
		t.Fatalf("got %d near misses, want 1", len(near))
	}
	got := strings.Join(near[0].Explain(rule, req), "; ")
	if !strings.Contains(got, "(no --as given)") {
		t.Errorf("an empty identity was not explained: %s", got)
	}
}

func TestNearMissesSkipsRulesThatActuallyMatched(t *testing.T) {
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/x#token"}, []string{"tea"}, []string{ModeExec}),
	}}
	req := Request{Ref: "bao:app/x#token", Identity: "tea", Mode: ModeExec, Time: noon}
	if near := p.NearMisses(req); len(near) != 0 {
		t.Errorf("a matching rule was reported as a near miss: %+v", near)
	}
}

func TestNearMissesIncludesAnUnscopedRule(t *testing.T) {
	// A rule with no secrets condition covers every ref, so it is as relevant to
	// the question as one naming the ref explicitly.
	p := &Policy{Rules: []Rule{
		{Allow: true, Identities: []string{"tea"}},
	}}
	req := Request{Ref: "bao:anything#x", Identity: "other", Mode: ModeExec, Time: noon}
	if near := p.NearMisses(req); len(near) != 1 {
		t.Errorf("an unscoped rule was not treated as covering this ref: %+v", near)
	}
}

func TestExplainReportsTheDecidingRuleIndex(t *testing.T) {
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/*"}, []string{"agent-*"}, nil),
		allow([]string{"bao:app/gitea#token"}, []string{"agent-x"}, []string{ModeExec}),
	}}
	allowed, idx := p.Explain(Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: ModeExec, Time: noon})
	if allowed {
		t.Error("the earlier deny did not decide")
	}
	if idx != 0 {
		t.Errorf("Explain returned rule %d, want 0", idx)
	}

	// No rule at all is -1, not 0 — otherwise "default deny" is indistinguishable
	// from "denied by the first rule".
	_, idx = p.Explain(Request{Ref: "bao:elsewhere#x", Identity: "who", Mode: ModeExec, Time: noon})
	if idx != -1 {
		t.Errorf("a default deny reported rule %d, want -1", idx)
	}
}
