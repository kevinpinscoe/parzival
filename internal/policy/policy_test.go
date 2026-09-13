package policy

import (
	"testing"
	"time"
)

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"bao:app/gitea#token", "bao:app/gitea#token", true},
		{"bao:app/gitea#*", "bao:app/gitea#token", true},
		{"bao:app/*", "bao:app/gitea#token", true}, // * crosses '/' (unlike filepath.Match)
		{"bao:*", "bao:app/gitea#token", true},
		{"op://Private/*", "op://Private/thing/field", true},
		{"bao:app/gitea#????", "bao:app/gitea#toke", true},
		{"bao:app/gitea#token", "bao:app/other#token", false},
		{"op://Work/*", "op://Private/x/y", false},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.pattern, c.s); got != c.want {
			t.Errorf("wildcardMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestHoursMatch(t *testing.T) {
	at := func(hh, mm int) time.Time { return time.Date(2026, 7, 14, hh, mm, 0, 0, time.Local) }
	cases := []struct {
		spec string
		t    time.Time
		want bool
	}{
		{"08:00-18:00", at(9, 0), true},
		{"08:00-18:00", at(18, 0), true},
		{"08:00-18:00", at(7, 59), false},
		{"08:00-18:00", at(18, 1), false},
		{"22:00-06:00", at(23, 0), true},  // wrap-around
		{"22:00-06:00", at(5, 0), true},   // wrap-around
		{"22:00-06:00", at(12, 0), false}, // wrap-around
	}
	for _, c := range cases {
		if got := hoursMatch(c.spec, c.t); got != c.want {
			t.Errorf("hoursMatch(%q,%s)=%v want %v", c.spec, c.t.Format("15:04"), got, c.want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	// Friday 2026-07-17 at 10:00 local.
	fri := time.Date(2026, 7, 17, 10, 0, 0, 0, time.Local)
	sat := time.Date(2026, 7, 18, 10, 0, 0, 0, time.Local)

	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"tea", "docker"},
			Weekdays: []string{"Mon", "Tue", "Wed", "Thu", "Fri"}, Hours: "08:00-18:00"},
		{Allow: true, Secrets: []string{"op://Private/*"}},
		{Allow: false, Secrets: []string{"bao:prod/*"}},
	}}

	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{"gitea allowed weekday business hours", Request{Ref: "bao:app/gitea#token", Identity: "tea", Time: fri}, true},
		{"gitea wrong identity", Request{Ref: "bao:app/gitea#token", Identity: "curl", Time: fri}, false},
		{"gitea weekend denied", Request{Ref: "bao:app/gitea#token", Identity: "tea", Time: sat}, false},
		{"op private allowed any identity/time", Request{Ref: "op://Private/x/y", Identity: "", Time: sat}, true},
		{"unmatched ref denied by default", Request{Ref: "bao:other/x#f", Identity: "tea", Time: fri}, false},
	}
	for _, c := range cases {
		if got := p.Evaluate(c.req).Allow; got != c.want {
			t.Errorf("%s: Evaluate.Allow=%v want %v", c.name, got, c.want)
		}
	}
}

// The leak-containment control: an identity may be granted brokered delivery
// (exec/mount) while being refused the raw value (get), so an AI agent can use a
// credential it is structurally unable to see. See THREAT-MODEL.md §4b.
func TestEvaluateModes(t *testing.T) {
	now := time.Date(2026, 7, 25, 10, 0, 0, 0, time.Local)

	p := &Policy{Rules: []Rule{
		// The AI agent: brokered delivery only, never the raw value.
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"ai"},
			Modes: []string{ModeExec, ModeMount}},
		// A human: no modes listed, so every mode matches — including get.
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"me"}},
	}}

	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{"ai may exec", Request{Ref: "bao:app/gitea#token", Identity: "ai", Mode: ModeExec, Time: now}, true},
		{"ai may mount", Request{Ref: "bao:app/gitea#token", Identity: "ai", Mode: ModeMount, Time: now}, true},
		{"ai may NOT get", Request{Ref: "bao:app/gitea#token", Identity: "ai", Mode: ModeGet, Time: now}, false},
		{"human may get", Request{Ref: "bao:app/gitea#token", Identity: "me", Mode: ModeGet, Time: now}, true},
		{"human may exec", Request{Ref: "bao:app/gitea#token", Identity: "me", Mode: ModeExec, Time: now}, true},
	}
	for _, c := range cases {
		if got := p.Evaluate(c.req).Allow; got != c.want {
			t.Errorf("%s: Evaluate.Allow=%v want %v", c.name, got, c.want)
		}
	}

	// An empty Modes list must not accidentally restrict anything, and a rule
	// listing only get must not grant exec.
	getOnly := &Policy{Rules: []Rule{{Allow: true, Modes: []string{ModeGet}}}}
	if getOnly.Evaluate(Request{Ref: "x", Mode: ModeExec, Time: now}).Allow {
		t.Error("get-only rule wrongly allowed exec")
	}
	if !getOnly.Evaluate(Request{Ref: "x", Mode: ModeGet, Time: now}).Allow {
		t.Error("get-only rule wrongly refused get")
	}
}

func TestValidate(t *testing.T) {
	good := &Policy{Rules: []Rule{{Allow: true, Hours: "08:00-18:00", Weekdays: []string{"Mon"}, Monthdays: []int{1, 15}}}}
	if err := good.validate("policy.json"); err != nil {
		t.Fatalf("good policy failed validation: %v", err)
	}
	for _, bad := range []*Policy{
		{Rules: []Rule{{Hours: "8-18"}}},
		{Rules: []Rule{{Hours: "08:00_18:00"}}},
		{Rules: []Rule{{Weekdays: []string{"Funday"}}}},
		{Rules: []Rule{{Monthdays: []int{0}}}},
		{Rules: []Rule{{Monthdays: []int{32}}}},
		// A mode typo must fail loudly: silently matching nothing reads as
		// "policy ignored" rather than "rule misspelled".
		{Rules: []Rule{{Modes: []string{"exexc"}}}},
		{Rules: []Rule{{Modes: []string{ModeExec, "read"}}}},
	} {
		if err := bad.validate("policy.json"); err == nil {
			t.Errorf("expected validation error for %+v", bad.Rules[0])
		}
	}
}
