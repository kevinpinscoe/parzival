package policy

import "testing"

// The shape that shipped in examples/policy.json and ran in production: one
// rule restricts the AI identity to brokered delivery, a second rule permits any mode
// on the same ref for a different label. Because --as is self-asserted, the
// restriction is decorative — the caller just passes the other label.
func TestCheckFindsIdentityBypass(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"ai"}, Modes: []string{"exec", "mount"}},
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"tea"}},
	}}

	rep := p.Check()
	if rep.OK() {
		t.Fatal("Check found no bypass, but --as tea reads the raw value rule 0 refuses to ai")
	}
	if len(rep.Weakened) != 1 {
		t.Fatalf("Weakened = %d findings, want 1: %+v", len(rep.Weakened), rep.Weakened)
	}
	w := rep.Weakened[0]
	if w.RestrictedRule != 0 || w.OpenRule != 1 {
		t.Errorf("finding names rules %d/%d, want restricted 0 open 1", w.RestrictedRule, w.OpenRule)
	}
	if len(rep.GetOpen) != 1 || rep.GetOpen[0].Rule != 1 {
		t.Errorf("GetOpen = %+v, want just rule 1", rep.GetOpen)
	}
}

// The robust construction: restrict the ref rather than the identity. With every
// allow-rule for the ref excluding get, no label reaches the raw value.
func TestCheckRefFirstPolicyIsClean(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"ai"}, Modes: []string{"exec", "mount"}},
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"tea"}, Modes: []string{"exec", "mount"}},
	}}

	if rep := p.Check(); !rep.OK() {
		t.Fatalf("ref-first policy reported bypassable: %+v", rep.Weakened)
	}
}

// A broader pattern overlapping a narrower one is still a bypass.
func TestCheckDetectsOverlapByWildcard(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#token"}, Identities: []string{"ai"}, Modes: []string{"exec"}},
		{Allow: true, Secrets: []string{"bao:app/*"}, Identities: []string{"human"}},
	}}

	if rep := p.Check(); rep.OK() {
		t.Fatal("bao:app/* overlaps bao:app/gitea#token and permits get, but no finding was raised")
	}
}

// A rule with no secrets list matches every ref, so it defeats every restriction.
func TestCheckTreatsUnscopedRuleAsOverlappingEverything(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"ai"}, Modes: []string{"exec"}},
		{Allow: true, Identities: []string{"human"}},
	}}

	if rep := p.Check(); rep.OK() {
		t.Fatal("an unscoped allow-rule permitting get defeats every mode restriction")
	}
}

// If the only rule permitting get is reachable by exactly the identities the
// restriction covers, there is no other label to assert, so it is not a bypass.
func TestCheckIgnoresSubsumedIdentities(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"ai", "agent-*"}, Modes: []string{"exec"}},
		{Allow: true, Secrets: []string{"bao:app/gitea#*"}, Identities: []string{"agent-one"}},
	}}

	rep := p.Check()
	if !rep.OK() {
		t.Fatalf("agent-one is already covered by the restricted rule's globs; not a new bypass: %+v", rep.Weakened)
	}
	// It is still reported as a place the raw value is readable.
	if len(rep.GetOpen) != 1 {
		t.Errorf("GetOpen = %+v, want rule 1 listed", rep.GetOpen)
	}
}

// A deny-rule permits nothing, so it is never a bypass source.
func TestCheckIgnoresDenyRules(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Allow: false, Secrets: []string{"bao:prod/*"}},
		{Allow: true, Secrets: []string{"bao:prod/*"}, Identities: []string{"ai"}, Modes: []string{"exec"}},
	}}

	rep := p.Check()
	if len(rep.GetOpen) != 0 {
		t.Errorf("a deny-rule was counted as permitting get: %+v", rep.GetOpen)
	}
	if !rep.OK() {
		t.Errorf("no allow-rule permits get here: %+v", rep.Weakened)
	}
}

func TestPermitsGet(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"no modes means every mode", Rule{Allow: true}, true},
		{"explicit get", Rule{Allow: true, Modes: []string{"get"}}, true},
		{"brokered only", Rule{Allow: true, Modes: []string{"exec", "mount"}}, false},
		{"mount only", Rule{Allow: true, Modes: []string{"mount"}}, false},
	}
	for _, c := range cases {
		if got := permitsGet(c.rule); got != c.want {
			t.Errorf("%s: permitsGet = %v, want %v", c.name, got, c.want)
		}
	}
}
