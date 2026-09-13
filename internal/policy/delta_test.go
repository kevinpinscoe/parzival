package policy

import (
	"testing"
	"time"
)

// noon is a fixed evaluation instant. Delta results must not depend on when the
// test suite happens to run.
var noon = time.Date(2026, 9, 8, 12, 0, 0, 0, time.Local)

func TestDeltaReportsOnlyTheRequestedGrant(t *testing.T) {
	before := &Policy{Rules: []Rule{
		allow([]string{"bao:app/gitea#token"}, []string{"tea"}, []string{ModeExec}),
	}}
	proposed := allow([]string{"bao:app/YouTrack-Codex#token"}, []string{"codex"}, []string{ModeExec, ModeMount})
	after, err := before.InsertRule(proposed, 1)
	if err != nil {
		t.Fatalf("InsertRule: %v", err)
	}

	probes := ProbeSet([]*Policy{before, after}, RuleProbes(proposed))
	d := DiffAuthorization(before, after, probes, noon)

	if d.Empty() {
		t.Fatal("the delta is empty; the grant did nothing")
	}
	if len(d.Revocations()) != 0 {
		t.Errorf("a pure grant revoked something: %v", d.Revocations())
	}
	// Everything that changed must be something the proposed rule asked for.
	if unexpected := d.Unexpected(RuleProbes(proposed)); len(unexpected) != 0 {
		for _, c := range unexpected {
			t.Errorf("unexpected authorization change: %s", c.Describe())
		}
	}
	// And exactly the two brokered modes moved — not get.
	for _, c := range d.Grants() {
		if c.Probe.Mode == ModeGet {
			t.Errorf("get was granted: %s", c.Describe())
		}
	}
	if len(d.Grants()) != 2 {
		t.Errorf("granted %d probes, want exec and mount only", len(d.Grants()))
	}
}

func TestDeltaCatchesBroadeningBeyondTheRequest(t *testing.T) {
	// The operator asks about one ref, but the rule they actually wrote covers
	// the whole prefix. The delta has to surface the difference.
	before := &Policy{Rules: []Rule{
		allow([]string{"bao:app/gitea#token"}, []string{"tea"}, []string{ModeExec}),
	}}
	tooBroad := allow([]string{"bao:app/*"}, []string{"codex"}, []string{ModeExec})
	after, _ := before.InsertRule(tooBroad, 1)

	// What the operator believed they were granting.
	intended := []Probe{{Ref: "bao:app/YouTrack-Codex#token", Identity: "codex", Mode: ModeExec}}
	probes := ProbeSet([]*Policy{before, after}, intended)
	d := DiffAuthorization(before, after, probes, noon)

	unexpected := d.Unexpected(intended)
	if len(unexpected) == 0 {
		t.Fatal("a rule broadened well past the stated intent produced no unexpected changes")
	}
	var sawGiteaRef bool
	for _, c := range unexpected {
		if c.Probe.Ref == "bao:app/gitea#token" && c.Probe.Identity == "codex" {
			sawGiteaRef = true
		}
	}
	if !sawGiteaRef {
		t.Error("the delta did not notice that codex gained access to bao:app/gitea#token")
	}
}

func TestDeltaCatchesAccidentalRevocation(t *testing.T) {
	// Inserting a deny above an existing allow revokes access without touching
	// the allow's text — the failure a textual diff reads as one added line.
	before := &Policy{Rules: []Rule{
		allow([]string{"bao:app/*"}, []string{"tea"}, []string{ModeExec}),
	}}
	after, _ := before.InsertRule(deny([]string{"bao:app/gitea#token"}, nil, nil), 0)

	probes := ProbeSet([]*Policy{before, after}, nil)
	d := DiffAuthorization(before, after, probes, noon)

	rev := d.Revocations()
	if len(rev) == 0 {
		t.Fatal("inserting a deny above an allow revoked nothing")
	}
	if len(d.Grants()) != 0 {
		t.Errorf("a pure deny granted something: %v", d.Grants())
	}
}

func TestDeltaAgainstNoPolicyAtAll(t *testing.T) {
	// A host with no policy file denies everything. The first grant's delta is
	// measured against that, not against an empty rule list that might be read
	// as "no opinion".
	after := &Policy{Rules: []Rule{
		allow([]string{"bao:app/x#token"}, []string{"ai"}, []string{ModeExec}),
	}}
	probes := ProbeSet([]*Policy{after}, nil)
	d := DiffAuthorization(nil, after, probes, noon)
	if len(d.Grants()) != 1 {
		t.Errorf("granted %d probes against a nil policy, want 1", len(d.Grants()))
	}
	for _, c := range d.Grants() {
		if c.WasRule != -1 {
			t.Errorf("WasRule = %d against a nil policy, want -1", c.WasRule)
		}
	}
}

func TestDeltaFlagsTimeConditionalRules(t *testing.T) {
	// The delta is computed at one instant, so a rule that only applies inside a
	// window has to be named rather than silently contributing nothing.
	before := &Policy{}
	windowed := Rule{
		Allow: true, Secrets: []string{"bao:app/x#token"}, Identities: []string{"tea"},
		Modes: []string{ModeExec}, Weekdays: []string{"Mon"}, Hours: "08:00-18:00",
	}
	after, _ := before.InsertRule(windowed, 0)

	d := DiffAuthorization(before, after, ProbeSet([]*Policy{after}, nil), noon)
	if len(d.TimeConditional) != 1 || d.TimeConditional[0] != 0 {
		t.Errorf("TimeConditional = %v, want [0]", d.TimeConditional)
	}
}

func TestProbeSetAlwaysCoversEveryMode(t *testing.T) {
	// A policy that never mentions get is exactly where an accidentally granted
	// get matters most, so get must be probed regardless.
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/x#token"}, []string{"ai"}, []string{ModeExec}),
	}}
	probes := ProbeSet([]*Policy{p}, nil)
	var sawGet bool
	for _, pr := range probes {
		if pr.Mode == ModeGet {
			sawGet = true
		}
	}
	if !sawGet {
		t.Error("ProbeSet omitted get from a policy that never names it")
	}
}

func TestProbeSetIncludesTheEmptyIdentity(t *testing.T) {
	// A request with no --as is a real request, matched only by rules that place
	// no identity condition.
	p := &Policy{Rules: []Rule{allow([]string{"bao:app/x#token"}, []string{"ai"}, nil)}}
	var sawEmpty bool
	for _, pr := range ProbeSet([]*Policy{p}, nil) {
		if pr.Identity == "" {
			sawEmpty = true
		}
	}
	if !sawEmpty {
		t.Error("ProbeSet omitted the empty identity label")
	}
}

func TestProbeSetIsNonEmptyForAnUnconditionalPolicy(t *testing.T) {
	// A policy of rules with no conditions names no ref at all. The cross
	// product of an empty set is empty, which would read as "nothing changed".
	p := &Policy{Rules: []Rule{{Allow: true}}}
	if got := len(ProbeSet([]*Policy{p}, nil)); got == 0 {
		t.Fatal("ProbeSet produced no probes for an unconditional policy")
	}
	d := DiffAuthorization(&Policy{}, p, ProbeSet([]*Policy{p}, nil), noon)
	if d.Empty() {
		t.Error("adding an allow-everything rule produced an empty delta")
	}
}

func TestRuleProbesCoverEveryModeWhenTheRuleNamesNone(t *testing.T) {
	// A rule with no modes matches every mode, so that is what it should be
	// held to when the delta asks what it requested.
	probes := RuleProbes(allow([]string{"bao:app/x#token"}, []string{"ai"}, nil))
	if len(probes) != 3 {
		t.Errorf("RuleProbes returned %d probes for an unrestricted rule, want 3", len(probes))
	}
}
