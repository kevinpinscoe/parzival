package policy

import (
	"strings"
	"testing"
)

// allow and deny build rules compactly, so a test's ordering intent is visible
// on one line instead of buried in struct literals.
func allow(secrets, identities, modes []string) Rule {
	return Rule{Allow: true, Secrets: secrets, Identities: identities, Modes: modes}
}

func deny(secrets, identities, modes []string) Rule {
	return Rule{Allow: false, Secrets: secrets, Identities: identities, Modes: modes}
}

func TestBuildGrantRuleDefaultsToBrokeredModes(t *testing.T) {
	r, err := BuildGrantRule(GrantRequest{
		Tool:       "codex",
		Goal:       "file YouTrack issues",
		Secrets:    []string{"bao:app/YouTrack-Codex#token"},
		Identities: []string{"codex"},
	})
	if err != nil {
		t.Fatalf("BuildGrantRule: %v", err)
	}
	if !r.Allow {
		t.Error("a grant must produce an allow-rule")
	}
	// The central safety property: saying nothing about modes must never be
	// read as asking for raw retrieval.
	if permitsGet(r) {
		t.Errorf("grant with no modes stated permits get: %v", r.Modes)
	}
	want := map[string]bool{ModeExec: true, ModeMount: true}
	if len(r.Modes) != len(want) {
		t.Fatalf("modes = %v, want exec and mount", r.Modes)
	}
	for _, m := range r.Modes {
		if !want[m] {
			t.Errorf("unexpected default mode %q", m)
		}
	}
	if r.Description != "codex: file YouTrack issues" {
		t.Errorf("description = %q, want the tool and goal", r.Description)
	}
}

func TestBuildGrantRuleGrantsGetOnlyWhenAsked(t *testing.T) {
	g := GrantRequest{
		Secrets:    []string{"op://Private/Gitea/token"},
		Identities: []string{"kevin"},
		Modes:      []string{ModeGet},
	}
	if !g.GrantsRawGet() {
		t.Error("GrantsRawGet must report a deliberate get request")
	}
	r, err := BuildGrantRule(g)
	if err != nil {
		t.Fatalf("BuildGrantRule: %v", err)
	}
	if !permitsGet(r) {
		t.Error("a deliberately requested get was not granted")
	}
}

func TestBuildGrantRuleRejectsBadInput(t *testing.T) {
	cases := map[string]GrantRequest{
		"no secrets":        {Identities: []string{"ai"}},
		"no identities":     {Secrets: []string{"bao:app/x#token"}},
		"unknown mode":      {Secrets: []string{"bao:app/x#token"}, Identities: []string{"ai"}, Modes: []string{"exce"}},
		"bad hours":         {Secrets: []string{"bao:app/x#token"}, Identities: []string{"ai"}, Hours: "8am-6pm"},
		"bad weekday":       {Secrets: []string{"bao:app/x#token"}, Identities: []string{"ai"}, Weekdays: []string{"Funday"}},
		"bad monthday":      {Secrets: []string{"bao:app/x#token"}, Identities: []string{"ai"}, Monthdays: []int{32}},
		"negative monthday": {Secrets: []string{"bao:app/x#token"}, Identities: []string{"ai"}, Monthdays: []int{0}},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildGrantRule(g); err == nil {
				t.Fatal("expected a refusal, got none")
			}
		})
	}
}

func TestInsertionGoesAboveAnEarlierBlockingDeny(t *testing.T) {
	// Rule 0 denies every agent-* label everything under bao:app. A grant for
	// one ref under that prefix has to go above it or it never fires.
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/*"}, []string{"agent-*"}, nil),
		allow([]string{"bao:other/*"}, []string{"kevin"}, nil),
	}}
	proposed, err := BuildGrantRule(GrantRequest{
		Secrets:    []string{"bao:app/YouTrack-Codex#token"},
		Identities: []string{"agent-*"},
	})
	if err != nil {
		t.Fatalf("BuildGrantRule: %v", err)
	}

	pl := p.AnalyzeRuleInsertion(proposed)
	if pl.Err != nil {
		t.Fatalf("placement refused: %v", pl.Err)
	}
	if pl.Index != 0 {
		t.Errorf("Index = %d, want 0 (above the blocking deny)", pl.Index)
	}
	if len(pl.BlockedBy) != 1 || pl.BlockedBy[0] != 0 {
		t.Errorf("BlockedBy = %v, want [0]", pl.BlockedBy)
	}

	// And the placement has to actually work: evaluate it.
	updated, err := p.InsertRule(proposed, pl.Index)
	if err != nil {
		t.Fatalf("InsertRule: %v", err)
	}
	d := updated.Evaluate(Request{Ref: "bao:app/YouTrack-Codex#token", Identity: "agent-x", Mode: ModeExec})
	if !d.Allow {
		t.Errorf("the inserted rule does not fire: %+v", d)
	}
	// Everything else the deny covered must still be denied.
	d = updated.Evaluate(Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: ModeExec})
	if d.Allow {
		t.Error("insertion widened the grant beyond the requested ref")
	}
}

func TestInsertionGoesBelowANarrowerRuleItWouldSwallow(t *testing.T) {
	// Rule 0 denies one specific ref to one specific label. A broad allow over
	// the whole prefix must go below it, or that deny stops working.
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/gitea#token"}, []string{"agent-x"}, nil),
	}}
	proposed := allow([]string{"bao:app/*"}, []string{"agent-*"}, nil)

	pl := p.AnalyzeRuleInsertion(proposed)
	if pl.Err != nil {
		t.Fatalf("placement refused: %v", pl.Err)
	}
	if pl.Index != 1 {
		t.Errorf("Index = %d, want 1 (below the narrower deny)", pl.Index)
	}
	if len(pl.WouldBlock) != 1 || pl.WouldBlock[0] != 0 {
		t.Errorf("WouldBlock = %v, want [0]", pl.WouldBlock)
	}

	updated, _ := p.InsertRule(proposed, pl.Index)
	if updated.Evaluate(Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: ModeExec}).Allow {
		t.Error("the pre-existing deny stopped working")
	}
	if !updated.Evaluate(Request{Ref: "bao:app/gitea#token", Identity: "agent-y", Mode: ModeExec}).Allow {
		t.Error("the new allow does not fire for a label the deny did not name")
	}
}

func TestAmbiguousInsertionIsRefusedRatherThanGuessed(t *testing.T) {
	// Neither rule contains the other: the deny is narrower on identity, the
	// proposal is narrower on mode. Ordering them decides only the requests they
	// share, and nothing says which way that should go.
	p := &Policy{Rules: []Rule{
		deny([]string{"bao:app/gitea#token"}, []string{"agent-x"}, nil),
	}}
	proposed := allow([]string{"bao:app/gitea#token"}, []string{"agent-*"}, []string{ModeExec, ModeMount})

	pl := p.AnalyzeRuleInsertion(proposed)
	if pl.Err == nil {
		t.Fatalf("ambiguous placement was resolved to index %d instead of refused", pl.Index)
	}
	if len(pl.Ambiguous) != 1 || pl.Ambiguous[0] != 0 {
		t.Errorf("Ambiguous = %v, want [0]", pl.Ambiguous)
	}
	if !strings.Contains(pl.Err.Error(), "rule 0") {
		t.Errorf("the refusal does not name the conflicting rule: %v", pl.Err)
	}
}

func TestInsertionReportsRedundancy(t *testing.T) {
	p := &Policy{Rules: []Rule{
		allow([]string{"bao:app/*"}, []string{"agent-*"}, []string{ModeExec, ModeMount}),
	}}
	proposed := allow([]string{"bao:app/gitea#token"}, []string{"agent-x"}, []string{ModeExec})

	pl := p.AnalyzeRuleInsertion(proposed)
	if pl.Err != nil {
		t.Fatalf("placement refused: %v", pl.Err)
	}
	if !pl.Redundant() {
		t.Fatal("a rule already covered by a broader allow was not reported as redundant")
	}
	if pl.CoveredBy != 0 {
		t.Errorf("CoveredBy = %d, want 0", pl.CoveredBy)
	}
}

func TestInsertionIntoAnEmptyPolicy(t *testing.T) {
	p := &Policy{}
	proposed := allow([]string{"bao:app/x#token"}, []string{"ai"}, []string{ModeExec})
	pl := p.AnalyzeRuleInsertion(proposed)
	if pl.Err != nil {
		t.Fatalf("placement refused: %v", pl.Err)
	}
	if pl.Index != 0 {
		t.Errorf("Index = %d, want 0", pl.Index)
	}
	updated, err := p.InsertRule(proposed, pl.Index)
	if err != nil {
		t.Fatalf("InsertRule: %v", err)
	}
	// A policy with no schema declared is stamped on the way out, so an edited
	// file records the version it was edited against.
	if updated.Schema != SchemaVersion {
		t.Errorf("Schema = %d, want %d", updated.Schema, SchemaVersion)
	}
}

func TestInsertRuleDoesNotMutateTheOriginal(t *testing.T) {
	p := &Policy{Schema: 1, Rules: []Rule{
		deny([]string{"bao:prod/*"}, nil, nil),
	}}
	before := len(p.Rules)
	if _, err := p.InsertRule(allow([]string{"bao:app/x#token"}, []string{"ai"}, nil), 0); err != nil {
		t.Fatalf("InsertRule: %v", err)
	}
	if len(p.Rules) != before {
		t.Errorf("the original policy grew to %d rules; the candidate must be a copy", len(p.Rules))
	}
}

func TestInsertRuleRejectsAnOutOfRangeIndex(t *testing.T) {
	p := &Policy{Rules: []Rule{deny(nil, nil, nil)}}
	for _, i := range []int{-1, 2} {
		if _, err := p.InsertRule(allow([]string{"x"}, []string{"y"}, nil), i); err == nil {
			t.Errorf("index %d was accepted", i)
		}
	}
}
