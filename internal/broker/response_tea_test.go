package broker

import (
	"encoding/json"
	"testing"
)

func TestCanonicalizeTeaReposListAcceptsApprovedShape(t *testing.T) {
	raw := []byte(`[{"owner":"acme","name":"repo","type":"source","ssh":"ssh://x"}]`)
	got, err := canonicalizeTeaReposList(raw)
	if err != nil {
		t.Fatalf("canonicalizeTeaReposList: unexpected error: %v", err)
	}
	var repos []repoSummary
	if err := json.Unmarshal(got, &repos); err != nil {
		t.Fatalf("canonicalize output did not re-decode: %v", err)
	}
	if len(repos) != 1 || repos[0].Owner != "acme" {
		t.Errorf("canonicalizeTeaReposList: got %+v", repos)
	}
}

func TestCanonicalizeTeaReposListRejectsWrongTopLevelShape(t *testing.T) {
	_, err := canonicalizeTeaReposList([]byte(`{"not":"an array"}`))
	if err == nil {
		t.Fatal("canonicalizeTeaReposList: expected an error for a non-array top level, got none")
	}
}

func TestCanonicalizeTeaReposListRejectsUnknownField(t *testing.T) {
	_, err := canonicalizeTeaReposList([]byte(`[{"owner":"acme","name":"repo","type":"source","ssh":"ssh://x","extra":"field"}]`))
	if err == nil {
		t.Fatal("canonicalizeTeaReposList: expected an error for an unexpected field, got none")
	}
}

func TestCanonicalizeTeaReposListRejectsTrailingData(t *testing.T) {
	_, err := canonicalizeTeaReposList([]byte(`[{"owner":"acme","name":"repo","type":"source","ssh":"ssh://x"}]garbage`))
	if err == nil {
		t.Fatal("canonicalizeTeaReposList: expected an error for trailing data, got none")
	}
}

func TestCanonicalizeTeaReposListStripsUnrequestedContent(t *testing.T) {
	// The canonical output is a fresh re-marshal of the typed value, so it
	// can never carry anything beyond the four approved fields even if a
	// future consumer definition somehow requested more via --fields (an
	// operation's argv is fixed by the consumer definition, not the client,
	// but this is the defense that makes the canonicalizer's own contract
	// checkable independent of that).
	raw := []byte(`[{"owner":"acme","name":"repo","type":"source","ssh":"ssh://x"}]`)
	got, err := canonicalizeTeaReposList(raw)
	if err != nil {
		t.Fatalf("canonicalizeTeaReposList: unexpected error: %v", err)
	}
	var generic []map[string]any
	if err := json.Unmarshal(got, &generic); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if len(generic) != 1 || len(generic[0]) != 4 {
		t.Errorf("canonicalizeTeaReposList: output has %d fields, want exactly 4 (owner/name/type/ssh): %v", len(generic[0]), generic[0])
	}
}
