package main

import (
	"strings"
	"testing"
)

func TestUnifiedDiffIsEmptyForIdenticalInput(t *testing.T) {
	lines := []string{"a", "b", "c"}
	if got := unifiedDiff(lines, lines, "old", "new", 3); got != "" {
		t.Errorf("identical input produced a diff:\n%s", got)
	}
}

func TestUnifiedDiffShowsAnInsertion(t *testing.T) {
	a := []string{"{", `  "rules": [`, "    one", "  ]", "}"}
	b := []string{"{", `  "rules": [`, "    zero", "    one", "  ]", "}"}

	got := unifiedDiff(a, b, "policy.json", "candidate.json", 3)
	if !strings.HasPrefix(got, "--- policy.json\n+++ candidate.json\n") {
		t.Fatalf("missing or wrong header:\n%s", got)
	}
	if !strings.Contains(got, "+    zero") {
		t.Errorf("the inserted line is not marked as added:\n%s", got)
	}
	// Nothing was removed, so nothing may be shown as removed — a spurious `-`
	// line in a policy diff would read as an access revocation.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			t.Errorf("a pure insertion reported a deletion: %q", line)
		}
	}
}

func TestUnifiedDiffShowsADeletion(t *testing.T) {
	a := []string{"one", "two", "three"}
	b := []string{"one", "three"}

	got := unifiedDiff(a, b, "old", "new", 3)
	if !strings.Contains(got, "-two") {
		t.Errorf("the removed line is not marked as removed:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			t.Errorf("a pure deletion reported an insertion: %q", line)
		}
	}
}

func TestUnifiedDiffShowsAReplacement(t *testing.T) {
	a := []string{"one", "two", "three"}
	b := []string{"one", "TWO", "three"}

	got := unifiedDiff(a, b, "old", "new", 3)
	if !strings.Contains(got, "-two") || !strings.Contains(got, "+TWO") {
		t.Errorf("a replacement was not shown as both sides:\n%s", got)
	}
}

func TestUnifiedDiffLimitsContext(t *testing.T) {
	// Twenty unchanged lines around one change: with 2 lines of context the
	// output must not carry the whole file.
	var a, b []string
	for i := range 20 {
		a = append(a, string(rune('a'+i)))
		b = append(b, string(rune('a'+i)))
	}
	b[10] = "CHANGED"

	got := unifiedDiff(a, b, "old", "new", 2)
	body := strings.Count(got, "\n")
	if body > 12 {
		t.Errorf("context was not limited — %d lines for a one-line change:\n%s", body, got)
	}
	if !strings.Contains(got, "@@") {
		t.Errorf("no hunk header:\n%s", got)
	}
}

func TestUnifiedDiffSeparatesDistantChanges(t *testing.T) {
	var a []string
	for i := range 40 {
		a = append(a, string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	b := append([]string(nil), a...)
	b[2] = "FIRST"
	b[35] = "SECOND"

	got := unifiedDiff(a, b, "old", "new", 3)
	if n := strings.Count(got, "@@ -"); n != 2 {
		t.Errorf("expected two hunks for two distant changes, got %d:\n%s", n, got)
	}
}

func TestUnifiedDiffHandlesAnEmptyOriginal(t *testing.T) {
	// The first grant on a host with no policy diffs against nothing.
	got := unifiedDiff(nil, []string{"{", "}"}, "policy.json", "candidate.json", 3)
	if got == "" {
		t.Fatal("creating a file from nothing produced no diff")
	}
	if !strings.Contains(got, "+{") {
		t.Errorf("the new content is not shown as added:\n%s", got)
	}
}

func TestSplitLinesDropsTheTrailingNewline(t *testing.T) {
	// Marshal always terminates with a newline; without this every diff would
	// carry a spurious trailing blank line.
	got := splitLines([]byte("a\nb\n"))
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("splitLines = %q", got)
	}
	if len(splitLines(nil)) != 0 || len(splitLines([]byte("\n"))) != 0 {
		t.Error("empty input should produce no lines")
	}
}
