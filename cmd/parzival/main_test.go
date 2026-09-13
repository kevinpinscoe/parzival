package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kevinpinscoe/parzival/internal/agent"
)

// `parzival get REF > cred.txt` is the commonest way a raw value ends up
// permanently on disk. A pipe or terminal stays allowed — only a regular file
// is refused.
func TestRefuseRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := refuseRegularFile(f); err == nil {
		t.Error("a redirect to a regular file was permitted")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := refuseRegularFile(w); err != nil {
		t.Errorf("a pipe must stay allowed, got: %v", err)
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if err := refuseRegularFile(devnull); err != nil {
		t.Errorf("%s is a device, not a regular file, got: %v", os.DevNull, err)
	}
}

// --- the AI agent shell refusal -----------------------------

// clearAgentMarkers unsets every marker for the duration of a test, so a suite
// run from inside an agent shell — which is how this project is developed —
// starts from a known-clean environment rather than inheriting a detection.
func clearAgentMarkers(t *testing.T) {
	t.Helper()
	for _, m := range agent.Markers() {
		t.Setenv(m.Env, "")
	}
}

func TestRefuseAgentShellAllowsAnOrdinaryShell(t *testing.T) {
	clearAgentMarkers(t)
	if err := refuseAgentShell(); err != nil {
		t.Errorf("get was refused in a shell with no agent marker: %v", err)
	}
}

// Every marker must refuse, not just the one the developer happened to have set.
func TestRefuseAgentShellRefusesEveryMarker(t *testing.T) {
	for _, m := range agent.Markers() {
		t.Run(m.Env, func(t *testing.T) {
			clearAgentMarkers(t)
			t.Setenv(m.Env, "1")
			err := refuseAgentShell()
			if err == nil {
				t.Fatalf("$%s set: get was permitted", m.Env)
			}
			// The refusal has to be actionable. An agent that is told "no" and
			// not told what to do instead reaches for the next thing that works.
			for _, want := range []string{m.Env, "probe", "exec"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q: %v", want, err)
				}
			}
			// There is no override, and the message must not imply one exists.
			for _, forbidden := range []string{"--force", "--allow", "set PARZIVAL"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Errorf("refusal advertises an override (%q): %v", forbidden, err)
				}
			}
		})
	}
}

func TestSplitAtDashDash(t *testing.T) {
	pre, post, err := splitAtDashDash([]string{"--as", "ci", "aws", "--", "aws", "s3", "ls"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pre, []string{"--as", "ci", "aws"}) {
		t.Fatalf("pre = %v", pre)
	}
	if !slices.Equal(post, []string{"aws", "s3", "ls"}) {
		t.Fatalf("post = %v", post)
	}

	bad := [][]string{
		{"aws", "s3", "ls"}, // no --
		{"aws", "--"},       // no command after --
	}
	for _, args := range bad {
		if _, _, err := splitAtDashDash(args); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}

func TestSubstituteCred(t *testing.T) {
	got := substituteCred([]string{"tea", "--config", "{{cred}}", "whoami"}, "/run/x/credential", "/run/x")
	want := []string{"tea", "--config", "/run/x/credential", "whoami"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// No placeholder → unchanged.
	got = substituteCred([]string{"aws", "s3", "ls"}, "/run/x/credential", "/run/x")
	if !slices.Equal(got, []string{"aws", "s3", "ls"}) {
		t.Fatalf("unexpected substitution: %v", got)
	}
	// {{creddir}} gets the dir, not the file — and {{cred}} is not a prefix of it,
	// so both resolve correctly in the same arg.
	got = substituteCred([]string{"sh", "-c", "XDG_CONFIG_HOME={{creddir}} cat {{cred}}"}, "/run/x/tea/config.yml", "/run/x")
	want = []string{"sh", "-c", "XDG_CONFIG_HOME=/run/x cat /run/x/tea/config.yml"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
