package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

// isolateState points XDG_STATE_HOME at a temp dir so a test's audit records go
// somewhere disposable. The audit log is deliberately outside the config dir, so
// isolateConfig alone is not enough: without this a test run appends real-looking
// decisions to the developer's own audit trail, which is the one file that has to
// stay trustworthy about what was actually fetched.
func isolateState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return filepath.Join(dir, "parzival")
}

// installPolicy writes a policy into an isolated config dir, isolates the audit
// log alongside it, and returns the state dir the audit log will appear in.
// probe has no --file flag by design — it asks about the policy that is actually
// in force — so every probe test has to install one.
func installPolicy(t *testing.T, body string) string {
	t.Helper()
	cfg := isolateConfig(t)
	state := isolateState(t)
	if err := os.WriteFile(filepath.Join(cfg, "policy.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	return state
}

// parsePolicy builds a Policy the same way the binary does, so a test cannot
// accidentally exercise a rule shape the real parser would refuse.
func parsePolicy(t *testing.T, body string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(body), "test-policy.json")
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return p
}

const probeBrokeredOnly = `{
  "schema": 1,
  "rules": [
    { "allow": true, "description": "brokered delivery only", "secrets": ["bao:app/gitea#*"],
      "identities": ["ai"], "modes": ["exec","mount"] }
  ]
}`

const probeGetAllowed = `{
  "schema": 1,
  "rules": [
    { "allow": true, "description": "raw value permitted", "secrets": ["gopass:*"],
      "identities": ["ansible"], "modes": ["get"] }
  ]
}`

// --- mode selection -------------------------------------------------------

// probe takes no --mode: the question is whether the identity can reach the ref
// at all. An identity restricted to brokered delivery must still be able to
// probe, or the verb fails exactly the callers it was built for.
func TestProbeReachesRefThroughBrokeredModeOnly(t *testing.T) {
	p := parsePolicy(t, probeBrokeredOnly)
	mode, reason, ok := probeReachableMode(p, "bao:app/gitea#token", "ai", time.Now())
	if !ok {
		t.Fatal("brokered-only identity could not reach its own ref")
	}
	if mode != policy.ModeExec {
		t.Errorf("reached via %q, want %q", mode, policy.ModeExec)
	}
	if reason == "" {
		t.Error("no deciding rule reported")
	}
}

// get is tried first, because the question an operator most often has is
// whether an identity can still read a raw value.
func TestProbePrefersGetWhenGetIsAllowed(t *testing.T) {
	p := parsePolicy(t, probeGetAllowed)
	mode, _, ok := probeReachableMode(p, "gopass:anything", "ansible", time.Now())
	if !ok {
		t.Fatal("get-mode identity could not reach its own ref")
	}
	if mode != policy.ModeGet {
		t.Errorf("reached via %q, want %q", mode, policy.ModeGet)
	}
}

func TestProbeReportsNoReachableMode(t *testing.T) {
	p := parsePolicy(t, probeBrokeredOnly)
	if mode, _, ok := probeReachableMode(p, "bao:app/gitea#token", "someone-else", time.Now()); ok {
		t.Errorf("an identity with no rule reached the ref via %q", mode)
	}
}

// probe must grant nothing. A mode the policy denies is never the answer, even
// when another mode for the same identity is allowed.
func TestProbeNeverReportsADeniedMode(t *testing.T) {
	p := parsePolicy(t, probeBrokeredOnly)
	mode, _, ok := probeReachableMode(p, "bao:app/gitea#token", "ai", time.Now())
	if !ok {
		t.Fatal("want reachable")
	}
	d := p.Evaluate(policy.Request{Ref: "bao:app/gitea#token", Identity: "ai", Mode: mode, Time: time.Now()})
	if !d.Allow {
		t.Errorf("probe reported mode %q, which the policy denies", mode)
	}
}

// --- verdicts and exit statuses -------------------------------------------

func TestProbeDeniedByPolicy(t *testing.T) {
	installPolicy(t, probeBrokeredOnly)
	err := runProbe([]string{"--as", "nobody", "bao:app/gitea#token"})
	if got := probeExitCode(err); got != probeExitDenied {
		t.Errorf("exit %d, want %d (DENIED)", got, probeExitDenied)
	}
}

// No policy file at all is the strict deny-by-default case, and probe must
// report it as a refusal rather than falling through to a fetch.
func TestProbeDeniedWithNoPolicyFile(t *testing.T) {
	isolateConfig(t)
	isolateState(t)
	err := runProbe([]string{"--as", "ansible", "bao:app/gitea#token"})
	if got := probeExitCode(err); got != probeExitDenied {
		t.Errorf("exit %d, want %d (DENIED)", got, probeExitDenied)
	}
}

// The verdict this verb exists for: the policy permits the fetch and the store
// refuses or cannot perform it. That is what an ungranted OpenBao ACL looks
// like from here, and it must be distinguishable from a policy denial — running
// `get` to find out which had happened is the leak this verb exists to prevent.
func TestProbeBackendFailureIsErrorNotDenied(t *testing.T) {
	installPolicy(t, probeGetAllowed)
	err := runProbe([]string{"--as", "ansible", "gopass:some/path"})
	got := probeExitCode(err)
	if got == probeExitDenied {
		t.Fatal("a backend failure was reported as a policy denial")
	}
	if got != probeExitError {
		t.Errorf("exit %d, want %d (ERROR)", got, probeExitError)
	}
}

func TestProbeRejectsWrongArgumentCount(t *testing.T) {
	installPolicy(t, probeGetAllowed)
	for _, args := range [][]string{{}, {"a", "b"}} {
		if err := runProbe(args); err == nil {
			t.Errorf("probe %v: want an error, got nil", args)
		}
	}
}

// --- the audit record -----------------------------------------------------

// A probe performs a real fetch, so it is audited — unlike `policy what-if`,
// which simulates and deliberately writes nothing. Caller marks it, so a reader
// can tell a reachability check from a delivery.
func TestProbeWritesExactlyOneAuditRecord(t *testing.T) {
	state := installPolicy(t, probeBrokeredOnly)
	_ = runProbe([]string{"--as", "nobody", "bao:app/gitea#token"})

	data, err := os.ReadFile(filepath.Join(state, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := nonEmptyLines(string(data))
	if len(lines) != 1 {
		t.Fatalf("wrote %d audit records, want exactly 1:\n%s", len(lines), data)
	}
	if !strings.Contains(lines[0], "probe") {
		t.Errorf("audit record does not identify itself as a probe: %s", lines[0])
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
