package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/ephemeral"
	"github.com/kevinpinscoe/parzival/internal/policy"
	"github.com/kevinpinscoe/parzival/internal/profile"
	"github.com/kevinpinscoe/parzival/internal/store"
)

// Tests for deny_agents at the CLI (PARZIVAL-84): exec authorizes every secret
// before fetching any, and an agent-denying rule refuses before the store, the
// renderer, the RAM file or the child is touched.

// execSpy replaces every credential-bearing stage of the exec pipeline and
// counts how often each is reached.
type execSpy struct {
	resolves, gets, renders, dirs, children int
	childCredFile                           string // contents of $PARZIVAL_CRED_FILE as the child saw it
}

type spyStore struct{ spy *execSpy }

func (s spyStore) Name() string                     { return "spy" }
func (s spyStore) Capabilities() store.Capabilities { return store.Capabilities{} }
func (s spyStore) Get(_ context.Context, ref store.SecretRef) ([]byte, error) {
	s.spy.gets++
	return []byte("value-of-" + ref.Path), nil
}

func installExecSpy(t *testing.T) *execSpy {
	t.Helper()
	spy := &execSpy{}
	origResolve, origRender, origDir, origChild := resolveStore, renderProfile, newCredDir, startChild
	t.Cleanup(func() {
		resolveStore, renderProfile, newCredDir, startChild = origResolve, origRender, origDir, origChild
	})
	resolveStore = func(store.SecretRef) (store.Store, error) {
		spy.resolves++
		return spyStore{spy}, nil
	}
	renderProfile = func(p *profile.Profile, s map[string][]byte) ([]byte, error) {
		spy.renders++
		return p.Render(s)
	}
	newCredDir = func() (*ephemeral.Dir, error) {
		spy.dirs++
		return ephemeral.New()
	}
	startChild = func(c *exec.Cmd) error {
		spy.children++
		for _, kv := range c.Env {
			if path, ok := strings.CutPrefix(kv, "PARZIVAL_CRED_FILE="); ok {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				spy.childCredFile = string(data)
			}
		}
		return nil
	}
	return spy
}

func (s *execSpy) assertNothingTouched(t *testing.T) {
	t.Helper()
	if s.resolves+s.gets+s.renders+s.dirs+s.children != 0 {
		t.Errorf("a refused exec reached the credential pipeline: %d store resolutions, %d fetches, %d renders, %d credential dirs, %d children",
			s.resolves, s.gets, s.renders, s.dirs, s.children)
	}
}

// installProfile writes a two-secret exec profile: "first" sorts before
// "second", so a refusal of the second secret happens after the first was
// already authorized.
func installProfile(t *testing.T, cfg string) {
	t.Helper()
	dir := filepath.Join(cfg, "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{
  "secrets": { "first": "bao:app/ordinary#token", "second": "bao:app/admin#token" },
  "template": "{{.first}} {{.second}}"
}`
	if err := os.WriteFile(filepath.Join(dir, "pair.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setupExec(t *testing.T, policyBody string) *execSpy {
	t.Helper()
	cfg := isolateConfig(t)
	isolateState(t)
	if err := os.WriteFile(filepath.Join(cfg, "policy.json"), []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	installProfile(t, cfg)
	return installExecSpy(t)
}

func runAsAgent(t *testing.T) {
	t.Helper()
	clearAgentMarkers(t)
	t.Setenv("PARZIVAL_AGENT", "1")
}

// Only the first secret has a rule; the second falls to the default deny.
const firstSecretOnly = `{"rules": [
  { "allow": true, "secrets": ["bao:app/ordinary#token"], "modes": ["exec"] }
]}`

// The ordinary secret is open to anyone through exec; the admin secret is
// refused to agent contexts whatever label they assert, and the broad grant
// below it cannot be reached by an agent for that ref.
const adminDeniedToAgents = `{"rules": [
  { "allow": true, "deny_agents": true, "secrets": ["bao:app/admin#token"], "modes": ["exec","mount"] },
  { "allow": true, "secrets": ["bao:app/*"], "modes": ["exec","mount"] }
]}`

func TestExecDeniedSecondSecretFetchesNothing(t *testing.T) {
	clearAgentMarkers(t)
	spy := setupExec(t, firstSecretOnly)
	err := runExec([]string{"pair", "--", "true"})
	var denied *policy.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("want a policy denial, got %v", err)
	}
	if denied.Req.Ref != "bao:app/admin#token" {
		t.Errorf("denied ref %q, want the second secret", denied.Req.Ref)
	}
	spy.assertNothingTouched(t)
}

func TestExecAgentDenialFetchesNothing(t *testing.T) {
	runAsAgent(t)
	spy := setupExec(t, adminDeniedToAgents)
	err := runExec([]string{"pair", "--", "true"})
	var denied *policy.DeniedError
	if !errors.As(err, &denied) || !denied.AgentDenied {
		t.Fatalf("want an agent denial, got %v", err)
	}
	spy.assertNothingTouched(t)
}

func TestExecAgentDenialHoldsForEveryIdentity(t *testing.T) {
	runAsAgent(t)
	for _, id := range []string{"kevin", "admin", "ai", "human-only"} {
		spy := setupExec(t, adminDeniedToAgents)
		err := runExec([]string{"--as", id, "pair", "--", "true"})
		var denied *policy.DeniedError
		if !errors.As(err, &denied) || !denied.AgentDenied {
			t.Errorf("--as %s: want an agent denial, got %v", id, err)
		}
		spy.assertNothingTouched(t)
	}
	// $PARZIVAL_IDENTITY is the other way to assert a label.
	t.Setenv("PARZIVAL_IDENTITY", "kevin")
	spy := setupExec(t, adminDeniedToAgents)
	if err := runExec([]string{"pair", "--", "true"}); err == nil {
		t.Error("$PARZIVAL_IDENTITY bypassed the agent denial")
	}
	spy.assertNothingTouched(t)
}

func TestExecWithoutAnAgentIsUnchanged(t *testing.T) {
	clearAgentMarkers(t)
	spy := setupExec(t, adminDeniedToAgents)
	if err := runExec([]string{"pair", "--", "true"}); err != nil {
		t.Fatalf("non-agent exec refused: %v", err)
	}
	if spy.gets != 2 || spy.renders != 1 || spy.dirs != 1 || spy.children != 1 {
		t.Errorf("pipeline counts %+v, want 2 fetches and one render, dir and child", *spy)
	}
	if spy.childCredFile != "value-of-app/ordinary value-of-app/admin" {
		t.Errorf("child saw %q", spy.childCredFile)
	}
}

func TestOrdinaryAgentExecIsUnchanged(t *testing.T) {
	runAsAgent(t)
	spy := setupExec(t, `{"rules": [
	  { "allow": true, "secrets": ["bao:app/*"], "identities": ["ai"], "modes": ["exec","mount"] }
	]}`)
	if err := runExec([]string{"--as", "ai", "pair", "--", "true"}); err != nil {
		t.Fatalf("ordinary agent exec refused: %v", err)
	}
	if spy.gets != 2 || spy.children != 1 {
		t.Errorf("pipeline counts %+v, want 2 fetches and one child", *spy)
	}
}

// The global get refusal is unchanged and still comes first: an agent shell is
// refused before any policy is consulted, deny_agents or not.
func TestGetRefusalInAnAgentShellIsUnchanged(t *testing.T) {
	runAsAgent(t)
	spy := setupExec(t, `{"rules": [{ "allow": true, "secrets": ["bao:app/*"] }]}`)
	err := runGet([]string{"bao:app/ordinary#token"})
	if err == nil || !strings.Contains(err.Error(), "AI agent") {
		t.Fatalf("want the agent-shell refusal, got %v", err)
	}
	spy.assertNothingTouched(t)
}

func TestProbeReportsAnAgentDenial(t *testing.T) {
	runAsAgent(t)
	spy := setupExec(t, adminDeniedToAgents)
	if got := probeExitCode(runProbe([]string{"--as", "kevin", "bao:app/admin#token"})); got != probeExitDenied {
		t.Errorf("probe exit %d, want %d (DENIED)", got, probeExitDenied)
	}
	spy.assertNothingTouched(t)
}

// --- policy what-if --agent ------------------------------------------------

func whatIfFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWhatIfAgentFlagSelectsTheContext(t *testing.T) {
	// what-if must not inherit the shell's own agent context: the operator
	// chooses which one to ask about.
	runAsAgent(t)
	file := whatIfFile(t, adminDeniedToAgents)
	base := []string{"--file", file, "--as", "kevin", "--mode", "exec", "--ref", "bao:app/admin#token"}

	if err := runPolicyWhatIf(base); err != nil {
		t.Errorf("without --agent: want ALLOW (exit 0), got %v", err)
	}
	if code := probeExitCode(runPolicyWhatIf(append([]string{"--agent"}, base...))); code != 1 {
		t.Errorf("with --agent: exit %d, want 1 (DENY)", code)
	}
	// A ref only the broad rule covers is allowed in both contexts.
	other := []string{"--file", file, "--as", "ai", "--mode", "exec", "--ref", "bao:app/ordinary#token", "--agent"}
	if err := runPolicyWhatIf(other); err != nil {
		t.Errorf("ordinary ref with --agent: want ALLOW, got %v", err)
	}
}

func TestWhatIfExplainsAnAgentDenial(t *testing.T) {
	p := parsePolicy(t, adminDeniedToAgents)
	req := policy.Request{Ref: "bao:app/admin#token", Identity: "kevin", Mode: policy.ModeExec,
		Time: time.Now(), Agent: whatIfAgentMarker}
	allow, idx := p.Explain(req)
	var out bytes.Buffer
	writeWhatIf(&out, p, req, allow, idx, req.Time)
	text := out.String()
	for _, want := range []string{"DENY", "Matched rule: 0", "Context:      AI agent (simulated)", "deny_agents", "no later, broader rule"} {
		if !strings.Contains(text, want) {
			t.Errorf("what-if output lacks %q:\n%s", want, text)
		}
	}

	req.Agent = ""
	allow, idx = p.Explain(req)
	out.Reset()
	writeWhatIf(&out, p, req, allow, idx, req.Time)
	if !strings.Contains(out.String(), "ALLOW") || !strings.Contains(out.String(), "no AI agent detected") {
		t.Errorf("non-agent what-if:\n%s", out.String())
	}
}
