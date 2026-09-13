package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

// writePolicy puts a policy file in a temp dir and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// isolateConfig points PARZIVAL_CONFIG_HOME at an empty temp dir, so a command
// run without --file cannot reach the developer's real policy.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
	return dir
}

const shadowedPolicy = `{
  "schema": 1,
  "rules": [
    { "allow": false, "description": "agents get nothing under bao:app", "secrets": ["bao:app/*"], "identities": ["agent-*"] },
    { "allow": true,  "description": "never reached", "secrets": ["bao:app/gitea#token"], "identities": ["agent-x"], "modes": ["exec"] }
  ]
}`

const brokeredPolicy = `{
  "schema": 1,
  "rules": [
    { "allow": true, "description": "brokered only, working hours", "secrets": ["bao:app/gitea#*"],
      "identities": ["tea"], "modes": ["exec","mount"],
      "weekdays": ["Mon","Tue","Wed","Thu","Fri"], "hours": "08:00-18:00" }
  ]
}`

// --- validate -------------------------------------------------------------

func TestValidateRejectsAnUnreachableRule(t *testing.T) {
	isolateConfig(t)
	path := writePolicy(t, shadowedPolicy)
	err := runPolicyValidate([]string{"--file", path})
	if err == nil {
		t.Fatal("a policy with an unreachable rule validated clean")
	}
	if !strings.Contains(err.Error(), "error") {
		t.Errorf("unexpected failure text: %v", err)
	}
}

func TestValidateAcceptsAPolicyWithOnlyWarnings(t *testing.T) {
	isolateConfig(t)
	// A deliberate raw-get exception is a warning, not an error: it is a real
	// capability worth seeing, but the policy means exactly what it says.
	path := writePolicy(t, `{"schema":1,"rules":[
	  {"allow":true,"secrets":["op://Private/*"],"identities":["kevin"]}
	]}`)
	if err := runPolicyValidate([]string{"--file", path}); err != nil {
		t.Errorf("a warning-only policy failed validation: %v", err)
	}
}

func TestValidateAcceptsAFileAsAPositionalArgument(t *testing.T) {
	isolateConfig(t)
	path := writePolicy(t, brokeredPolicy)
	if err := runPolicyValidate([]string{path}); err != nil {
		t.Errorf("positional file argument rejected: %v", err)
	}
}

func TestValidateRefusesBothFormsOfTheFileArgument(t *testing.T) {
	isolateConfig(t)
	path := writePolicy(t, brokeredPolicy)
	if err := runPolicyValidate([]string{"--file", path, path}); err == nil {
		t.Error("giving the file twice was accepted")
	}
}

func TestValidateReportsAMalformedPolicyRatherThanCrashing(t *testing.T) {
	isolateConfig(t)
	for name, body := range map[string]string{
		"trailing data": `{"rules":[]}{"rules":[]}`,
		"unknown field": `{"schema":1,"rules":[{"allow":true,"modez":["exec"]}]}`,
		"bad mode":      `{"schema":1,"rules":[{"allow":true,"modes":["exce"]}]}`,
		"bad hours":     `{"schema":1,"rules":[{"allow":true,"hours":"8am-6pm"}]}`,
		"bad weekday":   `{"schema":1,"rules":[{"allow":true,"weekdays":["Funday"]}]}`,
		"bad monthday":  `{"schema":1,"rules":[{"allow":true,"monthdays":[32]}]}`,
		"newer schema":  `{"schema":99,"rules":[]}`,
		"not json":      `nonsense`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := runPolicyValidate([]string{"--file", writePolicy(t, body)}); err == nil {
				t.Fatalf("%s validated clean", name)
			}
		})
	}
}

func TestValidateOnAMissingFileIsAnError(t *testing.T) {
	isolateConfig(t)
	err := runPolicyValidate([]string{"--file", filepath.Join(t.TempDir(), "absent.json")})
	if err == nil {
		t.Fatal("a named file that does not exist validated clean")
	}
}

func TestValidateWithNoLivePolicyIsNotAnError(t *testing.T) {
	// No policy file means every fetch is denied. That is the intended secure
	// default, not a validation failure.
	isolateConfig(t)
	if err := runPolicyValidate(nil); err != nil {
		t.Errorf("an absent live policy was reported as invalid: %v", err)
	}
}

// --- check ----------------------------------------------------------------

func TestCheckStillFailsOnlyOnBypassableModes(t *testing.T) {
	isolateConfig(t)
	// This policy has an unreachable rule — a validate error — but no bypassable
	// mode restriction. check's exit status gates rollouts in the runbook, so it
	// must not start failing on findings it never covered.
	if err := runPolicyCheck([]string{"--file", writePolicy(t, shadowedPolicy)}); err != nil {
		t.Errorf("check failed on an ordering finding it does not own: %v", err)
	}

	bypassable := writePolicy(t, `{"schema":1,"rules":[
	  {"allow":true,"secrets":["bao:app/gitea#*"],"identities":["agent-*"],"modes":["exec","mount"]},
	  {"allow":true,"secrets":["bao:app/gitea#*"],"identities":["kevin"]}
	]}`)
	if err := runPolicyCheck([]string{"--file", bypassable}); err == nil {
		t.Error("check passed a policy whose mode restriction is bypassable")
	}
}

func TestCheckAcceptsAFileFlag(t *testing.T) {
	isolateConfig(t)
	if err := runPolicyCheck([]string{"--file", writePolicy(t, brokeredPolicy)}); err != nil {
		t.Errorf("check --file failed on a clean policy: %v", err)
	}
}

// --- what-if --------------------------------------------------------------

func TestWhatIfRequiresRefAndMode(t *testing.T) {
	isolateConfig(t)
	path := writePolicy(t, brokeredPolicy)
	cases := [][]string{
		{"--file", path, "--mode", "exec"},                                    // no --ref
		{"--file", path, "--ref", "bao:app/gitea#token"},                      // no --mode
		{"--file", path, "--ref", "x", "--mode", "teleport"},                  // unknown mode
		{"--file", path, "--ref", "x", "--mode", "exec", "--at", "yesterday"}, // unparseable time
	}
	for _, args := range cases {
		if err := runPolicyWhatIf(args); err == nil {
			t.Errorf("accepted bad arguments: %v", args)
		}
	}
}

func TestWhatIfNamesTheRuleThatDecides(t *testing.T) {
	p, err := policy.Parse([]byte(shadowedPolicy), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req := policy.Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: policy.ModeExec, Time: time.Now()}
	allow, idx := p.Explain(req)
	if allow {
		t.Fatal("the deny at rule 0 did not decide")
	}
	if idx != 0 {
		t.Fatalf("Explain returned rule %d, want 0", idx)
	}

	var b strings.Builder
	writeWhatIf(&b, p, req, allow, idx, req.Time)
	out := b.String()

	for _, want := range []string{
		"DENY",
		"Matched rule: 0",
		"agents get nothing under bao:app",
		// The first-match explanation is the point of the command: the rule the
		// operator expected to fire is below one that matched first.
		"before any rule below it",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("what-if output is missing %q:\n%s", want, out)
		}
	}
}

func TestWhatIfExplainsWhyANearMissDidNotFire(t *testing.T) {
	// The commonest real question is "why didn't my rule fire?", and "no rule
	// matches" does not answer it.
	p, err := policy.Parse([]byte(brokeredPolicy), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	at := time.Date(2026, 9, 8, 9, 30, 0, 0, time.Local) // a Tuesday, in hours
	req := policy.Request{Ref: "bao:app/gitea#token", Identity: "tea", Mode: policy.ModeGet, Time: at}

	allow, idx := p.Explain(req)
	if allow || idx != -1 {
		t.Fatalf("expected a default deny, got allow=%v rule=%d", allow, idx)
	}

	var b strings.Builder
	writeWhatIf(&b, p, req, allow, idx, at)
	out := b.String()
	if !strings.Contains(out, "Rules covering this ref that did not match") {
		t.Fatalf("no near-miss section:\n%s", out)
	}
	if !strings.Contains(out, "mode get is not in [exec mount]") {
		t.Errorf("the near-miss did not name the failing condition:\n%s", out)
	}
}

func TestWhatIfIsTimeAware(t *testing.T) {
	p, err := policy.Parse([]byte(brokeredPolicy), "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ref, id := "bao:app/gitea#token", "tea"

	inHours := time.Date(2026, 9, 8, 9, 30, 0, 0, time.Local) // Tuesday 09:30
	if allow, _ := p.Explain(policy.Request{Ref: ref, Identity: id, Mode: policy.ModeExec, Time: inHours}); !allow {
		t.Error("a request inside the rule's window was denied")
	}

	afterHours := time.Date(2026, 9, 8, 22, 0, 0, 0, time.Local) // Tuesday 22:00
	if allow, _ := p.Explain(policy.Request{Ref: ref, Identity: id, Mode: policy.ModeExec, Time: afterHours}); allow {
		t.Error("a request outside the rule's window was allowed")
	}

	weekend := time.Date(2026, 9, 6, 9, 30, 0, 0, time.Local) // Sunday 09:30
	if allow, _ := p.Explain(policy.Request{Ref: ref, Identity: id, Mode: policy.ModeExec, Time: weekend}); allow {
		t.Error("a weekend request was allowed by a Mon-Fri rule")
	}
}

func TestWhatIfNamesUnrestrictedModesOnlyForAnAllowRule(t *testing.T) {
	// A deny-rule with no modes refuses every mode, which is the safe direction.
	// Saying "including get" there would read as though it granted something.
	denyAll := policy.Rule{Allow: false, Secrets: []string{"bao:app/*"}}
	if got := indentRule(denyAll, "  "); strings.Contains(got, "including get") {
		t.Errorf("a deny-rule was described as permitting get:\n%s", got)
	}
	allowAll := policy.Rule{Allow: true, Secrets: []string{"bao:app/*"}}
	if got := indentRule(allowAll, "  "); !strings.Contains(got, "including get") {
		t.Errorf("an allow-rule with no modes did not warn about get:\n%s", got)
	}
}

func TestWhatIfWithNoPolicyFileDenies(t *testing.T) {
	isolateConfig(t)
	err := runPolicyWhatIf([]string{"--ref", "bao:app/x#token", "--mode", "exec"})
	if err == nil {
		t.Fatal("what-if against a host with no policy did not report a denial")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("want exit status 1, got %v", err)
	}
}

// --- dispatch -------------------------------------------------------------

func TestPolicyDispatchRejectsUnknownSubcommands(t *testing.T) {
	if err := runPolicy(nil); err == nil {
		t.Error("bare `policy` was accepted")
	}
	if err := runPolicy([]string{"delete-everything"}); err == nil {
		t.Error("an unknown policy subcommand was accepted")
	}
}
