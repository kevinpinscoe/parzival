package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

// liveConfig writes a policy into an isolated config dir and points
// PARZIVAL_CONFIG_HOME at it, so `grant` and `apply` operate on a policy the
// test owns. No test in this file may touch the developer's real policy.
func liveConfig(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
	path = filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write live policy: %v", err)
	}
	return dir, path
}

func loadLive(t *testing.T, path string) *policy.Policy {
	t.Helper()
	p, exists, err := policy.LoadFile(path)
	if err != nil || !exists {
		t.Fatalf("live policy did not load: exists=%v err=%v", exists, err)
	}
	return p
}

func backups(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, "policy.json.bak.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return got
}

func candidates(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, "parzival-policy-candidate-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return got
}

const brokeredLive = `{"schema":1,"rules":[
  {"allow":false,"description":"prod is never brokered here","secrets":["bao:prod/*"]},
  {"allow":true,"description":"gitea for agents","secrets":["bao:app/gitea#*"],"identities":["ai","agent-*"],"modes":["exec","mount"]}
]}`

// --- the grant/apply boundary --------------------------------------------

func TestGrantWithoutApplyLeavesTheLivePolicyAlone(t *testing.T) {
	dir, path := liveConfig(t, brokeredLive)
	before := loadLive(t, path)

	err := runPolicyGrant([]string{
		"--tool", "codex", "--goal", "file issues",
		"--secret", "bao:app/YouTrack-Codex#token", "--identity", "codex",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	if got := loadLive(t, path); len(got.Rules) != len(before.Rules) {
		t.Errorf("live policy grew to %d rules without --apply", len(got.Rules))
	}
	if b := backups(t, dir); len(b) != 0 {
		t.Errorf("a backup was taken without --apply: %v", b)
	}
	// The candidate is deliberately left behind: it is what `policy apply` takes.
	if c := candidates(t, dir); len(c) != 1 {
		t.Errorf("expected exactly one candidate to review, got %v", c)
	}
}

func TestGrantWithApplyInstallsBacksUpAndVerifies(t *testing.T) {
	dir, path := liveConfig(t, brokeredLive)

	err := runPolicyGrant([]string{
		"--tool", "codex", "--goal", "file issues",
		"--secret", "bao:app/YouTrack-Codex#token", "--identity", "codex",
		"--apply", "--yes",
	})
	if err != nil {
		t.Fatalf("grant --apply: %v", err)
	}

	got := loadLive(t, path)
	if len(got.Rules) != 3 {
		t.Fatalf("installed policy has %d rules, want 3", len(got.Rules))
	}

	// The rule is a narrow exec/mount grant, and get is not among its modes.
	var found bool
	for _, r := range got.Rules {
		if r.Description == "codex: file issues" {
			found = true
			if len(r.Modes) != 2 {
				t.Errorf("installed modes = %v, want exec and mount", r.Modes)
			}
			for _, m := range r.Modes {
				if m == policy.ModeGet {
					t.Error("get was granted by a request that never named it")
				}
			}
		}
	}
	if !found {
		t.Error("the granted rule is not in the installed policy")
	}

	// It fires, and only for the identity and modes asked for.
	if allow, _ := got.Explain(policy.Request{Ref: "bao:app/YouTrack-Codex#token", Identity: "codex", Mode: policy.ModeExec}); !allow {
		t.Error("the installed rule does not fire for the granted request")
	}
	if allow, _ := got.Explain(policy.Request{Ref: "bao:app/YouTrack-Codex#token", Identity: "codex", Mode: policy.ModeGet}); allow {
		t.Error("get was allowed on the granted ref")
	}
	if allow, _ := got.Explain(policy.Request{Ref: "bao:app/YouTrack-Codex#token", Identity: "someone-else", Mode: policy.ModeExec}); allow {
		t.Error("an identity the rule does not name was granted access")
	}

	// Permissions and backup.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("installed policy mode = %04o, want 0600", perm)
	}
	b := backups(t, dir)
	if len(b) != 1 {
		t.Fatalf("expected one backup, got %v", b)
	}
	kept, _, err := policy.LoadFile(b[0])
	if err != nil {
		t.Fatalf("backup does not load: %v", err)
	}
	if len(kept.Rules) != 2 {
		t.Errorf("backup holds %d rules, want the pre-change 2", len(kept.Rules))
	}
	// The candidate is cleaned up once installed: a second file that looks
	// authoritative and is not would be a trap.
	if c := candidates(t, dir); len(c) != 0 {
		t.Errorf("candidate left behind after a successful install: %v", c)
	}
}

func TestGrantWithoutYesRefusesOnAnUnanswerablePrompt(t *testing.T) {
	// --apply says an install is intended; it does not answer the prompt. With
	// stdin at EOF the answer is no, and nothing is installed.
	dir, path := liveConfig(t, brokeredLive)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	stdin := os.Stdin
	os.Stdin = devnull
	defer func() { os.Stdin = stdin }()

	err = runPolicyGrant([]string{
		"--secret", "bao:app/x#token", "--identity", "ci", "--apply",
	})
	if err == nil {
		t.Fatal("an unanswered confirmation installed the policy")
	}
	if len(loadLive(t, path).Rules) != 2 {
		t.Error("the live policy changed despite the cancellation")
	}
	if b := backups(t, dir); len(b) != 0 {
		t.Errorf("a backup was taken for a cancelled install: %v", b)
	}
}

// --- refusals -------------------------------------------------------------

func TestGrantRefusesWhenItWouldBroadenBeyondTheRequest(t *testing.T) {
	// The existing rule restricts tea to brokered delivery on one ref. A raw-get
	// grant over the whole prefix defeats that restriction, because identity
	// labels are self-asserted.
	dir, path := liveConfig(t, `{"schema":1,"rules":[
	  {"allow":true,"secrets":["bao:app/gitea#token"],"identities":["tea"],"modes":["exec","mount"]}
	]}`)

	err := runPolicyGrant([]string{
		"--secret", "bao:app/*", "--identity", "auditor", "--modes", "get",
		"--apply", "--yes",
	})
	if err == nil {
		t.Fatal("a grant defeating an existing mode restriction was installed")
	}
	if len(loadLive(t, path).Rules) != 1 {
		t.Error("the live policy changed despite the refusal")
	}
	if b := backups(t, dir); len(b) != 0 {
		t.Errorf("a backup was taken for a refused install: %v", b)
	}
}

func TestGrantRefusesAnAmbiguousPlacement(t *testing.T) {
	// A narrow deny and a broader allow on the same ref: neither contains the
	// other, and both orders are legitimate policies. Guessing is exactly what
	// must not happen.
	_, path := liveConfig(t, `{"schema":1,"rules":[
	  {"allow":false,"secrets":["bao:app/gitea#token"],"identities":["agent-x"]}
	]}`)

	err := runPolicyGrant([]string{
		"--secret", "bao:app/gitea#token", "--identity", "agent-*", "--apply", "--yes",
	})
	if err == nil {
		t.Fatal("an ambiguous placement was resolved instead of refused")
	}
	// The refusal names both resolutions, so the fix is one flag.
	for _, want := range []string{"--at 1", "--at 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not offer %q: %v", want, err)
		}
	}
	if len(loadLive(t, path).Rules) != 1 {
		t.Error("the live policy changed despite the refusal")
	}
}

func TestGrantAtOverrideWritesTheExceptionBeforeGeneralIdiom(t *testing.T) {
	// The resolution the refusal above suggests must actually work: a narrow
	// deny kept above a broader allow is an ordinary, correct policy.
	_, path := liveConfig(t, `{"schema":1,"rules":[
	  {"allow":false,"secrets":["bao:app/gitea#token"],"identities":["agent-x"]}
	]}`)

	err := runPolicyGrant([]string{
		"--secret", "bao:app/gitea#token", "--identity", "agent-*",
		"--at", "1", "--apply", "--yes",
	})
	if err != nil {
		t.Fatalf("the suggested placement was refused: %v", err)
	}

	got := loadLive(t, path)
	if allow, _ := got.Explain(policy.Request{Ref: "bao:app/gitea#token", Identity: "agent-x", Mode: policy.ModeExec}); allow {
		t.Error("the pre-existing exception stopped working")
	}
	if allow, _ := got.Explain(policy.Request{Ref: "bao:app/gitea#token", Identity: "agent-y", Mode: policy.ModeExec}); !allow {
		t.Error("the new general rule does not fire")
	}
}

func TestGrantRejectsBadInputBeforeTouchingAnything(t *testing.T) {
	_, path := liveConfig(t, brokeredLive)
	cases := map[string][]string{
		"no secret":     {"--identity", "ci", "--apply", "--yes"},
		"no identity":   {"--secret", "bao:app/x#t", "--apply", "--yes"},
		"unknown mode":  {"--secret", "bao:app/x#t", "--identity", "ci", "--modes", "exce", "--apply", "--yes"},
		"bad hours":     {"--secret", "bao:app/x#t", "--identity", "ci", "--hours", "8am-6pm", "--apply", "--yes"},
		"bad weekday":   {"--secret", "bao:app/x#t", "--identity", "ci", "--weekdays", "Funday", "--apply", "--yes"},
		"bad monthday":  {"--secret", "bao:app/x#t", "--identity", "ci", "--monthdays", "32", "--apply", "--yes"},
		"monthday text": {"--secret", "bao:app/x#t", "--identity", "ci", "--monthdays", "first", "--apply", "--yes"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := runPolicyGrant(args); err == nil {
				t.Fatal("accepted")
			}
			if len(loadLive(t, path).Rules) != 2 {
				t.Error("the live policy changed on a rejected request")
			}
		})
	}
}

// --- apply ----------------------------------------------------------------

func TestApplyInstallsAReviewedCandidate(t *testing.T) {
	dir, path := liveConfig(t, brokeredLive)

	// Produce a candidate the way an operator would: a dry-run grant.
	if err := runPolicyGrant([]string{
		"--secret", "bao:app/new#token", "--identity", "ci",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	cands := candidates(t, dir)
	if len(cands) != 1 {
		t.Fatalf("expected one candidate, got %v", cands)
	}

	if err := runPolicyApply([]string{"--apply", "--yes", cands[0]}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := loadLive(t, path); len(got.Rules) != 3 {
		t.Errorf("installed policy has %d rules, want 3", len(got.Rules))
	}
	if len(backups(t, dir)) != 1 {
		t.Error("apply did not take a backup")
	}
}

func TestApplyRefusesACandidateThatDoesNotLoad(t *testing.T) {
	_, path := liveConfig(t, brokeredLive)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":1,"rules":[{"allow":true,"modez":["exec"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyApply([]string{"--apply", "--yes", bad}); err == nil {
		t.Fatal("a candidate with an unknown field was installed")
	}
	if len(loadLive(t, path).Rules) != 2 {
		t.Error("the live policy changed despite the refusal")
	}
}

func TestApplyRefusesACandidateWithAnUnreachableRule(t *testing.T) {
	dir, path := liveConfig(t, brokeredLive)
	bad := filepath.Join(t.TempDir(), "bad.json")
	body := `{"schema":1,"rules":[
	  {"allow":false,"secrets":["bao:app/*"]},
	  {"allow":true,"secrets":["bao:app/gitea#token"],"identities":["tea"],"modes":["exec"]}
	]}`
	if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPolicyApply([]string{"--apply", "--yes", bad}); err == nil {
		t.Fatal("a candidate with an unreachable rule was installed")
	}
	if len(loadLive(t, path).Rules) != 2 {
		t.Error("the live policy changed despite the refusal")
	}
	if b := backups(t, dir); len(b) != 0 {
		t.Errorf("a backup was taken for a refused apply: %v", b)
	}
}

func TestApplyRequiresACandidatePath(t *testing.T) {
	liveConfig(t, brokeredLive)
	if err := runPolicyApply([]string{"--apply"}); err == nil {
		t.Error("apply with no candidate was accepted")
	}
	if err := runPolicyApply([]string{"--apply", filepath.Join(t.TempDir(), "absent.json")}); err == nil {
		t.Error("apply with a missing candidate was accepted")
	}
}

// --- first grant on a host with no policy --------------------------------

func TestGrantCreatesTheFirstPolicy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
	path := filepath.Join(dir, "policy.json")

	if err := runPolicyGrant([]string{
		"--secret", "bao:app/x#token", "--identity", "ci", "--apply", "--yes",
	}); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	got := loadLive(t, path)
	if len(got.Rules) != 1 {
		t.Fatalf("created policy has %d rules, want 1", len(got.Rules))
	}
	if got.Schema != policy.SchemaVersion {
		t.Errorf("created policy declares schema %d, want %d", got.Schema, policy.SchemaVersion)
	}
	// Nothing existed, so there is nothing to have backed up.
	if b := backups(t, dir); len(b) != 0 {
		t.Errorf("a backup was written for a policy that did not exist: %v", b)
	}
}

// --- interactive gathering ------------------------------------------------

func TestGatherInteractivelyReadsAnswersAndKeepsDefaults(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"codex",                        // tool
		"file YouTrack issues",         // goal
		"bao:app/YouTrack-Codex#token", // secrets
		"codex",                        // identities
		"",                             // modes — accept the default
		"",                             // weekdays
		"",                             // month days
		"",                             // hours
	}, "\n") + "\n")

	got, err := gatherInteractively(in, &strings.Builder{}, policy.GrantRequest{})
	if err != nil {
		t.Fatalf("gatherInteractively: %v", err)
	}
	if got.Tool != "codex" || got.Goal != "file YouTrack issues" {
		t.Errorf("tool/goal = %q/%q", got.Tool, got.Goal)
	}
	if len(got.Secrets) != 1 || got.Secrets[0] != "bao:app/YouTrack-Codex#token" {
		t.Errorf("secrets = %v", got.Secrets)
	}
	if len(got.Identities) != 1 || got.Identities[0] != "codex" {
		t.Errorf("identities = %v", got.Identities)
	}
	// An empty answer takes the offered default, which is brokered delivery —
	// pressing Enter must never be how raw get gets granted.
	if got.GrantsRawGet() {
		t.Errorf("accepting the default mode granted get: %v", got.Modes)
	}
	if got.Hours != "" || len(got.Weekdays) != 0 || len(got.Monthdays) != 0 {
		t.Errorf("blank time limits were not left empty: %+v", got)
	}
}

func TestConfirmDefaultsToNo(t *testing.T) {
	for _, answer := range []string{"", "\n", "n\n", "no\n", "maybe\n", "Y E S\n"} {
		ok, err := confirm(strings.NewReader(answer), &strings.Builder{}, "install?")
		if err != nil {
			t.Fatalf("confirm(%q): %v", answer, err)
		}
		if ok {
			t.Errorf("confirm(%q) said yes", answer)
		}
	}
	for _, answer := range []string{"y\n", "Y\n", "yes\n", " YES \n"} {
		ok, err := confirm(strings.NewReader(answer), &strings.Builder{}, "install?")
		if err != nil {
			t.Fatalf("confirm(%q): %v", answer, err)
		}
		if !ok {
			t.Errorf("confirm(%q) said no", answer)
		}
	}
}

// --- flag parsing ---------------------------------------------------------

func TestRepeatedFlagsCollectRatherThanOverwrite(t *testing.T) {
	dir, path := liveConfig(t, `{"schema":1,"rules":[]}`)
	if err := runPolicyGrant([]string{
		"--secret", "bao:app/a#token", "--secret", "bao:app/b#token",
		"--identity", "ci", "--identity", "deploy",
		"--apply", "--yes",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	got := loadLive(t, path)
	r := got.Rules[0]
	if len(r.Secrets) != 2 || len(r.Identities) != 2 {
		t.Fatalf("repeated flags collapsed: secrets=%v identities=%v", r.Secrets, r.Identities)
	}
	_ = dir
}

func TestSplitCommasIgnoresBlanksAndSpaces(t *testing.T) {
	got := splitCommas(" exec , , mount ")
	if len(got) != 2 || got[0] != "exec" || got[1] != "mount" {
		t.Errorf("splitCommas = %v", got)
	}
	if splitCommas("") != nil || splitCommas("  ") != nil {
		t.Error("an empty list should be nil, so the rule's default applies")
	}
}
