package broker

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/profile"
)

// --- minimalEnv ----------------------------------------------------------

func TestMinimalEnvContainsOnlyExpectedVars(t *testing.T) {
	env := minimalEnv("/run/parzival/op-1", profile.Inject{EnvDir: "XDG_CONFIG_HOME"}, "/run/parzival/op-1/tea/config.yml", "/run/parzival/op-1")

	want := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/run/parzival/op-1",
		"LC_ALL=C",
		"XDG_CONFIG_HOME=/run/parzival/op-1",
	}
	if len(env) != len(want) {
		t.Fatalf("minimalEnv: got %d vars %v, want %d vars %v", len(env), env, len(want), want)
	}
	for _, w := range want {
		if !slices.Contains(env, w) {
			t.Errorf("minimalEnv: missing %q, got %v", w, env)
		}
	}
}

func TestMinimalEnvOmitsUnsetInjectFields(t *testing.T) {
	env := minimalEnv("/run/parzival/op-1", profile.Inject{}, "", "")
	if len(env) != 3 {
		t.Errorf("minimalEnv: with no Inject fields set, want exactly PATH/HOME/LC_ALL, got %v", env)
	}
}

// --- runConsumer -----------------------------------------------------------

func minimalTestEnv(t *testing.T) []string {
	t.Helper()
	return minimalEnv(t.TempDir(), profile.Inject{}, "", "")
}

func TestRunConsumerHappyPath(t *testing.T) {
	res := runConsumer(context.Background(), []string{fakeTeaPath, "repos", "list", "--owner", "acme", "--output", "json"}, minimalTestEnv(t), MaxResponseBytes)
	if res.exitErr != nil {
		t.Fatalf("runConsumer: unexpected exit error: %v (stderrLen=%d)", res.exitErr, res.stderrLen)
	}
	if res.truncated || res.timedOut {
		t.Errorf("runConsumer: got truncated=%v timedOut=%v, want both false", res.truncated, res.timedOut)
	}
	var repos []repoSummary
	if err := json.Unmarshal(res.stdout, &repos); err != nil {
		t.Fatalf("runConsumer: stdout did not decode: %v (stdout=%q)", err, res.stdout)
	}
	if len(repos) == 0 || repos[0].Owner != "acme" {
		t.Errorf("runConsumer: got %+v", repos)
	}
}

func TestRunConsumerCapturesTruncatedOutput(t *testing.T) {
	const bound = 1024
	res := runConsumer(context.Background(), []string{fakeTeaPath, "repos", "list", "--owner", "huge", "--output", "json"}, minimalTestEnv(t), bound)
	if res.exitErr != nil {
		t.Fatalf("runConsumer: unexpected exit error: %v", res.exitErr)
	}
	if !res.truncated {
		t.Error("runConsumer: expected truncated=true for output exceeding the bound")
	}
	if len(res.stdout) != bound {
		t.Errorf("runConsumer: captured %d bytes, want exactly the %d-byte bound", len(res.stdout), bound)
	}
}

func TestRunConsumerTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res := runConsumer(ctx, []string{fakeTeaPath, "repos", "list", "--owner", "slow", "--output", "json"}, minimalTestEnv(t), MaxResponseBytes)
	if !res.timedOut {
		t.Error("runConsumer: expected timedOut=true for an operation exceeding its deadline")
	}
	if res.exitErr == nil {
		t.Error("runConsumer: expected a non-nil exit error for a killed process")
	}
}

func TestRunConsumerNonzeroExitReportsStderrLengthNotContent(t *testing.T) {
	res := runConsumer(context.Background(), []string{fakeTeaPath, "repos", "list", "--owner", "failing", "--output", "json"}, minimalTestEnv(t), MaxResponseBytes)
	if res.exitErr == nil {
		t.Fatal("runConsumer: expected a non-nil exit error for a nonzero exit")
	}
	if res.stderrLen == 0 {
		t.Error("runConsumer: expected stderrLen > 0 -- the fixture writes to stderr on this path")
	}
	// launchResult structurally has no field carrying raw stderr bytes -- see
	// its type definition in launcher.go. stderrLen is the fact this package
	// is permitted to know; the content itself is never captured into any
	// field this package's other code could later log or return.
}

func TestRunConsumerChildEnvironmentIsExactlyMinimal(t *testing.T) {
	env := minimalTestEnv(t)
	res := runConsumer(context.Background(), []string{fakeTeaPath, "repos", "list", "--owner", "dump-env", "--output", "json"}, env, MaxResponseBytes)
	if res.exitErr != nil {
		t.Fatalf("runConsumer: unexpected exit error: %v", res.exitErr)
	}
	var gotEnv []string
	if err := json.Unmarshal(res.stdout, &gotEnv); err != nil {
		t.Fatalf("runConsumer: dump-env output did not decode: %v", err)
	}
	if len(gotEnv) != len(env) {
		t.Fatalf("runConsumer: child saw %d env vars %v, want exactly the %d constructed vars %v", len(gotEnv), gotEnv, len(env), env)
	}
	for _, w := range env {
		if !slices.Contains(gotEnv, w) {
			t.Errorf("runConsumer: child environment missing %q, got %v", w, gotEnv)
		}
	}
	// And nothing that looks like it leaked from the broker's own ambient
	// process environment (this test process's own PATH, USER, etc. beyond
	// what minimalEnv itself constructed).
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "PARZIVAL_") || strings.HasPrefix(kv, "BAO_") {
			t.Errorf("runConsumer: child environment must never contain a PARZIVAL_*/BAO_* variable, got %q", kv)
		}
	}
}
