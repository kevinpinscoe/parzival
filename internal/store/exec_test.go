package store

import (
	"context"
	"strings"
	"testing"
)

// These two exercise execRunner itself, which is the one place a real process
// must be spawned to test anything at all. They run /bin/sh, never a backend
// CLI, so the "unit tests do not spawn backends" rule still holds.

// The success path must be silent: a chatty backend must not be able to put
// anything on parzival's stderr, which in an agent session is the transcript.
func TestExecRunnerDiscardsStderrOnSuccess(t *testing.T) {
	out, err := execRunner{}.run(context.Background(), "sh", "-c", "echo noise >&2; printf value")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(out) != "value" {
		t.Errorf("stdout = %q, want %q", out, "value")
	}
	// Nothing to assert about parzival's own stderr beyond this: the runner no
	// longer holds a reference to it, so it cannot write there.
}

// On failure the diagnostics are the only clue the operator gets, so they must
// reach the error — just not the success path.
func TestExecRunnerSurfacesStderrOnFailure(t *testing.T) {
	_, err := execRunner{}.run(context.Background(), "sh", "-c", "echo 'permission denied to this path' >&2; exit 2")
	if err == nil {
		t.Fatal("run returned nil for a command that exited 2")
	}
	if !strings.Contains(err.Error(), "permission denied to this path") {
		t.Errorf("error should carry the backend's stderr, got: %v", err)
	}
}
