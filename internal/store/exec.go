package store

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// runner executes an external CLI and returns its stdout. It exists as an
// interface so tests can substitute a fake without spawning real processes.
type runner interface {
	run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// execRunner runs the real binary via os/exec.
//
// The backend's stderr is captured rather than passed through to parzival's own
// stderr, and is surfaced only when the command fails. On the success path
// nothing is written to a stream at all: a verbose backend must not be able to
// interleave diagnostics — which can quote a reference, a path, or in the worst
// case secret material — into a terminal, a CI log, or an AI agent's transcript.
// See THREAT-MODEL.md §4b.
type execRunner struct{}

func (execRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Leaving Stderr nil makes Output capture it into ExitError.Stderr.
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if msg := strings.TrimSpace(string(ee.Stderr)); msg != "" {
				return nil, fmt.Errorf("%w: %s", err, msg)
			}
		}
		return nil, err
	}
	return out, nil
}
