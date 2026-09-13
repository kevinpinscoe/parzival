package broker

import (
	"context"
	"os/exec"

	"github.com/kevinpinscoe/parzival/internal/profile"
)

// maxStderrCapture bounds how much of a consumer's stderr the broker ever
// reads into memory, purely to produce a length/emptiness fact for the
// diagnostic log — never to persist the content anywhere. A real CLI's
// stderr routinely echoes back what it was given, and what it was given is
// the credential; see SERVICE-PROTOCOL.md, "What a response may never
// contain".
const maxStderrCapture = 64 * 1024

// launchResult is what a consumer invocation produced, reduced to exactly
// what the rest of the broker may act on: bounded, still-raw stdout bytes
// (response_tea.go's canonicalizer is what turns them into something safe to
// return), whether stdout was truncated, whether the operation timed out,
// the process exit error if any, and stderr metadata — a FACT about stderr
// (its length) rather than its content.
type launchResult struct {
	stdout    []byte
	truncated bool
	stderrLen int
	timedOut  bool
	exitErr   error
}

// minimalEnv builds a child process's environment from nothing — never
// os.Environ() — per SERVICE-PROTOCOL.md step 9: "never the client's
// environment, PATH, loader variables, proxy settings, config-home paths, or
// inherited descriptors." homeDir is the operation's own ephemeral runtime
// directory, pinned as HOME so an accidental $HOME-based lookup by the
// consumer lands somewhere Cleanup wipes rather than the broker's real home.
// LC_ALL is pinned for deterministic, locale-independent output, since that
// output gets parsed as JSON. inj/credPath/credDirPath are exactly what the
// consumer needs to find its rendered credential — the one thing a profile
// is allowed to inject; broker.go's startup validation already refused any
// profile whose Inject.Env/Inject.EnvDir claims a reserved name, so nothing
// here can collide with PATH, HOME, or the other reserved variables.
func minimalEnv(homeDir string, inj profile.Inject, credPath, credDirPath string) []string {
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + homeDir,
		"LC_ALL=C",
	}
	if inj.Env != "" {
		env = append(env, inj.Env+"="+credPath)
	}
	if inj.EnvDir != "" {
		env = append(env, inj.EnvDir+"="+credDirPath)
	}
	return env
}

// runConsumer executes argv[0] with argv[1:] and env, never through a shell
// (os/exec's fork+exec, not sh -c), capturing stdout up to maxStdout bytes
// and stderr up to maxStderrCapture bytes. ctx carries the operation's
// deadline; exec.CommandContext kills the process if it is exceeded.
func runConsumer(ctx context.Context, argv []string, env []string, maxStdout int) *launchResult {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env

	stdout := &boundedBuffer{max: maxStdout}
	stderr := &boundedBuffer{max: maxStderrCapture}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	res := &launchResult{
		stdout:    stdout.data,
		truncated: stdout.truncated,
		stderrLen: stderr.total,
		exitErr:   err,
		timedOut:  ctx.Err() == context.DeadlineExceeded,
	}
	return res
}

// boundedBuffer is an io.Writer that retains at most max bytes and tracks
// whether more were discarded, without ever growing past max. Write never
// errors — exceeding the bound does not interrupt the process, which either
// runs to completion (and is then judged too large) or is killed by the
// context deadline like any other operation.
type boundedBuffer struct {
	max       int
	data      []byte
	total     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.total += len(p)
	room := b.max - len(b.data)
	if room <= 0 {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}
	n := len(p)
	if n > room {
		n = room
		b.truncated = true
	}
	b.data = append(b.data, p[:n]...)
	return len(p), nil
}
