//go:build unix

package consumer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uid returns the uid the tests run as. The trust-root check is about ownership
// rather than about being root, so the whole property can be exercised as an
// ordinary user with that uid standing in for the administrator's.
func uid(t *testing.T) uint32 {
	t.Helper()
	return uint32(os.Getuid())
}

// tree builds <tmp>/root/consumers/tea.json with the given modes and returns the
// temporary directory (the stopAt for the walk) and the definition's path.
func tree(t *testing.T, rootMode, dirMode, fileMode os.FileMode) (stopAt, file string) {
	t.Helper()
	stopAt = t.TempDir()
	// t.TempDir() honours the process umask, which on this host leaves the
	// directory group-writable. That is a real failure by the rule under test,
	// so normalise the walk's top rather than letting an unrelated umask decide
	// whether the positive case passes.
	if err := os.Chmod(stopAt, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(stopAt, "root")
	dir := filepath.Join(root, "consumers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "tea.json")
	if err := os.WriteFile(file, []byte(teaDefinition), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set modes outermost-first so a later chmod is not blocked by an earlier one.
	for path, mode := range map[string]os.FileMode{root: rootMode, dir: dirMode, file: fileMode} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	return stopAt, file
}

func TestVerifyTrustRootAcceptsAWellOwnedTree(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o644)
	if err := verifyTrustRootUnder(file, uid(t), stopAt); err != nil {
		t.Fatalf("a root-owned, non-group-writable tree should pass: %v", err)
	}
}

func TestVerifyTrustRootRejectsAWritableFile(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o666)
	assertTrustRootFailure(t, verifyTrustRootUnder(file, uid(t), stopAt), file, "writable by group or other")
}

func TestVerifyTrustRootRejectsAGroupWritableFile(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o664)
	assertTrustRootFailure(t, verifyTrustRootUnder(file, uid(t), stopAt), file, "writable by group or other")
}

// TestVerifyTrustRootRejectsAWritableParent is the reason the function walks
// ancestors at all. The definition here is 0600 and owned correctly; the client
// still cannot edit it — it can rename it away and put its own in its place,
// which is the same outcome with one extra step.
func TestVerifyTrustRootRejectsAWritableParent(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o777, 0o600)
	dir := filepath.Dir(file)
	assertTrustRootFailure(t, verifyTrustRootUnder(file, uid(t), stopAt), dir, "writable by group or other")
}

func TestVerifyTrustRootRejectsAWritableGrandparent(t *testing.T) {
	stopAt, file := tree(t, 0o777, 0o755, 0o600)
	root := filepath.Dir(filepath.Dir(file))
	assertTrustRootFailure(t, verifyTrustRootUnder(file, uid(t), stopAt), root, "writable by group or other")
}

func TestVerifyTrustRootRejectsTheWrongOwner(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o600)
	// Nothing on the host is owned by this uid, so the target fails the
	// ownership half of the check rather than the mode half.
	const nobodyish = 65530
	err := verifyTrustRootUnder(file, nobodyish, stopAt)
	assertTrustRootFailure(t, err, file, "expected uid 65530")
}

// TestVerifyTrustRootRejectsTmp is the everyday mistake the check exists to
// catch: /tmp is mode 1777, so nothing beneath it is a trust root however the
// file itself is owned. The sticky bit does not change that answer.
func TestVerifyTrustRootRejectsTmp(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tea.json")
	if err := os.WriteFile(file, []byte(teaDefinition), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTrustRoot(file, uid(t)); err == nil {
		t.Fatal("a definition under /tmp was accepted as a trust root")
	}
}

func TestVerifyTrustRootReportsAMissingPath(t *testing.T) {
	stopAt := t.TempDir()
	err := verifyTrustRootUnder(filepath.Join(stopAt, "absent.json"), uid(t), stopAt)
	if err == nil {
		t.Fatal("a missing path was accepted")
	}
	var tre *TrustRootError
	if !errors.As(err, &tre) {
		t.Fatalf("expected a *TrustRootError, got %T", err)
	}
}

func TestVerifyExecutableChecksTheBinary(t *testing.T) {
	// A definition can be flawlessly owned and still name an executable in a
	// directory the client controls — the substitution the allowlist exists to
	// prevent, arrived at from the other end.
	stopAt := t.TempDir()
	exe := filepath.Join(stopAt, "tea")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	d := &Definition{Name: "tea", Executable: exe, Profile: "p"}
	if err := d.VerifyExecutable(uid(t)); err == nil {
		t.Fatal("a world-writable executable was accepted")
	}
}

func assertTrustRootFailure(t *testing.T, err error, wantFailed, wantReason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a failure naming %s", wantFailed)
	}
	var tre *TrustRootError
	if !errors.As(err, &tre) {
		t.Fatalf("expected a *TrustRootError, got %T: %v", err, err)
	}
	// The error names the path that actually failed, which for a file is
	// usually a directory above it — the one thing the operator needs to know.
	if resolved, rerr := filepath.EvalSymlinks(wantFailed); rerr == nil {
		wantFailed = resolved
	}
	if tre.Failed != wantFailed {
		t.Errorf("failed path = %s, want %s", tre.Failed, wantFailed)
	}
	if !strings.Contains(tre.Reason, wantReason) {
		t.Errorf("reason = %q, want it to contain %q", tre.Reason, wantReason)
	}
}
