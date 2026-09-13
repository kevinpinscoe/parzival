//go:build unix

package consumer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Regression coverage: root (uid 0) must be the trusted owner in
// production, never the broker's own runtime identity. Because the test
// process cannot chown a fixture to a uid it does not own, these tests model
// ownership with a fake stat rather than a real chown — see withOwnerUID.

// fakeOwnerFileInfo wraps a real os.FileInfo, overriding the uid its Sys()
// reports and clearing any group/other write bit its Mode() reports. The uid
// override is the point: it models an owner (root, or a synthetic
// service-account uid) the test process cannot actually create a fixture as.
// The mode override exists only so a walk that reaches real, uncontrolled
// ancestors (VerifyExecutable always walks to the real filesystem root) is
// not at the mercy of this host's actual directory permissions — every other
// mode bit, including the type bits that distinguish a file from a
// directory, is left exactly as the real fixture reports it.
type fakeOwnerFileInfo struct {
	os.FileInfo
	uid uint32
}

func (f fakeOwnerFileInfo) Sys() any {
	real := f.FileInfo.Sys().(*syscall.Stat_t)
	cp := *real
	cp.Uid = f.uid
	return &cp
}

func (f fakeOwnerFileInfo) Mode() os.FileMode {
	return f.FileInfo.Mode() &^ 0o022
}

// withOwnerUID substitutes the package's lstat seam for the duration of the
// test so every path checkOwnership examines reports uid as its owner (mode
// safety forced the same way — see fakeOwnerFileInfo), regardless of who
// actually created the underlying fixture or what the real host's ambient
// directories are owned/moded as. Restored automatically at test end. This
// is an unexported, in-package test seam only — nothing outside this package
// can reach it, so it is not a production bypass; production always
// resolves lstat to os.Lstat.
func withOwnerUID(t *testing.T, uid uint32) {
	t.Helper()
	orig := lstat
	lstat = func(name string) (os.FileInfo, error) {
		fi, err := orig(name)
		if err != nil {
			return nil, err
		}
		return fakeOwnerFileInfo{fi, uid}, nil
	}
	t.Cleanup(func() { lstat = orig })
}

// TestVerifyTrustRootAcceptsARootOwnedTargetWithRootTrustedOwner is
// requirement 1: a root-owned trust root, checked with TrustedOwnerRootUID,
// succeeds when modes and ancestors are otherwise safe. This is the exact
// production shape a correct deployment relies on.
func TestVerifyTrustRootAcceptsARootOwnedTargetWithRootTrustedOwner(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o644)
	withOwnerUID(t, 0)
	if err := verifyTrustRootUnder(file, TrustedOwnerRootUID, stopAt); err != nil {
		t.Fatalf("a root-owned tree with TrustedOwnerUID=0 should pass: %v", err)
	}
}

// TestVerifyTrustRootRejectsARootOwnedTargetWithNonRootTrustedOwner is
// requirement 2: supplying a non-root trusted owner still fails a
// root-owned target. The risk this guards against is entirely in which
// *value* production wires into trustedOwnerUID, never in this function's
// willingness to reject a mismatch.
func TestVerifyTrustRootRejectsARootOwnedTargetWithNonRootTrustedOwner(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o644)
	withOwnerUID(t, 0)
	const nonRootTrustedOwner = 1000
	err := verifyTrustRootUnder(file, nonRootTrustedOwner, stopAt)
	assertTrustRootFailure(t, err, file, "expected uid 1000")
}

// TestVerifyTrustRootRejectsABrokerOwnedTargetWithRootTrustedOwner is
// requirement 3: a target owned by the broker's own (non-root) identity is
// not trusted merely because *some* uid matches it — with the production
// trusted owner (root), a broker-owned file must still fail. The broker's
// own uid is not an acceptable stand-in for root, in either direction.
func TestVerifyTrustRootRejectsABrokerOwnedTargetWithRootTrustedOwner(t *testing.T) {
	stopAt, file := tree(t, 0o755, 0o755, 0o644)
	const brokerRuntimeUID = 977 // a stand-in for parzival-broker's own service-account uid
	withOwnerUID(t, brokerRuntimeUID)
	err := verifyTrustRootUnder(file, TrustedOwnerRootUID, stopAt)
	assertTrustRootFailure(t, err, file, "expected uid 0")
}

// TestVerifyExecutableAcceptsARootOwnedExecutableWithRootTrustedOwner is
// requirement 4: a correctly root-owned named executable (e.g. the real
// /usr/bin/tea a consumer definition names) verifies successfully once
// production supplies TrustedOwnerRootUID. VerifyExecutable always walks to
// the real filesystem root (it calls the public VerifyTrustRoot, which has
// no test-only stopAt parameter), so withOwnerUID's mode override is what
// keeps this test independent of this host's real directory permissions.
func TestVerifyExecutableAcceptsARootOwnedExecutableWithRootTrustedOwner(t *testing.T) {
	stopAt := t.TempDir()
	if err := os.Chmod(stopAt, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(stopAt, "tea")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	withOwnerUID(t, 0)
	d := &Definition{Name: "tea", Executable: exe, Profile: "p"}
	if err := d.VerifyExecutable(TrustedOwnerRootUID); err != nil {
		t.Fatalf("a root-owned, safely-moded executable should verify with TrustedOwnerUID=0: %v", err)
	}
}
