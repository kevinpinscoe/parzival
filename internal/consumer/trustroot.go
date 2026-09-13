//go:build unix

package consumer

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// TrustedOwnerRootUID is the trusted-owner uid every production trust-root
// check must be verified against: root. It is a constant, not a value
// derived from any runtime identity (the broker's own uid included) and not
// configurable by environment, profile, consumer definition, or any other
// user-controlled input. cmd/parzival-broker is the only production caller
// and wires this constant directly; only this package's
// own tests supply a different value, to model an owner (root) a test
// process cannot actually create a fixture as.
const TrustedOwnerRootUID uint32 = 0

// lstat is checkOwnership's filesystem stat call. It is a package variable
// rather than a direct os.Lstat call so this package's own tests can
// substitute a fake that reports a chosen uid — modeling ownership by root
// (uid 0) without requiring the test process to run as root or to chown a
// fixture, neither of which it has the privilege to do. It is unexported:
// nothing outside this package can reach it, so this is a test seam, not a
// production bypass — production always resolves to os.Lstat.
var lstat = os.Lstat

// TrustRootError reports a path that fails the trust-root check, naming the
// path that actually failed rather than the one that was asked about — for a
// file the failure is usually a directory several levels above it.
type TrustRootError struct {
	Asked  string // the path VerifyTrustRoot was called with
	Failed string // the path that failed: Asked itself, or an ancestor directory
	Reason string
}

func (e *TrustRootError) Error() string {
	if e.Failed == e.Asked {
		return fmt.Sprintf("trust root %s: %s", e.Asked, e.Reason)
	}
	return fmt.Sprintf("trust root %s: %s: %s", e.Asked, e.Failed, e.Reason)
}

// VerifyTrustRoot reports whether path is safe to treat as administrator-owned
// configuration: owned by trustedOwnerUID, not writable by group or other, and
// reached only through directories with the same property. Every production
// caller passes TrustedOwnerRootUID; a value derived from the verifying
// process's own runtime identity would defeat this check entirely.
//
// The ancestor walk is the point of the function. A 0600 root-owned consumer
// definition inside a directory the client can write is not protected at all —
// the client cannot edit the file, but it can rename it away and put its own
// there, which is the same thing with an extra step. Checking the file alone
// gives a confident answer to the wrong question.
//
// This does not make the check sufficient. A definition can be perfectly owned
// and still name an executable the client can replace; VerifyExecutable covers
// that, and neither covers a client that is root.
func VerifyTrustRoot(path string, trustedOwnerUID uint32) error {
	return verifyTrustRootUnder(path, trustedOwnerUID, string(filepath.Separator))
}

// verifyTrustRootUnder is VerifyTrustRoot with the top of the ancestor walk made
// explicit. It exists so tests can build a tree under a temporary directory and
// check it without the walk continuing into /tmp, which is mode 1777 and fails
// by design. Production callers always walk to the filesystem root; nothing but
// a test should ever pass a different stopAt, because a stopAt below a
// client-writable directory is exactly the hole this function looks for.
func verifyTrustRootUnder(path string, trustedOwnerUID uint32, stopAt string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return &TrustRootError{Asked: path, Failed: path, Reason: "cannot resolve to an absolute path"}
	}
	// Resolve symlinks before checking: the permissions that matter are those
	// of the file that is actually opened, and of the directories actually
	// walked to reach it.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return &TrustRootError{Asked: path, Failed: abs, Reason: "cannot resolve symlinks: " + err.Error()}
	}
	stop, err := filepath.EvalSymlinks(stopAt)
	if err != nil {
		return &TrustRootError{Asked: path, Failed: stopAt, Reason: "cannot resolve symlinks: " + err.Error()}
	}

	first := true
	for p := resolved; ; p = filepath.Dir(p) {
		if err := checkOwnership(path, p, trustedOwnerUID, first); err != nil {
			return err
		}
		first = false
		if p == stop || p == filepath.Dir(p) {
			return nil
		}
	}
}

// checkOwnership applies the trust-root property to one path. target is true for
// the path the caller asked about and false for its ancestors, which is the one
// place the two differ: the target must be owned by trustedOwnerUID exactly,
// while an ancestor may also be owned by root.
//
// Root is accepted on ancestors because a service account's own files ordinarily
// live under root-owned directories (/etc, /usr, /run), and because a root that
// wanted to subvert the broker would not need a directory to do it — root is
// outside this boundary either way (THREAT-MODEL.md §4d).
//
// This function's own logic never varies with which uid is passed in: the
// risk is entirely in production wiring the wrong *value* into
// trustedOwnerUID (the broker's own runtime uid instead of
// TrustedOwnerRootUID), never in this check's semantics.
// Widening the target case to also accept uid 0 unconditionally — regardless of
// trustedOwnerUID — would silently trust root-owned content even when a caller
// (test or otherwise) deliberately asked for a different trusted owner; that is
// not this function's job to decide.
func checkOwnership(asked, p string, trustedOwnerUID uint32, target bool) error {
	fi, err := lstat(p)
	if err != nil {
		return &TrustRootError{Asked: asked, Failed: p, Reason: "cannot stat: " + err.Error()}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return &TrustRootError{Asked: asked, Failed: p, Reason: "no ownership information available on this platform"}
	}
	if st.Uid != trustedOwnerUID && (target || st.Uid != 0) {
		return &TrustRootError{Asked: asked, Failed: p,
			Reason: fmt.Sprintf("owned by uid %d, expected uid %d", st.Uid, trustedOwnerUID)}
	}
	mode := fi.Mode().Perm()
	if mode&0o022 != 0 {
		return &TrustRootError{Asked: asked, Failed: p,
			Reason: fmt.Sprintf("mode %04o is writable by group or other", mode)}
	}
	// A sticky directory (/tmp, mode 1777) never reaches here — 0o022 catches
	// it first. That is the intended answer: a definition under /tmp is not a
	// trust root however the sticky bit constrains renames.
	return nil
}

// VerifyExecutable applies the same check to the binary a definition names.
//
// It is a separate call because it answers a separate question. A definition
// can be flawlessly owned and still point at an executable in a directory the
// client controls, in which case the allowlist names a program the client
// chooses the contents of — the exact substitution the definition exists to
// prevent, arrived at from the other end.
func (d *Definition) VerifyExecutable(trustedOwnerUID uint32) error {
	return VerifyTrustRoot(d.Executable, trustedOwnerUID)
}
