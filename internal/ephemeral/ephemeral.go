// Package ephemeral provides RAM-backed temporary storage for secret material:
// a private directory whose files are zeroed and unlinked on cleanup. Nothing
// here is written to persistent disk.
//
// The platform-specific creation and teardown live in ephemeral_linux.go
// (tmpfs) and ephemeral_darwin.go (a per-invocation RAM disk). The shared logic
// here — writing 0600 files and wiping on cleanup — is identical on both.
package ephemeral

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Dir is a private, RAM-backed directory that wipes its contents on Cleanup.
type Dir struct {
	path     string
	teardown func() // platform-specific final teardown, run after files are zeroed
}

// New creates a RAM-backed 0700 directory for the current platform.
func New() (*Dir, error) { return newDir() }

// Path returns the directory's path.
func (d *Dir) Path() string { return d.path }

// WriteFile writes b to a new 0600 file at name (a path relative to the dir)
// and returns its full path. name may name subdirectories, which are created
// 0700. It refuses to overwrite an existing file, and refuses a name that would
// resolve outside the dir — a rendered secret must never land somewhere Cleanup
// does not wipe.
func (d *Dir) WriteFile(name string, b []byte) (string, error) {
	p := filepath.Join(d.path, name)
	if !d.contains(p) {
		return "", fmt.Errorf("ephemeral: %q resolves outside the ephemeral dir", name)
	}
	if parent := filepath.Dir(p); parent != d.path {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", fmt.Errorf("ephemeral: mkdir %s: %w", parent, err)
		}
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("ephemeral: create %s: %w", p, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", fmt.Errorf("ephemeral: write %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("ephemeral: close %s: %w", p, err)
	}
	return p, nil
}

// contains reports whether p lies inside the dir. Belt-and-braces against a
// traversing inject.filename, which profile.validateFilename already rejects.
func (d *Dir) contains(p string) bool {
	rel, err := filepath.Rel(d.path, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Cleanup best-effort zeroes every file in the dir — at any depth, since a
// profile may render into a subdirectory — then runs the platform teardown
// (remove the dir on Linux; unmount + detach the RAM disk on macOS). It is
// idempotent and safe to call more than once (e.g. via defer and on a signal).
func (d *Dir) Cleanup() {
	if d == nil || d.path == "" {
		return
	}
	// WalkDir does not follow symlinks, so this cannot be steered outside the dir.
	filepath.WalkDir(d.path, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil // best effort: keep going, teardown still runs
		}
		if !e.IsDir() {
			zeroFile(p)
		}
		return nil
	})
	if d.teardown != nil {
		d.teardown()
	}
	d.path = ""
}

// zeroFile overwrites a file's bytes with zeros before it is unlinked. On a RAM
// disk the pages are freed on unlink/detach anyway; this is defense in depth.
func zeroFile(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	zeros := make([]byte, 4096)
	for remaining := fi.Size(); remaining > 0; {
		n := min(int64(len(zeros)), remaining)
		if _, err := f.Write(zeros[:n]); err != nil {
			return
		}
		remaining -= n
	}
	f.Sync()
}
