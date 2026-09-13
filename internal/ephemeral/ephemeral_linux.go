//go:build linux

package ephemeral

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// newDir creates a 0700 directory on tmpfs. It prefers $XDG_RUNTIME_DIR
// (per-user tmpfs) and falls back to /dev/shm. Teardown just removes the dir.
func newDir() (*Dir, error) {
	base, err := ramBase()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("ephemeral: create base %s: %w", base, err)
	}
	suffix, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(base, "run-"+suffix)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("ephemeral: create dir %s: %w", path, err)
	}
	return &Dir{path: path, teardown: func() { os.RemoveAll(path) }}, nil
}

// ramBase returns a RAM-backed base directory for parzival's ephemeral files.
func ramBase() (string, error) {
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "parzival"), nil
	}
	// /dev/shm is tmpfs on Linux; it is world-writable (1777) so namespace by uid.
	const shm = "/dev/shm"
	if fi, err := os.Stat(shm); err == nil && fi.IsDir() {
		return filepath.Join(shm, fmt.Sprintf("parzival-%d", os.Getuid())), nil
	}
	return "", fmt.Errorf("ephemeral: no RAM-backed dir ($XDG_RUNTIME_DIR unset and /dev/shm absent)")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ephemeral: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
