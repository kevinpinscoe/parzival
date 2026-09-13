//go:build linux

package mount

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestProfileNames(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
	pdir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"gitea-token.json", "aws.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(pdir, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, err := profileNames()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"aws", "gitea-token"}) { // sorted, .txt excluded
		t.Fatalf("profileNames = %v, want [aws gitea-token]", names)
	}
}

func TestProfileNamesMissingDir(t *testing.T) {
	t.Setenv("PARZIVAL_CONFIG_HOME", filepath.Join(t.TempDir(), "absent"))
	names, err := profileNames()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("want no names, got %v", names)
	}
}
