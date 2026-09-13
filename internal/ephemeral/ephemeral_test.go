//go:build linux

package ephemeral

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirLifecycle(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	dirPath := d.Path()

	if fi, err := os.Stat(dirPath); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm = %o, want 700", fi.Mode().Perm())
	}

	p, err := d.WriteFile("credential", []byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file perm = %o, want 600", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(p); string(got) != "s3cr3t" {
		t.Fatalf("content = %q, want s3cr3t", got)
	}

	// Refuse to overwrite an existing file.
	if _, err := d.WriteFile("credential", []byte("x")); err == nil {
		t.Fatal("expected error writing over existing file")
	}

	d.Cleanup()
	if _, err := os.Stat(dirPath); !os.IsNotExist(err) {
		t.Fatalf("dir still present after cleanup: %v", err)
	}
	d.Cleanup() // idempotent, must not panic
}

// A profile may render into a subdirectory (inject.filename "tea/config.yml")
// for tools that read a fixed filename inside a config dir.
func TestWriteFileNested(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Cleanup()

	p, err := d.WriteFile("tea/config.yml", []byte("token: s3cr3t\n"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file perm = %o, want 600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir perm = %o, want 700", fi.Mode().Perm())
	}
}

// A rendered secret must never land outside the dir Cleanup wipes.
func TestWriteFileRejectsEscape(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Cleanup()

	for _, name := range []string{"../escape", "a/../../escape", "sub/../../out"} {
		if _, err := d.WriteFile(name, []byte("x")); err == nil {
			t.Fatalf("WriteFile(%q) succeeded, want refusal", name)
		}
	}
}

// Regression: Cleanup used to os.ReadDir and skip directory entries, so a secret
// rendered into a subdirectory was unlinked but never zeroed. Uses a hand-built
// Dir with no teardown so the bytes survive for inspection.
func TestCleanupZeroesNestedFiles(t *testing.T) {
	d := &Dir{path: t.TempDir()} // nil teardown: Cleanup zeroes but does not remove

	top, err := d.WriteFile("credential", []byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	nested, err := d.WriteFile("tea/config.yml", []byte("token: s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}

	d.Cleanup()

	for _, p := range []string{top, nested} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s is empty; expected same-length zeroed content", p)
		}
		for i, c := range b {
			if c != 0 {
				t.Fatalf("%s not zeroed: byte %d = %q", p, i, c)
			}
		}
	}
}
