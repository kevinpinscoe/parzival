package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZero(t *testing.T) {
	b := []byte("secret")
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Zero left byte %d = %d, want 0", i, v)
		}
	}
}

func TestWriteToNoTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTo(f, []byte("s3cr3t")); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	f.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("wrote %q, want %q (no added newline)", got, "s3cr3t")
	}
}
