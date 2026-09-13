// Package secret holds helpers for handling raw secret bytes: writing them to
// an output exactly (no added newline) and wiping them from memory afterward.
package secret

import (
	"fmt"
	"os"
)

// Zero overwrites b with zeros. This is best effort: Go's garbage collector may
// already have copied the value elsewhere, so it reduces exposure rather than
// guaranteeing erasure.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// FileForFD wraps an already-open, inherited file descriptor as an *os.File so a
// secret can be written to a caller-supplied descriptor instead of stdout.
func FileForFD(fd int) *os.File {
	return os.NewFile(uintptr(fd), fmt.Sprintf("fd/%d", fd))
}

// WriteTo writes exactly b to dst, with no added newline.
func WriteTo(dst *os.File, b []byte) error {
	if _, err := dst.Write(b); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}
