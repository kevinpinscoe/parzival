//go:build darwin

// Package mount's macOS implementation is a stub: FUSE on macOS (via fuse-t or
// macFUSE) is not yet supported. Use `parzival exec`, which renders to a RAM disk.
package mount

import "errors"

// Serve is not implemented on macOS.
func Serve(mountpoint, identity string) error {
	return errors.New("parzival mount is not supported on macOS yet; use `parzival exec` (RAM-disk delivery) instead")
}
