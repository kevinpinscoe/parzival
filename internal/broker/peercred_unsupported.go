//go:build !linux

package broker

import (
	"errors"
	"net"
)

// peerUID is not implemented on this platform. Mirrors internal/mount's
// mount_darwin.go stub pattern: an XPC-based peer identity for macOS is not
// implemented yet; SO_PEERCRED is Linux-specific.
func peerUID(conn *net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials: SO_PEERCRED is not supported on this platform")
}
