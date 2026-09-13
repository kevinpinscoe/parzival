//go:build linux

package broker

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID reads the connecting client's uid from the kernel via SO_PEERCRED.
// There is no field in the request for a client to state who it is, and
// there must never be one — SERVICE-PROTOCOL.md, "Peer credentials are read
// from the kernel, never from the request. There is no field in which a
// client states who it is, and there is no equivalent of --as."
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peer credentials: %w", err)
	}
	var ucred *unix.Ucred
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, fmt.Errorf("peer credentials: %w", ctrlErr)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("peer credentials: SO_PEERCRED: %w", sockErr)
	}
	return uint32(ucred.Uid), nil
}
