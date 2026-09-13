//go:build linux

package broker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerUIDReturnsOwnUID is the narrow real-socket test the design calls
// for: cross-uid behavior cannot be exercised under a single test uid (a real
// second uid would be needed), so this only proves the kernel-credential
// read itself works and returns the test process's own uid. Authorization
// DECISIONS against arbitrary constructed uids are tested separately and
// purely in authz_test.go's TestAuthzDecide, which needs no socket at all.
func TestPeerUIDReturnsOwnUID(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.UnixConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			errCh <- fmt.Errorf("accepted connection is not a *net.UnixConn: %T", conn)
			return
		}
		accepted <- uc
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var conn *net.UnixConn
	select {
	case conn = <-accepted:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	uid, err := peerUID(conn)
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Errorf("peerUID: got %d, want %d (this test process's own uid)", uid, os.Getuid())
	}
}
