package broker

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/store"
)

// These tests cover setSocketGroupAndMode's own behavior — that Serve()
// applies the configured group/mode deterministically, and refuses loudly
// rather than silently keeping a narrower socket when the configured group
// doesn't exist. They do NOT and cannot prove real cross-uid connect
// success/failure at the OS level (a single test process runs as one
// uid/gid set) — that proof requires a real multi-account environment
// against a packaged install, done separately from this test suite.
//
// What IS provable hermetically, and is proved here: the socket's resulting
// mode and group-ownership are exactly what was configured, using a group
// the test process is already a member of (its own primary group) so this
// needs no real "parzival-clients" system group to exist in CI.

// newSocketPermTestServer builds a minimal, fully-functional Server (unlike
// newFailingServer, this one is expected to actually Serve) with the given
// SocketGroupName, reusing testEnv's fixture consumer/profile/authz setup.
func newSocketPermTestServer(t *testing.T, socketGroupName string) *Server {
	t.Helper()
	authzPath := testEnv(t)
	cfg := Config{
		SocketPath:      filepath.Join(t.TempDir(), "broker.sock"),
		AuthzPath:       authzPath,
		AuditPath:       filepath.Join(t.TempDir(), "audit.log"),
		SocketGroupName: socketGroupName,
	}
	resolve := func(store.SecretRef) (store.Store, error) {
		return &fakeSecretStore{values: defaultTestSecrets()}, nil
	}
	peer := func(*net.UnixConn) (uint32, error) { return authorizedTestUID, nil }
	srv, err := newServer(cfg, noopVerify, resolve, peer, time.Now, &fakeAuditWriter{}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return srv
}

// currentGroupName resolves the calling process's own primary gid to a
// group name, so the test can ask setSocketGroupAndMode for a group that is
// guaranteed to exist and that the process is already a member of, without
// requiring any project-specific system group ("parzival-clients") to be
// present on whatever machine runs `go test`.
func currentGroupName(t *testing.T) (name string, gid int) {
	t.Helper()
	gid = os.Getgid()
	grp, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		t.Skipf("cannot resolve current gid %d to a group name on this system: %v", gid, err)
	}
	return grp.Name, gid
}

func TestServeSetsSocketGroupAndMode(t *testing.T) {
	groupName, wantGID := currentGroupName(t)
	srv := newSocketPermTestServer(t, groupName)
	stop := startServing(t, srv)
	defer stop()

	fi, err := os.Stat(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %o, want 0660", got)
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t ownership info available on this platform")
	}
	if got := int(st.Gid); got != wantGID {
		t.Errorf("socket gid = %d, want %d (%s)", got, wantGID, groupName)
	}
}

func TestServeLeavesSocketAtDefaultModeWhenGroupNameEmpty(t *testing.T) {
	srv := newSocketPermTestServer(t, "")
	stop := startServing(t, srv)
	defer stop()

	// No assertion on the exact mode here — it's whatever the test
	// process's umask produces, which is not this package's business to
	// pin down. The point is only that Serve() must not fail, and must not
	// attempt any chown/chmod, when SocketGroupName is unset — which every
	// other test in this package already relies on implicitly, since none
	// of them set it.
	if _, err := os.Stat(srv.cfg.SocketPath); err != nil {
		t.Fatalf("stat socket: %v", err)
	}
}

func TestServeRefusesUnknownSocketGroup(t *testing.T) {
	srv := newSocketPermTestServer(t, "parzival-36-test-group-that-does-not-exist-anywhere")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := srv.Serve(ctx)
	if err == nil {
		t.Fatal("Serve: expected an error for an unresolvable socket group, got nil")
	}
	if !strings.Contains(err.Error(), "socket group") {
		t.Errorf("Serve error = %q, want it to mention the socket group by name", err.Error())
	}
}
