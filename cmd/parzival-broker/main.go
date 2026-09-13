// Command parzival-broker is the Linux broker daemon: it speaks the protocol
// in SERVICE-PROTOCOL.md, serving one operation, tea.repos-list, over an
// AF_UNIX socket. See internal/broker's package doc comment for what this
// implementation covers.
//
// This file is deliberately thin, matching cmd/parzival's own convention:
// every real decision — trust-root verification, authorization, the request
// sequence — lives in internal/broker. This file only turns flags/env vars
// into a broker.Config, pins the process-global environment internal/
// consumer, internal/profile and internal/ephemeral resolve their working
// directories from, and runs the server until asked to stop.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kevinpinscoe/parzival/internal/broker"
	"github.com/kevinpinscoe/parzival/internal/consumer"
)

// version and commit are populated at release-build time via
// `-ldflags "-X main.version=... -X main.commit=..."` (see .goreleaser.yml);
// a plain `go build` leaves them at their defaults.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "parzival-broker:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		socketPath  = flag.String("socket", envOr("PARZIVAL_BROKER_SOCKET", "/run/parzival/broker.sock"), "AF_UNIX socket path (or $PARZIVAL_BROKER_SOCKET)")
		authzPath   = flag.String("authz", envOr("PARZIVAL_BROKER_AUTHZ_FILE", ""), "authorization file path (or $PARZIVAL_BROKER_AUTHZ_FILE) — required")
		auditPath   = flag.String("audit", envOr("PARZIVAL_BROKER_AUDIT_FILE", ""), "audit log path (or $PARZIVAL_BROKER_AUDIT_FILE) — required")
		configHome  = flag.String("config-home", envOr("PARZIVAL_BROKER_CONFIG_HOME", ""), "root-owned directory holding consumers/ and profiles/ (or $PARZIVAL_BROKER_CONFIG_HOME) — required")
		runtimeRoot = flag.String("runtime-dir", envOr("PARZIVAL_BROKER_RUNTIME_DIR", ""), "broker-private runtime directory root (or $PARZIVAL_BROKER_RUNTIME_DIR) — required")
		socketGroup = flag.String("socket-group", envOr("PARZIVAL_BROKER_SOCKET_GROUP", "parzival-clients"), "local OS group the socket's group ownership and 0660 mode are set to after bind (or $PARZIVAL_BROKER_SOCKET_GROUP) — empty disables this")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("parzival-broker %s (commit %s)\n", version, commit)
		return nil
	}

	// These four have no built-in defaults deliberately: the packaged systemd
	// unit's own ExecStart= is what supplies fixed values for a real
	// deployment (see packaging/systemd/parzival-broker.service); a caller
	// with no packaging at all must still pass them explicitly rather than
	// the binary guessing a path.
	if *authzPath == "" || *auditPath == "" || *configHome == "" || *runtimeRoot == "" {
		return fmt.Errorf("missing required configuration: -authz, -audit, -config-home, and -runtime-dir (or their $PARZIVAL_BROKER_* environment equivalents) are all required")
	}

	// internal/consumer, internal/profile and internal/ephemeral all resolve
	// their working directories from process-global environment variables
	// (PARZIVAL_CONFIG_HOME, XDG_RUNTIME_DIR). The broker is a distinct
	// identity from any invoking user, so these are pinned explicitly here
	// rather than left to whatever the process happens to inherit.
	if err := os.Setenv("PARZIVAL_CONFIG_HOME", *configHome); err != nil {
		return fmt.Errorf("set PARZIVAL_CONFIG_HOME: %w", err)
	}
	if err := os.Setenv("XDG_RUNTIME_DIR", *runtimeRoot); err != nil {
		return fmt.Errorf("set XDG_RUNTIME_DIR: %w", err)
	}

	cfg := broker.Config{
		SocketPath: *socketPath,
		AuthzPath:  *authzPath,
		AuditPath:  *auditPath,
		// TrustedOwnerUID is deliberately the constant root uid, never the
		// broker's own runtime identity (os.Getuid()). The broker's own uid
		// is a privilege-reduction measure; it says nothing about who is
		// authorized to write the files it trusts.
		TrustedOwnerUID: consumer.TrustedOwnerRootUID,
		// SocketGroupName defaults to "parzival-clients" — the group name
		// this project's own packaging creates via sysusers.d.
		// Never a hardcoded uid or username: any local account an
		// administrator adds to this group can *reach* the socket, with
		// authz.json's uid-based rules deciding what it may then do.
		SocketGroupName: *socketGroup,
	}

	srv, err := broker.New(cfg)
	if err != nil {
		return err
	}

	// A leftover socket file from a prior, uncleanly stopped run otherwise
	// blocks Listen with "address already in use" even though nothing is
	// listening. Removing it before binding is ordinary restart hygiene, not
	// a security decision — the socket is recreated by Listen immediately
	// after, with the same mode/ownership Listen itself applies.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket %s: %w", *socketPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Serve stops accepting new connections and lets in-flight handlers
	// finish when ctx is cancelled by the signal above — see broker.go's
	// Serve doc comment. There is no process-wide os.Exit-on-signal handler
	// here (unlike cmd/parzival's exec cleanupOnSignal), because that
	// pattern is wrong for a daemon serving concurrent connections: killing
	// the whole process on the first signal would cut off every other
	// in-flight request, not just the one being interrupted.
	return srv.Serve(ctx)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
