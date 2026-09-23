package broker

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kevinpinscoe/parzival/internal/consumer"
	"github.com/kevinpinscoe/parzival/internal/profile"
	"github.com/kevinpinscoe/parzival/internal/secret"
	"github.com/kevinpinscoe/parzival/internal/store"
)

// Config is the broker's configuration: plain data only. It deliberately
// carries no function-valued field for trust-root verification, store
// resolution, or peer-credential reading — see Server's unexported fields
// and New's doc comment for why a production-reachable seam for any of those
// is not offered, even to cmd/parzival-broker.
type Config struct {
	// SocketPath is the AF_UNIX socket the broker listens on.
	SocketPath string
	// AuthzPath is the peer-authorization file (authz.go's AuthzFile). The
	// packaged systemd unit fixes it at /etc/parzival-broker/authz.json for
	// real deployments (see INSTALL.md); it stays a Config field, not a
	// hardcoded constant, so tests and non-package deployments can point
	// elsewhere.
	AuthzPath string
	// AuditPath is the audit log file (audit.go's fileAuditWriter).
	AuditPath string
	// TrustedOwnerUID is the uid every trust-root check (consumer
	// definitions, their executables, their profiles, the authorization
	// file) requires ownership by. It is the *trusted* owner — root in
	// every production deployment (consumer.TrustedOwnerRootUID) — not the
	// broker's own runtime identity: cmd/parzival-broker wires this
	// constant, never the broker's own os.Getuid(). Only this package's
	// own tests supply a different value.
	TrustedOwnerUID uint32

	// SocketGroupName, when non-empty, is the name of a local OS group the
	// listening socket's group ownership is set to immediately after
	// creation, alongside setting its mode to 0660. Filesystem
	// permissions on the socket are a coarse local admission gate only — the
	// authoritative per-request decision is still SO_PEERCRED plus authz.json,
	// unaffected by this field. Membership in this group must never be
	// treated as authorizing an operation by itself.
	//
	// Left empty (the zero value), the socket keeps whatever mode/ownership
	// net.Listen's underlying bind(2) produces under the process's umask —
	// existing tests rely on this to avoid needing a real system group.
	//
	// A name that doesn't resolve to a real group is a startup-time refusal,
	// not a silent fall-back to the umask-derived mode: silently keeping a
	// tighter-than-configured socket would leave every uid the operator
	// authorized in authz.json unable to connect, with no error until
	// someone tries — refuse loudly instead of degrading silently.
	SocketGroupName string

	// MaxRequestBytes/MaxResponseBytes/ReadTimeout/DefaultOpTimeout default
	// to SERVICE-PROTOCOL.md's stated bounds when zero.
	MaxRequestBytes  int
	MaxResponseBytes int
	ReadTimeout      time.Duration
	DefaultOpTimeout time.Duration
}

func applyDefaults(cfg Config) Config {
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = MaxRequestBytes
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = MaxResponseBytes
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.DefaultOpTimeout == 0 {
		cfg.DefaultOpTimeout = 30 * time.Second
	}
	return cfg
}

// reservedEnvNames are variable names a profile's Inject.Env/Inject.EnvDir
// may never claim, regardless of what an administrator writes. A profile is
// administrator-authored, but these are broker-controlled specifically so a
// profile *cannot* redefine them, even by accident.
var reservedEnvNames = map[string]bool{
	"PATH": true, "HOME": true, "XDG_RUNTIME_DIR": true,
	"PARZIVAL_CONFIG_HOME": true,
	"LD_PRELOAD":           true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true,
	"ENV": true, "BASH_ENV": true, "SHELL": true,
}

// checkReservedInjectVars refuses a profile whose Inject.Env or
// Inject.EnvDir names a reserved variable. A profile is still free to
// inject anything else it needs (e.g. XDG_CONFIG_HOME, as
// examples/profiles/tea.json does) — only the reserved set is off-limits.
func checkReservedInjectVars(inj profile.Inject) error {
	for _, name := range []string{inj.Env, inj.EnvDir} {
		if name == "" {
			continue
		}
		if reservedEnvNames[name] || strings.HasPrefix(name, "BAO_") || strings.HasPrefix(name, "PARZIVAL_") {
			return fmt.Errorf("inject variable %q is reserved and may not be claimed by a profile", name)
		}
	}
	return nil
}

// verifyTrustRootFunc, resolveStoreFunc and peerUIDFunc are the three
// security-critical dependencies Server needs. Each has exactly one real
// implementation (consumer.VerifyTrustRoot, store.Resolve, peerUID) and New
// wires only those. newServer accepts them as parameters purely so this
// package's own tests — compiled into the same package, the only place that
// can reach an unexported identifier — can substitute fakes; no exported API
// anywhere in this package accepts a replacement for any of the three.
type verifyTrustRootFunc func(path string, trustedOwnerUID uint32) error
type resolveStoreFunc func(store.SecretRef) (store.Store, error)
type peerUIDFunc func(*net.UnixConn) (uint32, error)

// Server is the broker. Every field a client's request could otherwise use
// to influence trust decisions is unexported; the only way to build one from
// outside this package is New, which always uses the real implementations.
type Server struct {
	cfg      Config
	defs     map[string]*consumer.Definition
	profiles map[string]*profile.Profile // keyed by profile name
	authz    *AuthzFile
	audit    AuditWriter
	log      *log.Logger

	verify  verifyTrustRootFunc
	resolve resolveStoreFunc
	peer    peerUIDFunc
	now     func() time.Time

	ln *net.UnixListener
}

// New constructs a Server, verifying every part of the trust root — every
// consumer definition and its executable, every profile a consumer
// references, and the authorization file — before returning. Any failure at
// any step refuses: no listener is ever created for a Server whose trust
// root did not fully verify.
//
// This is the only entry point cmd/parzival-broker calls, and it always
// wires the real dependencies: consumer.VerifyTrustRoot, store.Resolve, and
// the real SO_PEERCRED reader. There is no Config field, flag, or
// environment variable that changes any of the three — a production-typable
// bypass of security-critical verification is exactly the kind of control
// this project refuses to offer (see internal/agent's doc comment for the
// same principle applied elsewhere in this codebase).
func New(cfg Config) (*Server, error) {
	audit, err := newFileAuditWriter(cfg.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("broker startup: %w", err)
	}
	logger := log.New(os.Stderr, "parzival-broker: ", log.LstdFlags|log.Lmicroseconds)
	return newServer(cfg, consumer.VerifyTrustRoot, store.Resolve, peerUID, time.Now, audit, logger)
}

func newServer(
	cfg Config,
	verify verifyTrustRootFunc,
	resolve resolveStoreFunc,
	peer peerUIDFunc,
	now func() time.Time,
	audit AuditWriter,
	logger *log.Logger,
) (*Server, error) {
	cfg = applyDefaults(cfg)

	defs, err := consumer.LoadAll(consumer.Dir())
	if err != nil {
		return nil, fmt.Errorf("broker startup: %w", err)
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("broker startup: no consumer definitions loaded from %s", consumer.Dir())
	}
	for name, def := range defs {
		defPath := filepath.Join(consumer.Dir(), name+".json")
		if err := verify(defPath, cfg.TrustedOwnerUID); err != nil {
			return nil, fmt.Errorf("broker startup: consumer definition %q: %w", name, err)
		}
		// Not def.VerifyExecutable(cfg.TrustedOwnerUID): that method always calls
		// the real consumer.VerifyTrustRoot directly, bypassing the
		// injectable verify seam entirely (production's verify IS
		// consumer.VerifyTrustRoot, so behavior is identical there, but a
		// test using a fake verify would silently fall through to the real
		// filesystem check on the executable path and fail under a
		// t.TempDir(), which sits under /tmp's own 1777 mode).
		if err := verify(def.Executable, cfg.TrustedOwnerUID); err != nil {
			return nil, fmt.Errorf("broker startup: consumer %q executable: %w", name, err)
		}
		for opName, op := range def.Operations {
			key := name + "." + opName
			if _, err := validatorFor(key, op); err != nil {
				return nil, fmt.Errorf("broker startup: consumer %q operation %q %w", name, opName, err)
			}
		}
	}

	// Every referenced profile is resolved, loaded, and trust-verified now —
	// at startup, not lazily on first request — and cached, so a request
	// handler never re-loads or re-verifies one (no per-request TOCTOU
	// window on profile trust). A profile is part of the trusted computing
	// base exactly like a consumer definition: it controls which credential
	// references get fetched and what gets injected into the consumer's
	// environment.
	profiles := make(map[string]*profile.Profile, len(defs))
	for name, def := range defs {
		if _, already := profiles[def.Profile]; already {
			continue
		}
		prof, err := profile.Load(def.Profile)
		if err != nil {
			return nil, fmt.Errorf("broker startup: consumer %q profile %q: %w", name, def.Profile, err)
		}
		profPath := filepath.Join(profile.Dir(), def.Profile+".json")
		if err := verify(profPath, cfg.TrustedOwnerUID); err != nil {
			return nil, fmt.Errorf("broker startup: profile %q: %w", def.Profile, err)
		}
		if err := checkReservedInjectVars(prof.Inject); err != nil {
			return nil, fmt.Errorf("broker startup: profile %q: %w", def.Profile, err)
		}
		profiles[def.Profile] = prof
	}

	authzFile, err := LoadFile(cfg.AuthzPath)
	if err != nil {
		return nil, fmt.Errorf("broker startup: %w", err)
	}
	if err := verify(cfg.AuthzPath, cfg.TrustedOwnerUID); err != nil {
		return nil, fmt.Errorf("broker startup: authorization file: %w", err)
	}
	if err := authzFile.Validate(defs); err != nil {
		return nil, fmt.Errorf("broker startup: %w", err)
	}

	return &Server{
		cfg:      cfg,
		defs:     defs,
		profiles: profiles,
		authz:    authzFile,
		audit:    audit,
		log:      logger,
		verify:   verify,
		resolve:  resolve,
		peer:     peer,
		now:      now,
	}, nil
}

// Serve listens on cfg.SocketPath and serves connections until ctx is
// cancelled, at which point it stops accepting new connections, lets
// in-flight handlers finish, and returns nil.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("broker: listen %s: %w", s.cfg.SocketPath, err)
	}
	uln, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return fmt.Errorf("broker: listener for %s is not a *net.UnixListener", s.cfg.SocketPath)
	}

	// bind(2) creates the socket file honoring the process's
	// umask, with nothing about net.Listen letting a caller specify a mode
	// directly — the packaged unit's own UMask=0077 hardening setting is
	// exactly what left this at 0700 (owner-only) with no explicit fix here.
	// A 0700 socket admits only the broker's own uid, which defeats
	// authz.json's whole per-uid model: any uid it authorizes needs to be
	// able to *connect* before SO_PEERCRED + authz.json ever get to decide
	// whether that uid's *operation* is allowed. Applying the intended
	// group/mode immediately after a successful Listen — before Accept is
	// ever called, so no connection can race this window — only ever moves
	// the socket from the narrower umask-derived mode to the intended one,
	// never the reverse, so there is no window where it is more open than
	// configured.
	if s.cfg.SocketGroupName != "" {
		if err := setSocketGroupAndMode(s.cfg.SocketPath, s.cfg.SocketGroupName); err != nil {
			uln.Close()
			return fmt.Errorf("broker: %w", err)
		}
	}
	s.ln = uln

	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			uln.Close()
		case <-shutdown:
		}
	}()

	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := uln.Accept()
		if err != nil {
			acceptErr = err
			break
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, uc)
		}()
	}
	close(shutdown)
	wg.Wait()

	if ctx.Err() != nil {
		return nil // graceful shutdown: the Accept error is just the closed listener
	}
	return fmt.Errorf("broker: accept: %w", acceptErr)
}

// setSocketGroupAndMode sets path's group ownership to groupName's gid and
// its mode to 0660 (owner+group read/write, no world access).
// This is filesystem-layer local admission only: it decides who can *reach*
// the socket, never what they're allowed to *do* once connected, which
// remains SO_PEERCRED plus authz.json's uid-based decision in session.go,
// entirely unchanged by this function.
//
// Ownership (the ':owner' half) is left alone deliberately — chown requires
// either owning the file and being a member of the target gid (true for the
// broker process itself, which just created this file and is expected to
// carry groupName as a supplementary group in production), or CAP_CHOWN.
// Refusing loudly here if that membership is missing is correct: a silent
// fallback would leave the socket at its narrower as-created mode with no
// indication why authorized callers can't connect.
func setSocketGroupAndMode(path, groupName string) error {
	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("socket group %q: %w (create it — e.g. via packaging/sysusers.d — before starting the broker)", groupName, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("socket group %q: gid %q is not numeric: %w", groupName, grp.Gid, err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("chown %s to group %q (gid %d): %w — is the broker's own account a member of that group?", path, groupName, gid, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("chmod %s to 0660: %w", path, err)
	}
	return nil
}

// fetchSecrets fetches every secret prof declares, using the broker's own
// store authentication (s.resolve) — never a caller-supplied identity.
// SERVICE-PROTOCOL.md step 7: "Fetch the credential using the broker's own
// store authentication." On any failure, every secret already fetched is
// zeroed before returning.
func (s *Server) fetchSecrets(ctx context.Context, prof *profile.Profile) (map[string][]byte, error) {
	secrets := make(map[string][]byte, len(prof.Secrets))
	for name, ref := range prof.Secrets {
		parsed, err := store.ParseRef(ref)
		if err != nil {
			zeroAll(secrets)
			return nil, fmt.Errorf("parse secret ref: %w", err)
		}
		st, err := s.resolve(parsed)
		if err != nil {
			zeroAll(secrets)
			return nil, fmt.Errorf("resolve store: %w", err)
		}
		val, err := st.Get(ctx, parsed)
		if err != nil {
			zeroAll(secrets)
			return nil, fmt.Errorf("fetch secret: %w", err)
		}
		secrets[name] = val
	}
	return secrets, nil
}

// zeroAll zeroes every value in m.
func zeroAll(m map[string][]byte) {
	for _, v := range m {
		secret.Zero(v)
	}
}
