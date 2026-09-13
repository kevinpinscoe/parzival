package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kevinpinscoe/parzival/internal/store"
)

// fakeSecretStore is an in-memory store.Store for tests — no real OpenBao,
// no network. getCalls counts Get invocations, so tests can assert a
// credential was never fetched on a denied or invalid request.
type fakeSecretStore struct {
	values   map[string][]byte
	getCalls int
	getErr   error
}

func (f *fakeSecretStore) Name() string                     { return "fake" }
func (f *fakeSecretStore) Capabilities() store.Capabilities { return store.Capabilities{} }
func (f *fakeSecretStore) Get(_ context.Context, ref store.SecretRef) ([]byte, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.values[ref.Raw]
	if !ok {
		return nil, fmt.Errorf("fake store: no value for %s", ref.Raw)
	}
	return append([]byte(nil), v...), nil
}

const testCredentialValue = "gt_TESTCREDENTIALVALUE_MUST_NEVER_LEAK_9f8e7d"

const testConsumerJSONTemplate = `{
  "schema": 1,
  "name": "tea",
  "executable": %q,
  "profile": "tea",
  "operations": {
    "repos-list": {
      "argv": ["repos", "list", "--owner", "${owner}", "--output", "json"],
      "inputs": {"owner": {"pattern": "[A-Za-z0-9._-]+", "max_length": 39}},
      "response": "json",
      "timeout_seconds": 1
    }
  }
}`

const testProfileJSON = `{
  "secrets": {"token": "bao:app/gitea#token", "url": "bao:app/gitea#url", "user": "bao:app/gitea#user"},
  "template": "logins:\n    - name: parzival\n      url: {{ .url }}\n      token: {{ .token }}\n      default: true\n      user: {{ .user }}\n      version_check: true\n",
  "inject": {"filename": "tea/config.yml", "env_dir": "XDG_CONFIG_HOME"}
}`

const testAuthzJSON = `{
  "schema": 1,
  "entries": [
    {"uid": 1000, "operations": ["tea.repos-list"]}
  ]
}`

const (
	authorizedTestUID   = 1000
	unauthorizedTestUID = 2000
)

// testEnv sets up a fresh PARZIVAL_CONFIG_HOME (consumers/tea.json —
// executable pointed at the faketea fixture — and profiles/tea.json) and a
// fresh XDG_RUNTIME_DIR, via t.Setenv (restored automatically at test end,
// the sanctioned isolation mechanism PARZIVAL_CONFIG_HOME exists for).
// Returns the path to a fresh authz.json fixture granting
// authorizedTestUID tea.repos-list.
func testEnv(t *testing.T) (authzPath string) {
	t.Helper()
	configHome := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", configHome)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	consumersDir := filepath.Join(configHome, "consumers")
	profilesDir := filepath.Join(configHome, "profiles")
	if err := os.MkdirAll(consumersDir, 0o700); err != nil {
		t.Fatalf("mkdir consumers: %v", err)
	}
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatalf("mkdir profiles: %v", err)
	}
	consumerJSON := fmt.Sprintf(testConsumerJSONTemplate, fakeTeaPath)
	if err := os.WriteFile(filepath.Join(consumersDir, "tea.json"), []byte(consumerJSON), 0o600); err != nil {
		t.Fatalf("write consumer definition: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profilesDir, "tea.json"), []byte(testProfileJSON), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	authzPath = filepath.Join(t.TempDir(), "authz.json")
	if err := os.WriteFile(authzPath, []byte(testAuthzJSON), 0o600); err != nil {
		t.Fatalf("write authz file: %v", err)
	}
	return authzPath
}

func defaultTestSecrets() map[string][]byte {
	return map[string][]byte{
		"bao:app/gitea#token": []byte(testCredentialValue),
		"bao:app/gitea#url":   []byte("https://gitea.test"),
		"bao:app/gitea#user":  []byte("parzival"),
	}
}

func noopVerify(string, uint32) error { return nil }

// testServerOpts customizes newTestServer's construction. Zero values pick
// sensible defaults (a working store, uid 0 as trusted owner for verify since
// verify itself is faked, a discarding logger).
type testServerOpts struct {
	peerUID uint32
	peerErr error
	store   *fakeSecretStore
	verify  verifyTrustRootFunc
	auditW  AuditWriter
	logger  *log.Logger
}

func newTestServer(t *testing.T, authzPath string, opts testServerOpts) (*Server, *fakeSecretStore) {
	t.Helper()
	st := opts.store
	if st == nil {
		st = &fakeSecretStore{values: defaultTestSecrets()}
	}
	resolve := func(store.SecretRef) (store.Store, error) { return st, nil }
	peer := func(*net.UnixConn) (uint32, error) { return opts.peerUID, opts.peerErr }
	verify := opts.verify
	if verify == nil {
		verify = noopVerify
	}
	auditW := opts.auditW
	if auditW == nil {
		auditW = &fakeAuditWriter{}
	}
	logger := opts.logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	cfg := Config{
		SocketPath:      filepath.Join(t.TempDir(), "broker.sock"),
		AuthzPath:       authzPath,
		AuditPath:       filepath.Join(t.TempDir(), "audit.log"),
		TrustedOwnerUID: 0,
	}
	srv, err := newServer(cfg, verify, resolve, peer, time.Now, auditW, logger)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return srv, st
}

// startServing starts srv.Serve in the background and waits for its socket
// to appear. The returned stop function cancels serving and waits for it to
// finish, failing the test if it does not stop promptly.
func startServing(t *testing.T, srv *Server) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(srv.cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear in time", srv.cfg.SocketPath)
		}
		time.Sleep(5 * time.Millisecond)
	}

	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop within 2s of context cancellation")
		}
	}
}

// doRequest dials srv's socket, sends req, and returns the decoded response.
func doRequest(t *testing.T, srv *Server, req Request) *Response {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return doRawRequest(t, srv, body)
}

// doRawRequest dials srv's socket and sends an arbitrary raw frame body,
// for tests that need to send something Request's own strict shape cannot
// represent (an unknown field, trailing data, a missing field).
func doRawRequest(t *testing.T, srv *Server, body []byte) *Response {
	t.Helper()
	conn, err := net.Dial("unix", srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := writeFrame(conn, body); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	respBody, err := readFrame(conn, uint32(MaxResponseBytes+4096))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("unmarshal response: %v (body=%q)", err, respBody)
	}
	return &resp
}

// dialRaw returns a raw connection to srv's socket for tests that drive the
// wire protocol by hand (oversized frames, no response expected, etc.).
func dialRaw(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// --- small file helpers for tests that need to mutate fixtures after
// testEnv has already written them -----------------------------------------

func configHomeFromEnv(t *testing.T) string {
	t.Helper()
	v := os.Getenv("PARZIVAL_CONFIG_HOME")
	if v == "" {
		t.Fatal("PARZIVAL_CONFIG_HOME is not set — call testEnv(t) first")
	}
	return v
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// waitForCondition polls cond until it reports true or 2 seconds elapse.
func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
