package broker

import (
	"encoding/json"
	"testing"
)

func TestClientCall_OK_ReposList(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	c, err := Dial(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Call("tea.repos-list", map[string]string{"owner": "acme"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != StatusOK {
		t.Fatalf("got status %s, want OK (error=%+v)", resp.Status, resp.Error)
	}
	var repos []repoSummary
	if err := json.Unmarshal(resp.Result, &repos); err != nil {
		t.Fatalf("result did not decode as []repoSummary: %v (result=%q)", err, resp.Result)
	}
	if len(repos) == 0 || repos[0].Owner != "acme" {
		t.Errorf("got %+v", repos)
	}
}

func TestClientCall_Denied(t *testing.T) {
	authzPath := testEnv(t)
	srv, st := newTestServer(t, authzPath, testServerOpts{peerUID: unauthorizedTestUID})
	defer startServing(t, srv)()

	c, err := Dial(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Call("tea.repos-list", map[string]string{"owner": "acme"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != StatusDenied {
		t.Fatalf("got status %s, want DENIED", resp.Status)
	}
	if resp.Error == nil || resp.Error.Code != CodeNotAuthorized {
		t.Errorf("got error %+v, want code %s", resp.Error, CodeNotAuthorized)
	}
	if st.getCalls != 0 {
		t.Errorf("credential must never be fetched on a denied request; store.Get was called %d times", st.getCalls)
	}
}

func TestClientCall_InvalidInput(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	c, err := Dial(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	// The fixture consumer's "owner" input pattern is [A-Za-z0-9._-]+ — a
	// space is not in that alphabet.
	resp, err := c.Call("tea.repos-list", map[string]string{"owner": "not valid"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != StatusInvalid {
		t.Fatalf("got status %s, want INVALID", resp.Status)
	}
}

func TestClientCall_UnknownOperationLooksLikeDenied(t *testing.T) {
	// Enumeration safety, from the client's perspective: an unauthorized
	// caller asking for an operation that doesn't exist gets exactly the
	// same DENIED a real-but-unauthorized operation would — see
	// session_test.go's TestAcceptance_EnumerationSafety_* for the
	// server-side property this exercises via the public Client API.
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: unauthorizedTestUID})
	defer startServing(t, srv)()

	c, err := Dial(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Call("tea.does-not-exist", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != StatusDenied {
		t.Fatalf("got status %s, want DENIED", resp.Status)
	}
}

func TestClientCall_SecondCallOnSameClientRefused(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	c, err := Dial(srv.cfg.SocketPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Call("tea.repos-list", map[string]string{"owner": "acme"}); err != nil {
		t.Fatalf("first Call: %v", err)
	}
	if _, err := c.Call("tea.repos-list", map[string]string{"owner": "acme"}); err == nil {
		t.Error("second Call on the same Client should be refused — SERVICE-PROTOCOL.md is one request per connection")
	}
}

func TestDial_NoBrokerListening(t *testing.T) {
	if _, err := Dial(t.TempDir() + "/no-such-socket"); err == nil {
		t.Error("Dial against a socket path with nothing listening should fail")
	}
}
