package broker

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- happy path --------------------------------------------------------------

func TestAcceptance_OK_ReposList(t *testing.T) {
	authzPath := testEnv(t)
	srv, st := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "acme"}})
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
	if st.getCalls == 0 {
		t.Error("expected the store to have been queried for the credential on a successful request")
	}
}

// --- enumeration safety --------------------------------------------------

func TestAcceptance_UnauthorizedDenied_NoCredentialFetched(t *testing.T) {
	authzPath := testEnv(t)
	srv, st := newTestServer(t, authzPath, testServerOpts{peerUID: unauthorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "acme"}})
	if resp.Status != StatusDenied {
		t.Fatalf("got status %s, want DENIED", resp.Status)
	}
	if st.getCalls != 0 {
		t.Errorf("credential must never be fetched on a denied request; store.Get was called %d times", st.getCalls)
	}
}

func TestAcceptance_EnumerationSafety_ExistingVsNonexistentOperationLookTheSameWhenDenied(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: unauthorizedTestUID})
	defer startServing(t, srv)()

	respReal := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list"})
	respGhost := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.does-not-exist"})

	realJSON, _ := json.Marshal(respReal)
	ghostJSON, _ := json.Marshal(respGhost)
	if !bytes.Equal(realJSON, ghostJSON) {
		t.Errorf("an unauthorized peer must not be able to distinguish an existing operation from a nonexistent one:\n  real:  %s\n  ghost: %s", realJSON, ghostJSON)
	}
	if respReal.Status != StatusDenied {
		t.Errorf("got status %s, want DENIED", respReal.Status)
	}
}

// --- malformed / syntax ----------------------------------------------------

func TestAcceptance_UnknownFieldRejected(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRawRequest(t, srv, []byte(`{"protocol":1,"operation":"tea.repos-list","executable":"/bin/sh"}`))
	if resp.Status != StatusInvalid || resp.Error == nil || resp.Error.Code != CodeMalformedRequest {
		t.Errorf("got %+v, want INVALID/malformed_request", resp)
	}
}

func TestAcceptance_MalformedOperationSyntaxRejected(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	for _, op := range []string{"get", "mount", "tea", "tea.", ".repos-list"} {
		resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: op})
		if resp.Status != StatusInvalid || resp.Error == nil || resp.Error.Code != CodeMalformedRequest {
			t.Errorf("operation %q: got %+v, want INVALID/malformed_request", op, resp)
		}
	}
}

func TestAcceptance_UnsupportedProtocolRejected(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: 99, Operation: "tea.repos-list"})
	if resp.Status != StatusInvalid || resp.Error == nil || resp.Error.Code != CodeUnsupportedProtocol {
		t.Errorf("got %+v, want INVALID/unsupported_protocol", resp)
	}
}

// --- input validation --------------------------------------------------

func TestAcceptance_InvalidInputRejected_NoCredentialFetched(t *testing.T) {
	authzPath := testEnv(t)
	srv, st := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "-leading-dash"}})
	if resp.Status != StatusInvalid || resp.Error == nil || resp.Error.Code != CodeInvalidInput {
		t.Fatalf("got %+v, want INVALID/invalid_input", resp)
	}
	if st.getCalls != 0 {
		t.Errorf("credential must never be fetched on an invalid-input request; store.Get was called %d times", st.getCalls)
	}
	if strings.Contains(resp.Error.Message, "-leading-dash") {
		t.Errorf("invalid_input message must never echo the client's value back, got: %s", resp.Error.Message)
	}
}

func TestAcceptance_UnknownInputRejected(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "acme", "extra": "x"}})
	if resp.Status != StatusInvalid || resp.Error == nil || resp.Error.Code != CodeInvalidInput {
		t.Errorf("got %+v, want INVALID/invalid_input for an undeclared input", resp)
	}
}

// --- consumer/response failures --------------------------------------------

func TestAcceptance_ConsumerFailed_NonzeroExit(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "failing"}})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeConsumerFailed {
		t.Errorf("got %+v, want ERROR/consumer_failed", resp)
	}
}

func TestAcceptance_ConsumerFailed_MalformedShape(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "malformed"}})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeConsumerFailed {
		t.Errorf("got %+v, want ERROR/consumer_failed", resp)
	}
}

func TestAcceptance_ConsumerFailed_TrailingData(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "trailing"}})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeConsumerFailed {
		t.Errorf("got %+v, want ERROR/consumer_failed", resp)
	}
}

func TestAcceptance_ResultTooLarge(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "huge"}})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeResultTooLarge {
		t.Errorf("got %+v, want ERROR/result_too_large", resp)
	}
}

func TestAcceptance_Timeout(t *testing.T) {
	authzPath := testEnv(t)
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "slow"}})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeTimeout {
		t.Errorf("got %+v, want ERROR/timeout", resp)
	}
}

// --- no credential leakage, across every path -------------------------------

func TestAcceptance_NoCredentialLeakage(t *testing.T) {
	scenarios := []struct {
		name  string
		peer  uint32
		owner string
	}{
		{"ok", authorizedTestUID, "acme"},
		{"denied", unauthorizedTestUID, "acme"},
		{"invalid-input", authorizedTestUID, "-bad"},
		{"consumer-failed", authorizedTestUID, "failing"},
		{"malformed-shape", authorizedTestUID, "malformed"},
		{"trailing", authorizedTestUID, "trailing"},
		{"too-large", authorizedTestUID, "huge"},
		{"timeout", authorizedTestUID, "slow"},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			authzPath := testEnv(t)
			var logBuf bytes.Buffer
			auditW := &fakeAuditWriter{}
			srv, _ := newTestServer(t, authzPath, testServerOpts{
				peerUID: sc.peer,
				auditW:  auditW,
				logger:  log.New(&logBuf, "", 0),
			})
			defer startServing(t, srv)()

			resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": sc.owner}})

			respJSON, _ := json.Marshal(resp)
			if strings.Contains(string(respJSON), testCredentialValue) {
				t.Errorf("response must never contain the credential, got: %s", respJSON)
			}
			for _, rec := range auditW.Records() {
				if strings.Contains(rec.Operation, testCredentialValue) {
					t.Error("audit record's Operation field must never contain the credential")
				}
				for _, n := range rec.InputNames {
					if strings.Contains(n, testCredentialValue) {
						t.Error("audit record's InputNames must never contain the credential")
					}
				}
			}
			if strings.Contains(logBuf.String(), testCredentialValue) {
				t.Errorf("diagnostic log must never contain the credential, got: %s", logBuf.String())
			}
		})
	}
}

// --- unconditional runtime-dir cleanup ---------------------------------------

func TestAcceptance_RuntimeDirCleanedUpOnEveryPath(t *testing.T) {
	scenarios := []string{"acme", "failing", "malformed", "trailing", "huge", "slow"}
	for _, owner := range scenarios {
		t.Run(owner, func(t *testing.T) {
			authzPath := testEnv(t)
			srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID})
			defer startServing(t, srv)()

			doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": owner}})

			runtimeBase := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "parzival")
			entries, err := os.ReadDir(runtimeBase)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("read runtime base: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("runtime dir %s has %d leftover entries after the request, want 0: %v", runtimeBase, len(entries), entries)
			}
		})
	}
}

// --- audit-before-respond ---------------------------------------------------

func TestAcceptance_AuditBeforeRespond_OKDowngradesToUnavailableOnAuditFailure(t *testing.T) {
	authzPath := testEnv(t)
	auditW := &fakeAuditWriter{failNext: true}
	srv, st := newTestServer(t, authzPath, testServerOpts{peerUID: authorizedTestUID, auditW: auditW})
	defer startServing(t, srv)()

	resp := doRequest(t, srv, Request{Protocol: ProtocolVersion, Operation: "tea.repos-list", Inputs: map[string]string{"owner": "acme"}})
	if resp.Status != StatusUnavailable {
		t.Fatalf("got status %s, want UNAVAILABLE when the audit write for an otherwise-OK request fails", resp.Status)
	}
	if resp.Error == nil || resp.Error.Code != CodeBrokerUnavailable {
		t.Errorf("got error %+v, want broker_unavailable", resp.Error)
	}
	// The operation itself still ran (the consumer already executed by the
	// time the audit write is attempted) -- this is not a rollback, only a
	// refusal to positively report success without a durable record.
	if st.getCalls == 0 {
		t.Error("the consumer operation should still have run before the audit write was attempted")
	}
}

func TestAcceptance_AuditWrittenForDeniedRequestEvenIfClientNeverReadsResponse(t *testing.T) {
	authzPath := testEnv(t)
	auditW := &fakeAuditWriter{}
	srv, _ := newTestServer(t, authzPath, testServerOpts{peerUID: unauthorizedTestUID, auditW: auditW})
	defer startServing(t, srv)()

	// Send the request, then close the connection immediately without
	// reading the response -- the audit write must not be contingent on the
	// client-facing write (or the client sticking around) succeeding.
	conn := dialRaw(t, srv)
	body, _ := json.Marshal(Request{Protocol: ProtocolVersion, Operation: "tea.repos-list"})
	if err := writeFrame(conn, body); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	conn.Close()

	// Give the handler goroutine a moment to finish (Serve's own shutdown
	// wait, exercised by the deferred stop() below, guarantees this by the
	// time the test function returns; poll briefly here as a speed-up).
	waitForCondition(t, func() bool { return len(auditW.Records()) > 0 })

	records := auditW.Records()
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	if records[0].Decision != StatusDenied {
		t.Errorf("got decision %s, want DENIED", records[0].Decision)
	}
}
