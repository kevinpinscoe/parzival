package broker

import (
	"context"
	"net"
	"sort"
	"time"

	"github.com/kevinpinscoe/parzival/internal/consumer"
	"github.com/kevinpinscoe/parzival/internal/ephemeral"
	"github.com/kevinpinscoe/parzival/internal/secret"
)

// handleConn serves exactly one request on conn, per SERVICE-PROTOCOL.md's
// "Serving one request" sequence — corrected for enumeration safety
// (authorization is decided against the requested operation STRING before
// resolution against loaded definitions is ever attempted, so an
// unauthorized peer cannot learn whether an operation exists by comparing
// DENIED against INVALID) and for audit-before-respond (an OK response is
// never sent unless its audit record was durably written first; every other
// response is still audited unconditionally, regardless of whether the
// subsequent client write succeeds).
func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	start := s.now()
	rec := AuditRecord{Time: start}

	// Step 1: peer credentials, read from the kernel. If this fails we do
	// not know who we might be answering, so close without a response and
	// without an audit record naming an unverified uid.
	uid, err := s.peer(conn)
	if err != nil {
		s.log.Printf("peer credentials: %v", err)
		return
	}
	rec.PeerUID = uid

	// Step 2: bounded, timed read of the framed request.
	conn.SetReadDeadline(start.Add(s.cfg.ReadTimeout))
	raw, err := readFrame(conn, uint32(s.cfg.MaxRequestBytes))
	if err != nil {
		// Oversized or timed out: close, no response — SERVICE-PROTOCOL.md's
		// framing bounds table.
		return
	}

	// Step 3: strict decode.
	req, err := decodeRequest(raw)
	if err != nil {
		s.finish(conn, start, rec, respMalformed())
		return
	}
	rec.Operation = req.Operation
	rec.InputNames = sortedInputNames(req.Inputs)

	if req.Protocol <= 0 {
		s.finish(conn, start, rec, respMalformed())
		return
	}
	if req.Protocol != ProtocolVersion {
		s.finish(conn, start, rec, respUnsupportedProtocol())
		return
	}
	if req.Operation == "" {
		s.finish(conn, start, rec, respMalformed())
		return
	}

	// Step 4: syntax-only check on the operation string. This says nothing
	// about whether the name resolves to anything configured, which is
	// exactly what makes it safe to apply before authorization.
	consumerName, opName, ok := splitOperationRef(req.Operation)
	if !ok {
		s.finish(conn, start, rec, respMalformed())
		return
	}

	// Step 5: authorize the uid against the operation STRING, before
	// resolution is ever attempted. DENIED is identical whether or not the
	// operation actually exists — that is the whole enumeration-safety
	// point. No credential is touched on this path.
	if !s.authz.Decide(uid, req.Operation) {
		s.finish(conn, start, rec, respDenied())
		return
	}

	// Step 6: resolve, only now that authorization has already succeeded.
	def, defOK := s.defs[consumerName]
	var op consumer.Operation
	if defOK {
		op, ok = def.Operations[opName]
	} else {
		ok = false
	}
	if !ok {
		// AuthzFile.Validate already proved at startup that every
		// authorized operation string resolves against the loaded
		// definitions. Reaching here means the broker's own state is
		// inconsistent with what it verified at startup — not a bad client
		// request. Logged loudly; answered UNAVAILABLE, never
		// INVALID/unknown_operation, which would disclose something to a
		// client that is already authorized for this string and has no
		// legitimate need to learn more about broker internals.
		s.log.Printf("invariant violation: uid %d authorized for %q but it does not resolve against loaded definitions", uid, req.Operation)
		s.finish(conn, start, rec, respUnavailable())
		return
	}

	// Step 7: validate inputs, build argv. Still no credential touched.
	argv, err := def.BuildArgv(opName, req.Inputs)
	if err != nil {
		s.finish(conn, start, rec, respInvalidInput(err.Error()))
		return
	}

	opCtx, cancel := context.WithTimeout(ctx, opTimeout(op, s.cfg.DefaultOpTimeout))
	defer cancel()

	// Step 8: fetch the credential, using the broker's own store auth.
	prof := s.profiles[def.Profile]
	secrets, err := s.fetchSecrets(opCtx, prof)
	if err != nil {
		s.log.Printf("fetch secrets for %q: %v", req.Operation, err)
		s.finish(conn, start, rec, respUnavailable())
		return
	}
	defer zeroAll(secrets)

	rendered, err := prof.Render(secrets)
	if err != nil {
		s.log.Printf("render profile for %q: %v", req.Operation, err)
		s.finish(conn, start, rec, respUnavailable())
		return
	}
	defer secret.Zero(rendered)

	// Step 9: broker-private runtime directory.
	dir, err := ephemeral.New()
	if err != nil {
		s.log.Printf("create runtime dir for %q: %v", req.Operation, err)
		s.finish(conn, start, rec, respUnavailable())
		return
	}
	// Registered as a panic/early-return safety net only — Cleanup is
	// idempotent. The real cleanup (step 12) is synchronous and explicit,
	// below, because it must precede the response write and this defer only
	// fires after handleConn returns, i.e. after conn.Write.
	defer dir.Cleanup()

	credPath, err := dir.WriteFile(prof.Inject.FileName(), rendered)
	if err != nil {
		s.log.Printf("write rendered profile for %q: %v", req.Operation, err)
		dir.Cleanup()
		s.finish(conn, start, rec, respUnavailable())
		return
	}

	// Step 10: execute, never through a shell, with a newly constructed
	// minimal environment — never the client's, never the broker's own.
	env := minimalEnv(dir.Path(), prof.Inject, credPath, dir.Path())
	result := runConsumer(opCtx, argv, env, s.cfg.MaxResponseBytes)

	// Step 11: validate and canonicalize the result. Never a raw passthrough
	// of consumer stdout.
	resp := classify(req.Operation, op, result)

	// Step 12: synchronous cleanup, BEFORE the response is built/sent — the
	// protocol requires removal to precede the write.
	dir.Cleanup()

	// Steps 13-15: audit, then respond — handled by finish, which for an OK
	// response downgrades to UNAVAILABLE if the audit write itself fails,
	// and for every other response still writes the audit record
	// unconditionally.
	s.finish(conn, start, rec, resp)
}

// finish is handleConn's single terminal step. For an OK response the audit
// write happens BEFORE the client ever sees OK, and a failed audit write
// downgrades the response to UNAVAILABLE rather than ever claiming success
// without a durable record of it (this has no rollback implication for the
// consumer operation, which already ran — the point is narrower: never
// positively report an operation whose audit record does not exist). For
// every other status the audit write still happens here, unconditionally —
// not contingent on whether the subsequent client write succeeds.
func (s *Server) finish(conn *net.UnixConn, start time.Time, rec AuditRecord, resp *Response) {
	rec.Duration = s.now().Sub(start)
	rec.Decision = resp.Status
	if resp.Error != nil {
		rec.Outcome = resp.Error.Code
	}

	if err := s.audit.Write(rec); err != nil {
		s.log.Printf("audit write failed (uid=%d op=%q decision=%s): %v", rec.PeerUID, rec.Operation, rec.Decision, err)
		if resp.Status == StatusOK {
			resp = respUnavailable()
		}
	}

	if err := writeResponse(conn, resp); err != nil {
		s.log.Printf("write response (uid=%d op=%q decision=%s): %v", rec.PeerUID, rec.Operation, resp.Status, err)
	}
}

// classify turns a launchResult into the closed-vocabulary response,
// applying the approved response validator for name — never forwarding raw
// consumer stdout. Exit status is checked before output shape/size, matching
// the error table's own ordering: a nonzero exit is consumer_failed
// regardless of what stdout held.
func classify(name string, op consumer.Operation, result *launchResult) *Response {
	if result.timedOut {
		return respTimeout()
	}
	if result.exitErr != nil {
		return respConsumerFailed()
	}
	if result.truncated {
		return respResultTooLarge()
	}
	validator, err := validatorFor(name, op)
	if err != nil {
		// Unreachable in practice: New refuses to start if any declared
		// operation lacks a registered validator or carries response_config
		// that validator does not accept. Treated as a consumer
		// failure rather than a panic, for the same "fail closed, not
		// loudly broken" reasoning as the rest of this file.
		return respConsumerFailed()
	}
	canonical, err := validator(result.stdout)
	if err != nil {
		return respConsumerFailed()
	}
	return okResponse(canonical)
}

// opTimeout returns op's declared timeout, or def if op declares none.
func opTimeout(op consumer.Operation, def time.Duration) time.Duration {
	if op.TimeoutSeconds > 0 {
		return time.Duration(op.TimeoutSeconds) * time.Second
	}
	return def
}

// sortedInputNames returns the names (never the values) of a request's
// inputs, sorted for deterministic audit records.
func sortedInputNames(inputs map[string]string) []string {
	if len(inputs) == 0 {
		return nil
	}
	names := make([]string, 0, len(inputs))
	for k := range inputs {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
