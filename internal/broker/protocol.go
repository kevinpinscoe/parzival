// Package broker implements the parzival broker service protocol
// (SERVICE-PROTOCOL.md): a Linux daemon that lets an untrusted client use a
// brokered credential without ever being able to read it. See
// SERVICE-PROTOCOL.md for the wire format this package implements, and
// THREAT-MODEL.md §4d for the boundary it is one component of — a correct
// implementation of the protocol running as the same uid as its client
// enforces nothing.
//
// As of this writing it serves exactly one operation, tea.repos-list — not
// the full protocol surface SERVICE-PROTOCOL.md specifies. The daemon is
// packaged (systemd unit, dedicated service account, sysusers.d) and the
// agent-facing client lives in cmd/parzival's service subcommand.
package broker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ProtocolVersion is the wire-protocol version this broker implements. A
// request naming any other version is refused (INVALID/unsupported_protocol)
// rather than served on a best-effort basis — SERVICE-PROTOCOL.md,
// "Versioning".
const ProtocolVersion = 1

// Framing bounds, from SERVICE-PROTOCOL.md's "Framing" table. MaxResponseBytes
// bounds a consumer's captured stdout (enforced in launcher.go, per "Serving
// one request" step 10) rather than the final framed response, which is
// ordinarily far smaller once canonicalized.
const (
	MaxRequestBytes  = 64 * 1024   // 64 KiB
	MaxResponseBytes = 1024 * 1024 // 1 MiB
)

// Request is one client request, exactly as SERVICE-PROTOCOL.md's "Request"
// section defines it. There is deliberately no field for an executable, a
// profile, a path, an environment variable, a file descriptor, a delivery
// mode, a timeout, an identity, or a raw flag — see that section for why none
// of those may ever be added here.
type Request struct {
	Protocol  int               `json:"protocol"`
	Operation string            `json:"operation"`
	Inputs    map[string]string `json:"inputs,omitempty"`
}

// Response is one broker response, exactly as SERVICE-PROTOCOL.md's
// "Response" section defines it.
type Response struct {
	Protocol int             `json:"protocol"`
	Status   string          `json:"status"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *ErrorBody      `json:"error,omitempty"`
}

// ErrorBody is a bounded code and a message drawn from a fixed set of
// phrasings — SERVICE-PROTOCOL.md, "What a response may never contain": no
// consumer output, no store error string, no OS error, no stack trace. The
// one relaxation is invalid_input, which may name the client's own input and
// the constraint it failed (never the value) — see errInvalidInput below.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// The status vocabulary is closed — SERVICE-PROTOCOL.md, "The status
// vocabulary is closed". A sixth value is not added without asking what it
// discloses.
const (
	StatusOK          = "OK"
	StatusDenied      = "DENIED"
	StatusInvalid     = "INVALID"
	StatusError       = "ERROR"
	StatusUnavailable = "UNAVAILABLE"
)

// Error codes — SERVICE-PROTOCOL.md, "Error codes".
//
// CodeUnknownOperation is defined for wire-format completeness (the document
// still names it) but this stage's session.go never produces it: enumeration
// safety requires authorization to be decided before a client learns whether
// an operation resolves at all (see session.go), so an unauthorized client
// always sees DENIED regardless of existence, and an authorized client whose
// operation still fails to resolve indicates a broker configuration
// inconsistency, answered UNAVAILABLE — never INVALID/unknown_operation,
// which would disclose something about broker internals to a client that has
// no legitimate need for it.
const (
	CodeUnsupportedProtocol = "unsupported_protocol"
	CodeMalformedRequest    = "malformed_request"
	CodeUnknownOperation    = "unknown_operation"
	CodeInvalidInput        = "invalid_input"
	CodeNotAuthorized       = "not_authorized"
	CodeConsumerFailed      = "consumer_failed"
	CodeResultTooLarge      = "result_too_large"
	CodeTimeout             = "timeout"
	CodeBrokerUnavailable   = "broker_unavailable"
)

// Fixed messages for each error code, used verbatim except errInvalidInput's
// carve-out.
const (
	msgUnsupportedProtocol = "unsupported protocol version"
	msgMalformedRequest    = "malformed request"
	msgNotAuthorized       = "operation not permitted for this client"
	msgConsumerFailed      = "operation failed"
	msgResultTooLarge      = "result exceeded the response size bound"
	msgTimeout             = "operation timed out"
	msgBrokerUnavailable   = "broker unavailable"
)

func okResponse(result json.RawMessage) *Response {
	return &Response{Protocol: ProtocolVersion, Status: StatusOK, Result: result}
}

func errResponse(status, code, message string) *Response {
	return &Response{Protocol: ProtocolVersion, Status: status, Error: &ErrorBody{Code: code, Message: message}}
}

func respDenied() *Response { return errResponse(StatusDenied, CodeNotAuthorized, msgNotAuthorized) }

func respMalformed() *Response {
	return errResponse(StatusInvalid, CodeMalformedRequest, msgMalformedRequest)
}

func respUnsupportedProtocol() *Response {
	return errResponse(StatusInvalid, CodeUnsupportedProtocol, msgUnsupportedProtocol)
}

// errInvalidInput names the input and the (value-free) constraint it failed.
// reason must never contain the client's supplied value — every caller of
// this function passes an error from consumer.BuildArgv, whose own input
// -validation errors are already written without echoing the value back (see
// internal/consumer, Input.check and BuildArgv's doc comments).
func respInvalidInput(reason string) *Response {
	return errResponse(StatusInvalid, CodeInvalidInput, "invalid input: "+reason)
}

func respConsumerFailed() *Response {
	return errResponse(StatusError, CodeConsumerFailed, msgConsumerFailed)
}

func respResultTooLarge() *Response {
	return errResponse(StatusError, CodeResultTooLarge, msgResultTooLarge)
}

func respTimeout() *Response { return errResponse(StatusError, CodeTimeout, msgTimeout) }

func respUnavailable() *Response {
	return errResponse(StatusUnavailable, CodeBrokerUnavailable, msgBrokerUnavailable)
}

// operationRE matches a syntactically valid qualified operation reference,
// "<consumer>.<operation>" — the same name shape internal/consumer enforces
// for a consumer or operation name on its own (nameRE there), joined by one
// literal dot. This is a pure syntax check: it says nothing about whether
// either half is actually configured, which is exactly what makes it safe to
// apply before authorization without becoming an existence oracle.
var operationRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9_-]*$`)

// splitOperationRef splits a syntactically valid qualified operation
// reference into its consumer and operation halves. ok is false if s does
// not match the required shape.
func splitOperationRef(s string) (consumerName, opName string, ok bool) {
	if !operationRE.MatchString(s) {
		return "", "", false
	}
	i := strings.IndexByte(s, '.')
	return s[:i], s[i+1:], true
}

// decodeExactlyOne decodes exactly one JSON value from data into v, refusing
// any non-whitespace trailing content. Whitespace-only trailing content is
// explicitly valid.
//
// json.Decoder.More() is the wrong tool for this: it reports whether another
// element follows within the array or object currently being parsed, and at
// the top level — after a complete value — it returns false for a lone
// unmatched '}' or ']', exactly the kind of trailing garbage this check
// exists to catch. The correct pattern is to attempt a second Decode and
// require io.EOF.
func decodeExactlyOne(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var discard json.RawMessage
	if err := dec.Decode(&discard); err != io.EOF {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}

// decodeRequest strictly decodes one Request from a frame body. Unknown
// field or trailing data is a decode error — SERVICE-PROTOCOL.md, "Unknown
// fields are refused, not ignored".
func decodeRequest(body []byte) (*Request, error) {
	var req Request
	if err := decodeExactlyOne(body, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// readFrame reads one length-prefixed message from r, enforcing max as the
// maximum body length. A declared length exceeding max is refused before any
// body bytes are read, so a lying length prefix cannot force a large
// allocation.
func readFrame(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > max {
		return nil, fmt.Errorf("frame length %d exceeds bound %d", n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	return body, nil
}

// writeFrame writes one length-prefixed message to w. It trusts its caller to
// have bounded body's size; the framing layer itself performs no size policy
// beyond what fits in the uint32 length prefix.
func writeFrame(w io.Writer, body []byte) error {
	if uint64(len(body)) > 0xFFFFFFFF {
		return fmt.Errorf("frame body too large: %d bytes", len(body))
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// writeResponse marshals and frames resp.
func writeResponse(w io.Writer, resp *Response) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	return writeFrame(w, body)
}
