package broker

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// clientDialTimeout, clientWriteTimeout and clientReadTimeout bound how long
// a Client will wait for each phase of a single exchange. There is no
// protocol-level requirement to be generous here — SERVICE-PROTOCOL.md's own
// framing bounds are far tighter (a 5s request read timeout on the broker
// side); these exist so a client hung against a dead or misbehaving broker
// fails with a clear error instead of blocking a caller forever.
const (
	clientDialTimeout  = 5 * time.Second
	clientWriteTimeout = 5 * time.Second
	clientReadTimeout  = 35 * time.Second // > the broker's 30s default operation deadline
)

// Client speaks the wire protocol from the far side of the broker's uid
// boundary: it dials the broker's AF_UNIX socket, sends exactly one framed
// Request, and reads exactly one framed Response. SERVICE-PROTOCOL.md's
// framing is deliberately one request per connection ("A client that wants a
// second operation opens a second connection"), so a Client is single-use —
// Call may be called at most once per Dial; a second call returns an error
// naming the first, rather than silently reusing a connection the broker has
// already closed its side of. Callers that need to make several requests
// call Dial again for each one.
type Client struct {
	conn *net.UnixConn
	used bool
}

// Dial opens a connection to the broker listening on socketPath. It does not
// send anything — a connection failure here means the broker is not
// reachable at all (not running, wrong path, permission denied), distinct
// from a protocol-level DENIED/INVALID/etc. that only Call can report.
func Dial(socketPath string) (*Client, error) {
	d := net.Dialer{Timeout: clientDialTimeout}
	conn, err := d.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("dial %s: not a unix socket connection", socketPath)
	}
	return &Client{conn: uc}, nil
}

// Call sends one request for operation with inputs and returns the broker's
// decoded Response. A non-nil error here is a transport-level failure — the
// connection broke, the response frame was malformed, the broker sent a
// protocol version this client doesn't understand echoed back oddly — never
// a protocol-level refusal, which arrives as a normal (non-nil) *Response
// with Status other than StatusOK. Callers must inspect Response.Status,
// not just check for a nil error, to know whether the operation actually
// succeeded.
func (c *Client) Call(operation string, inputs map[string]string) (*Response, error) {
	if c.used {
		return nil, fmt.Errorf("client already used for one call — SERVICE-PROTOCOL.md is one request per connection; Dial again for another")
	}
	c.used = true

	req := Request{Protocol: ProtocolVersion, Operation: operation, Inputs: inputs}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(clientWriteTimeout)); err != nil {
		return nil, fmt.Errorf("set write deadline: %w", err)
	}
	if err := writeFrame(c.conn, body); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	if err := c.conn.SetReadDeadline(time.Now().Add(clientReadTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	// MaxResponseBytes bounds a consumer's captured stdout before
	// canonicalization (see protocol.go); the framed response itself is a
	// JSON envelope around that, plus protocol/status/error fields, so a
	// generous margin avoids the client itself becoming the bottleneck on a
	// response the broker was willing to send.
	respBody, err := readFrame(c.conn, uint32(MaxResponseBytes+4096))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &resp, nil
}

// Close closes the underlying connection. Safe to call more than once.
func (c *Client) Close() error {
	return c.conn.Close()
}
