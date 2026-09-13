package broker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuditRecord is one request's audit entry: the peer's uid, the requested
// operation string, the decision (the response Status), an outcome code (the
// response Error.Code, empty for OK), the request's duration, and the NAMES
// of any inputs supplied — never their values, and never the credential, on
// any path. SERVICE-PROTOCOL.md, "Audit": "The names of the inputs are
// recorded; their values are not, because an input value is client-supplied
// data whose sensitivity the broker cannot judge."
type AuditRecord struct {
	Time       time.Time
	PeerUID    uint32
	Operation  string
	Decision   string
	Outcome    string
	Duration   time.Duration
	InputNames []string
}

// AuditWriter appends audit records durably. Unlike internal/policy's
// writeAudit (best-effort, never reports failure — appropriate for a CLI
// advisory log), this MUST be able to report a write failure: the
// audit-before-respond rule (session.go) means an otherwise-successful
// request is never answered OK unless its audit record was durably written
// first, which is only enforceable if Write can fail loudly.
type AuditWriter interface {
	Write(rec AuditRecord) error
}

// fileAuditWriter appends one tab-delimited line per record to a file, in
// the append-only, 0700-dir/0600-file style of internal/policy's writeAudit,
// but exported, fallible, and fsync'd — the durability audit-before-respond
// depends on.
type fileAuditWriter struct {
	path string
}

// newFileAuditWriter returns an AuditWriter appending to path, creating its
// parent directory (0700) if needed.
func newFileAuditWriter(path string) (*fileAuditWriter, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create %s: %w", dir, err)
	}
	return &fileAuditWriter{path: path}, nil
}

func (w *fileAuditWriter) Write(rec AuditRecord) error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", w.path, err)
	}
	defer f.Close()

	names := "-"
	if len(rec.InputNames) > 0 {
		names = strings.Join(rec.InputNames, ",")
	}
	line := fmt.Sprintf("%s\tuid=%d\toperation=%s\tdecision=%s\toutcome=%s\tduration=%s\tinputs=%s\n",
		rec.Time.Format(time.RFC3339Nano), rec.PeerUID, orDash(rec.Operation), orDash(rec.Decision), orDash(rec.Outcome), rec.Duration, names)
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("audit: write %s: %w", w.path, err)
	}
	// Sync so the record is durable before the caller is allowed to tell the
	// client OK -- an unsynced write that is lost on crash is indistinguishable
	// from one never attempted, which is exactly the gap audit-before-respond
	// closes.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("audit: sync %s: %w", w.path, err)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
