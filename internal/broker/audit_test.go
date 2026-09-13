package broker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAuditWriter is an in-memory AuditWriter for tests. Setting failNext
// makes the next Write call fail without recording the record — used by
// session_test.go's audit-before-respond tests. handleConn runs each
// connection on its own goroutine, so this type must itself be safe for
// concurrent use even though most tests only ever exercise one connection at
// a time; Records() is the safe way for a test to inspect what was written.
type fakeAuditWriter struct {
	mu       sync.Mutex
	records  []AuditRecord
	failNext bool
}

func (w *fakeAuditWriter) Write(rec AuditRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failNext {
		w.failNext = false
		return errors.New("fake audit write failure")
	}
	w.records = append(w.records, rec)
	return nil
}

// Records returns a snapshot of the records written so far.
func (w *fakeAuditWriter) Records() []AuditRecord {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]AuditRecord(nil), w.records...)
}

// --- fileAuditWriter ---------------------------------------------------------

func TestFileAuditWriterCreatesDirAndFileWithRestrictivePerms(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "audit-subdir", "audit.log")

	w, err := newFileAuditWriter(path)
	if err != nil {
		t.Fatalf("newFileAuditWriter: %v", err)
	}
	rec := AuditRecord{
		Time:       time.Now(),
		PeerUID:    1000,
		Operation:  "tea.repos-list",
		Decision:   StatusOK,
		Duration:   5 * time.Millisecond,
		InputNames: []string{"owner"},
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("audit dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Errorf("audit file mode = %o, want 0600", fileInfo.Mode().Perm())
	}
}

func TestFileAuditWriterAppendsMultipleRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := newFileAuditWriter(path)
	if err != nil {
		t.Fatalf("newFileAuditWriter: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Write(AuditRecord{Time: time.Now(), PeerUID: uint32(1000 + i), Operation: "tea.repos-list", Decision: StatusOK}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("audit log has %d lines, want 3: %q", len(lines), data)
	}
}

func TestFileAuditWriterRecordsNamesNotValues(t *testing.T) {
	// The type itself only carries names (AuditRecord.InputNames []string),
	// not a map of name->value -- this test confirms the writer faithfully
	// records exactly the names given and introduces no value field of its
	// own; the real guarantee that only names ever reach the AuditRecord in
	// the first place is session.go's responsibility, exercised in
	// session_test.go's acceptance suite.
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := newFileAuditWriter(path)
	if err != nil {
		t.Fatalf("newFileAuditWriter: %v", err)
	}
	if err := w.Write(AuditRecord{Time: time.Now(), PeerUID: 1000, Operation: "tea.repos-list", Decision: StatusOK, InputNames: []string{"owner"}}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "inputs=owner") {
		t.Errorf("audit log should record the input name %q, got: %q", "owner", data)
	}
}

func TestFileAuditWriterFailsOnUnwritableDir(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(base, 0o700) }) // let t.TempDir() clean up
	path := filepath.Join(base, "nested", "audit.log")

	if _, err := newFileAuditWriter(path); err == nil {
		t.Fatal("newFileAuditWriter: expected an error creating a directory under a read-only parent, got none")
	}
}

// --- fakeAuditWriter ---------------------------------------------------------

func TestFakeAuditWriterFailNext(t *testing.T) {
	w := &fakeAuditWriter{}
	w.failNext = true
	if err := w.Write(AuditRecord{}); err == nil {
		t.Fatal("fakeAuditWriter: expected the flagged write to fail")
	}
	if len(w.records) != 0 {
		t.Errorf("fakeAuditWriter: a failed write must not record anything, got %d records", len(w.records))
	}
	if err := w.Write(AuditRecord{PeerUID: 42}); err != nil {
		t.Fatalf("fakeAuditWriter: subsequent write should succeed: %v", err)
	}
	if len(w.records) != 1 {
		t.Errorf("fakeAuditWriter: got %d records, want 1", len(w.records))
	}
}
