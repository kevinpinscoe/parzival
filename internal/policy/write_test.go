package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// samplePolicy is a small, valid policy used wherever a test needs one and does
// not care about its contents.
func samplePolicy() *Policy {
	return &Policy{Schema: SchemaVersion, Rules: []Rule{
		deny([]string{"bao:prod/*"}, nil, nil),
		allow([]string{"bao:app/gitea#*"}, []string{"ai"}, []string{ModeExec, ModeMount}),
	}}
}

// writeLive puts a policy at path directly, standing in for whatever was there
// before a test's edit.
func writeLive(t *testing.T, path string, p *Policy) {
	t.Helper()
	data, err := Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestWriteAtomicInstallsWithOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := WriteAtomic(path, samplePolicy()); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != FileMode {
		t.Errorf("mode = %04o, want %04o", perm, FileMode)
	}

	// The installed file must load through the production parser, not merely
	// exist.
	got, exists, err := LoadFile(path)
	if err != nil || !exists {
		t.Fatalf("installed policy does not load: exists=%v err=%v", exists, err)
	}
	if len(got.Rules) != 2 {
		t.Errorf("loaded %d rules, want 2", len(got.Rules))
	}
}

func TestWriteAtomicLeavesNoTemporaryFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := WriteAtomic(path, samplePolicy()); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "policy.json" {
			t.Errorf("left behind %s", e.Name())
		}
	}
}

func TestWriteAtomicRefusesAPolicyItCouldNotLoadBack(t *testing.T) {
	// An in-memory policy can hold a value the parser rejects. Installing it
	// would leave a file this binary declines to load, denying every fetch on
	// the host — so the write is refused before anything is touched.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeLive(t, path, samplePolicy())

	bad := &Policy{Schema: SchemaVersion, Rules: []Rule{
		{Allow: true, Secrets: []string{"bao:app/x#token"}, Hours: "not-a-window"},
	}}
	if err := WriteAtomic(path, bad); err == nil {
		t.Fatal("an unloadable policy was installed")
	}

	// The live file must be exactly what it was.
	got, _, err := LoadFile(path)
	if err != nil {
		t.Fatalf("the live policy was damaged: %v", err)
	}
	if len(got.Rules) != 2 {
		t.Errorf("live policy now has %d rules, want the original 2", len(got.Rules))
	}
}

func TestBackupCapturesTheExactPreChangeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	original := samplePolicy()
	writeLive(t, path, original)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	name, err := Backup(path)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if name == "" {
		t.Fatal("Backup returned no name for an existing file")
	}
	if !strings.Contains(filepath.Base(name), ".bak.") {
		t.Errorf("backup name %q does not carry a .bak. marker", name)
	}

	// Change the live policy afterwards; the backup must not follow it.
	updated, _ := original.InsertRule(allow([]string{"bao:app/new#token"}, []string{"ai"}, []string{ModeExec}), 0)
	if err := WriteAtomic(path, updated); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	kept, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(kept) != string(before) {
		t.Error("the backup does not hold the exact pre-change policy")
	}
}

func TestBackupNeverOverwritesAnExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeLive(t, path, samplePolicy())

	first, err := Backup(path)
	if err != nil {
		t.Fatalf("first Backup: %v", err)
	}
	// A second backup within the same second must not reuse the first's name —
	// the case the whole scheme exists for is a bad edit noticed later, by which
	// time a reused filename has already lost the good copy.
	second, err := Backup(path)
	if err != nil {
		t.Fatalf("second Backup: %v", err)
	}
	if first == second {
		t.Fatalf("both backups landed on %s", first)
	}
	for _, n := range []string{first, second} {
		if _, err := os.Stat(n); err != nil {
			t.Errorf("backup %s is missing: %v", n, err)
		}
	}
}

func TestBackupOfAMissingPolicyIsNotAnError(t *testing.T) {
	// The first grant on a host with no policy file is a legitimate first edit.
	name, err := Backup(filepath.Join(t.TempDir(), "policy.json"))
	if err != nil {
		t.Fatalf("Backup of a missing file: %v", err)
	}
	if name != "" {
		t.Errorf("Backup returned %q for a file that does not exist", name)
	}
}

func TestRestorePutsTheBackupBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	original := samplePolicy()
	writeLive(t, path, original)

	name, err := Backup(path)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}

	updated, _ := original.InsertRule(allow([]string{"bao:app/oops#token"}, []string{"ai"}, nil), 0)
	if err := WriteAtomic(path, updated); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := Restore(name, path); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	got, _, err := LoadFile(path)
	if err != nil {
		t.Fatalf("restored policy does not load: %v", err)
	}
	if len(got.Rules) != len(original.Rules) {
		t.Errorf("restored %d rules, want %d", len(got.Rules), len(original.Rules))
	}
}

func TestRestoreRefusesACorruptBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeLive(t, path, samplePolicy())

	bad := filepath.Join(dir, "policy.json.bak.corrupt")
	if err := os.WriteFile(bad, []byte(`{"rules": [`), FileMode); err != nil {
		t.Fatalf("write corrupt backup: %v", err)
	}
	if err := Restore(bad, path); err == nil {
		t.Fatal("a corrupt backup was installed over a working policy")
	}
	if _, _, err := LoadFile(path); err != nil {
		t.Errorf("the live policy was damaged by the refused restore: %v", err)
	}
}

func TestWriteCandidateIsOwnerOnlyAndLoads(t *testing.T) {
	dir := t.TempDir()
	name, err := WriteCandidate(dir, samplePolicy())
	if err != nil {
		t.Fatalf("WriteCandidate: %v", err)
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatalf("stat candidate: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != FileMode {
		t.Errorf("candidate mode = %04o, want %04o", perm, FileMode)
	}
	if _, exists, err := LoadFile(name); err != nil || !exists {
		t.Errorf("candidate does not load: exists=%v err=%v", exists, err)
	}
	if !strings.Contains(filepath.Base(name), "parzival-policy-candidate-") {
		t.Errorf("candidate name %q is not recognisable", name)
	}
}

func TestVerifyInstalledAcceptsTheApprovedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := samplePolicy()
	if err := WriteAtomic(path, p); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := VerifyInstalled(path, p); err != nil {
		t.Errorf("VerifyInstalled rejected the policy it just installed: %v", err)
	}
}

func TestVerifyInstalledRejectsADifferentPolicy(t *testing.T) {
	// "The write returned no error" and "the approved file is on disk" are not
	// the same claim; this is the check that turns one into the other.
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := WriteAtomic(path, samplePolicy()); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	other, _ := samplePolicy().InsertRule(allow([]string{"bao:app/other#token"}, []string{"ai"}, nil), 0)
	if err := VerifyInstalled(path, other); err == nil {
		t.Fatal("VerifyInstalled accepted a policy that is not what was installed")
	}
}

func TestVerifyInstalledRejectsWrongPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := samplePolicy()
	if err := WriteAtomic(path, p); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := VerifyInstalled(path, p)
	if err == nil {
		t.Fatal("VerifyInstalled accepted a world-readable policy")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("the failure does not mention the mode: %v", err)
	}
}

func TestMarshalDoesNotEscapeRefCharacters(t *testing.T) {
	// & < > are legal in a ref and an identity glob. Escaping them would make
	// every diff of an edited policy unreadable, defeating the review step.
	p := &Policy{Schema: SchemaVersion, Rules: []Rule{
		allow([]string{"bao:app/x#a&b<c>d"}, []string{"ai"}, []string{ModeExec}),
	}}
	data, err := Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), "a&b<c>d") {
		t.Errorf("ref characters were escaped:\n%s", data)
	}
}

func TestRoundTripThroughDiskPreservesEveryField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := &Policy{Schema: SchemaVersion, Rules: []Rule{{
		Allow:       true,
		Description: "a rule using every field",
		Secrets:     []string{"bao:app/x#token"},
		Identities:  []string{"agent-*"},
		Modes:       []string{ModeExec, ModeMount},
		Weekdays:    []string{"Mon", "Fri"},
		Monthdays:   []int{1, 15},
		Hours:       "08:00-18:00",
	}}}
	if err := WriteAtomic(path, p); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := VerifyInstalled(path, p); err != nil {
		t.Errorf("a policy using every field did not survive the round trip: %v", err)
	}
}

func TestLoadFileRejectsTrailingData(t *testing.T) {
	// The same strictness the live policy gets, applied to a candidate: two JSON
	// objects in one file is a truncation or a paste accident, and guessing
	// which half to obey is exactly the wrong instinct.
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte(`{"rules":[]}{"rules":[]}`), FileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, exists, err := LoadFile(path)
	if err == nil {
		t.Fatal("trailing data was accepted")
	}
	if !exists {
		t.Error("a present-but-invalid file was reported as absent")
	}
	// The error names the candidate, not the live policy — otherwise the
	// operator goes and looks at the wrong file.
	if !strings.Contains(err.Error(), "candidate.json") {
		t.Errorf("the error names the wrong file: %v", err)
	}
}

func TestLoadFileRejectsAnUnknownFieldInACandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.json")
	body := `{"schema":1,"rules":[{"allow":true,"secrets":["bao:app/x#t"],"modez":["exec"]}]}`
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := LoadFile(path); err == nil {
		t.Fatal("an unknown field was accepted in a candidate")
	}
}

func TestLoadFileRejectsANewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.json")
	body := `{"schema":99,"rules":[]}`
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := func() error { _, _, e := LoadFile(path); return e }()
	if err == nil {
		t.Fatal("a schema newer than this binary understands was accepted")
	}
	if !strings.Contains(err.Error(), "candidate.json") {
		t.Errorf("the schema error names the wrong file: %v", err)
	}
}
