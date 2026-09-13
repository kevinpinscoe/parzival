package policy

// Installing a policy without ever leaving a half-written one on disk.
//
// The policy file is the only thing standing between a caller and every secret
// parzival can reach. A truncated write leaves a file that either fails to parse
// — every fetch denied, which is safe but is an outage — or, worse, parses as a
// shorter rule list whose first match is not the one the operator wrote. Neither
// is acceptable as a possible outcome of a crash mid-edit.
//
// So a new policy is written to a temporary file in the same directory,
// permissioned, flushed, and then moved over the live path with rename(2), which
// is atomic within a filesystem. A reader at any instant sees either the whole
// old policy or the whole new one. The temporary file goes in the same directory
// precisely so the rename stays within one filesystem; /tmp would be a different
// mount on most of these hosts and the rename would degrade to a copy.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileMode is the permission a policy file is written with. It is not a secret —
// it holds references, never values — but it decides what every caller on the
// host is authorized to fetch, so it is owner-only by the same reasoning that
// makes it worth having at all.
const FileMode os.FileMode = 0o600

// Marshal renders a policy as the JSON that gets written to disk: two-space
// indented, newline-terminated, HTML escaping off.
//
// Escaping is disabled because Go's encoder would otherwise rewrite `&`, `<` and
// `>` as & and friends. Those are legal characters in a secret ref and an
// identity glob, and a policy that comes back from a round trip textually
// different from the one that went in makes every diff unreadable — which
// defeats the review step the diff exists for.
func Marshal(p *Policy) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("render policy: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteAtomic installs p at path, replacing whatever is there in one step.
//
// The policy is re-parsed from its own rendered bytes before anything is
// written. A Policy assembled in memory can hold a value the parser would refuse
// — an invalid hours string, an unknown mode — and writing it would install a
// file that this binary then declines to load, denying every fetch on the host.
// Rendering and re-reading is the cheapest way to be sure the bytes about to be
// installed are bytes that load.
func WriteAtomic(path string, p *Policy) error {
	data, err := Marshal(p)
	if err != nil {
		return err
	}
	if _, err := Parse(data, filepath.Base(path)); err != nil {
		return fmt.Errorf("refusing to install a policy this parzival cannot load: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".policy-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Remove the temporary file on every failure path below. After a successful
	// rename there is nothing at tmpName any more and this is a no-op.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(FileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("set permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	// Flush to the device before the rename. Without this a crash between the
	// two can leave the rename durable and its contents not — the file exists,
	// at the right name, empty.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flush %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// Backup copies path to a timestamped sibling and returns the backup's name.
//
// It never overwrites an existing backup: if the name is taken it tries the next
// second, and gives up rather than clobbering. A backup that can be overwritten
// is not a backup — the case it exists for is a bad edit noticed some minutes
// later, by which time a scheme that reuses one filename has already lost the
// good copy to the second bad edit.
//
// A missing source is not an error. Granting the first rule on a host with no
// policy file is a legitimate first edit, and there is simply nothing to keep;
// the returned name is empty.
func Backup(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s for backup: %w", path, err)
	}

	mode := FileMode
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}

	when := time.Now()
	for attempt := range 60 {
		name := fmt.Sprintf("%s.bak.%s", path, when.Add(time.Duration(attempt)*time.Second).Format("20060102-150405"))
		// O_EXCL is what makes "never overwrite" true rather than merely
		// intended: checking for the file and then creating it would leave a
		// window for a concurrent edit to land in between.
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create backup %s: %w", name, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return "", fmt.Errorf("write backup %s: %w", name, err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return "", fmt.Errorf("flush backup %s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("close backup %s: %w", name, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("could not find an unused backup name beside %s after 60 attempts", path)
}

// Restore puts a backup back, atomically, using the same install path a normal
// write takes.
//
// It goes through Parse first for the same reason WriteAtomic does: a backup
// that has itself been corrupted is not something to install on top of a policy
// that at least loads. If the backup will not parse, the caller is better off
// with the bad-but-loadable file it already has and an error explaining why.
func Restore(backupPath, path string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup %s: %w", backupPath, err)
	}
	p, err := Parse(data, filepath.Base(backupPath))
	if err != nil {
		return fmt.Errorf("backup %s does not parse, refusing to install it: %w", backupPath, err)
	}
	return WriteAtomic(path, p)
}

// WriteCandidate writes a proposed policy to its own file for review, with the
// same permissions and the same pre-write parse as a live install.
//
// A candidate is reviewed and then installed, so anything true of the installed
// file has to be true of the candidate — otherwise the operator approves one
// artifact and a different one lands. os.CreateTemp is used for the name so a
// predictable path cannot be pre-created by another process and have its
// contents read or replaced.
func WriteCandidate(dir string, p *Policy) (string, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	data, err := Marshal(p)
	if err != nil {
		return "", err
	}
	if _, err := Parse(data, "candidate policy"); err != nil {
		return "", fmt.Errorf("refusing to write a candidate this parzival cannot load: %w", err)
	}

	f, err := os.CreateTemp(dir, fmt.Sprintf("parzival-policy-candidate-%s-*.json", time.Now().Format("20060102-150405")))
	if err != nil {
		return "", fmt.Errorf("create candidate file in %s: %w", dir, err)
	}
	name := f.Name()
	if err := f.Chmod(FileMode); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("set permissions on %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("close %s: %w", name, err)
	}
	return name, nil
}

// VerifyInstalled re-reads an installed policy and confirms it is what was meant
// to land: it parses, it matches the expected content, and its permissions are
// what they should be.
//
// This is the step that turns "the write returned no error" into "the file on
// disk is the file that was approved". They are not the same claim — a full
// filesystem, an interrupted rename, or another process writing the same path
// all produce the first without the second.
func VerifyInstalled(path string, expected *Policy) error {
	got, exists, err := LoadFile(path)
	if err != nil {
		return fmt.Errorf("installed policy does not load: %w", err)
	}
	if !exists {
		return fmt.Errorf("installed policy %s is missing after the write", path)
	}

	want, err := Marshal(expected)
	if err != nil {
		return err
	}
	have, err := Marshal(got)
	if err != nil {
		return err
	}
	if string(want) != string(have) {
		return fmt.Errorf("installed policy %s does not match the approved candidate", path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if perm := fi.Mode().Perm(); perm != FileMode {
		return fmt.Errorf("installed policy %s has mode %04o, want %04o", path, perm, FileMode)
	}
	return nil
}
