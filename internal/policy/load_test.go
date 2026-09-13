package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicy points ConfigDir at a temp dir holding the given policy.json body.
func writePolicy(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
}

// The regression this whole change exists for: a policy written for a newer
// parzival must be refused outright, not silently applied minus the field the
// binary cannot read. Ignoring "modes" turns a brokered-delivery-only rule into
// an unrestricted allow.
func TestLoadRejectsUnknownField(t *testing.T) {
	writePolicy(t, `{"rules":[{"allow":true,"secrets":["bao:app/*"],"future_field":["exec"]}]}`)

	_, _, err := Load()
	if err == nil {
		t.Fatal("Load accepted a policy with an unknown field; it must refuse rather than apply a weaker rule")
	}
	if !strings.Contains(err.Error(), "future_field") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
	if !strings.Contains(err.Error(), "older than the policy") {
		t.Errorf("error should point at a stale binary as the likely cause, got: %v", err)
	}
}

func TestLoadRejectsUnknownFieldInsideRule(t *testing.T) {
	// Unknown fields at the top level are caught too.
	writePolicy(t, `{"rules":[],"deny_get":true}`)
	if _, _, err := Load(); err == nil {
		t.Fatal("Load accepted an unknown top-level field")
	}
}

func TestLoadRejectsNewerSchema(t *testing.T) {
	writePolicy(t, `{"schema":99,"rules":[{"allow":true}]}`)

	_, _, err := Load()
	if err == nil {
		t.Fatal("Load accepted a policy declaring a newer schema than this binary understands")
	}
	if !strings.Contains(err.Error(), "upgrade parzival") {
		t.Errorf("error should tell the operator to upgrade, got: %v", err)
	}
}

func TestLoadAcceptsCurrentSchemaAndDescription(t *testing.T) {
	writePolicy(t, `{"schema":1,"rules":[
		{"allow":true,"description":"why this rule exists","secrets":["bao:app/*"],"modes":["exec"]}
	]}`)

	p, exists, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !exists {
		t.Fatal("exists = false for a policy that is present")
	}
	if p.Schema != SchemaVersion {
		t.Errorf("Schema = %d, want %d", p.Schema, SchemaVersion)
	}
	if p.Rules[0].Description != "why this rule exists" {
		t.Errorf("Description not parsed: %q", p.Rules[0].Description)
	}
}

func TestLoadRejectsTrailingData(t *testing.T) {
	writePolicy(t, `{"rules":[]}{"rules":[{"allow":true}]}`)
	if _, _, err := Load(); err == nil {
		t.Fatal("Load accepted a file with a second object after the policy")
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	t.Setenv("PARZIVAL_CONFIG_HOME", t.TempDir())
	p, exists, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if exists || p != nil {
		t.Fatal("a missing policy must report exists=false (caller then denies by default)")
	}
}
