package store

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBootstrapProviders(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		t.Setenv("PARZIVAL_OPENBAO_SECRET_ID", "secret-id")
		got, err := EnvBootstrapProvider{}.ReadSecretID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "secret-id" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("file trims newline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret-id")
		if err := os.WriteFile(path, []byte("secret-id\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := FileBootstrapProvider{Path: path}.ReadSecretID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "secret-id" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("systemd credential", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, defaultSystemdSecretIDName), []byte("secret-id"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := SystemdCredentialProvider{Dir: dir}.ReadSecretID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "secret-id" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("systemd-creds-user decrypt", func(t *testing.T) {
		fake := &fakeRunner{out: []byte("secret-id\n")}
		p := SystemdCredsUserProvider{Path: "/enc/path.cred", CredName: "openbao-secret-id", run: fake}
		got, err := p.ReadSecretID(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "secret-id" {
			t.Fatalf("got %q", got)
		}
		if fake.name != "systemd-creds" {
			t.Fatalf("ran %q, want systemd-creds", fake.name)
		}
		wantArgs := []string{"decrypt", "--user", "--name=openbao-secret-id", "/enc/path.cred"}
		if !reflect.DeepEqual(fake.args, wantArgs) {
			t.Fatalf("args = %v, want %v", fake.args, wantArgs)
		}
	})

	t.Run("systemd-creds-user with explicit uid", func(t *testing.T) {
		fake := &fakeRunner{out: []byte("secret-id")}
		p := SystemdCredsUserProvider{Path: "/enc/path.cred", CredName: "alert-lib", UID: "1000", run: fake}
		if _, err := p.ReadSecretID(context.Background()); err != nil {
			t.Fatal(err)
		}
		wantArgs := []string{"decrypt", "--user", "--uid=1000", "--name=alert-lib", "/enc/path.cred"}
		if !reflect.DeepEqual(fake.args, wantArgs) {
			t.Fatalf("args = %v, want %v", fake.args, wantArgs)
		}
	})

	t.Run("systemd-creds-user default name and path required", func(t *testing.T) {
		if _, err := (SystemdCredsUserProvider{}).ReadSecretID(context.Background()); err == nil {
			t.Fatal("want error for empty Path")
		}
	})
}

// TestNewOpenBaoFromEnvConfigFileFallback proves the fix for a real
// production bug: a caller with none of the PARZIVAL_OPENBAO_* environment
// variables set (a cron job, a systemd --user unit, an AI agent's own
// non-interactive tool shell) must still end up in approle mode, sourced
// entirely from $PARZIVAL_CONFIG_HOME/openbao.json.
func TestNewOpenBaoFromEnvConfigFileFallback(t *testing.T) {
	for _, v := range []string{
		"PARZIVAL_OPENBAO_AUTH", "BAO_ADDR", "VAULT_ADDR",
		"PARZIVAL_OPENBAO_ROLE_ID", "PARZIVAL_OPENBAO_SECRET_ID_PROVIDER",
		"PARZIVAL_OPENBAO_SECRET_ID_FILE", "PARZIVAL_OPENBAO_APPROLE_MOUNT",
		"BAO_NAMESPACE", "VAULT_NAMESPACE",
	} {
		t.Setenv(v, "")
	}

	configHome := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", configHome)

	cfg := `{
		"auth": "approle",
		"addr": "https://bao.example",
		"role_id": "role-from-file",
		"secret_id_provider": "systemd-creds-user",
		"secret_id_file": "/enc/from-config.cred"
	}`
	if err := os.WriteFile(filepath.Join(configHome, "openbao.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	backend, err := NewOpenBaoFromEnv()
	if err != nil {
		t.Fatalf("NewOpenBaoFromEnv: %v", err)
	}
	if backend.mode != openBaoModeAppRole {
		t.Fatalf("mode = %q, want approle", backend.mode)
	}
	if backend.addr != "https://bao.example" {
		t.Fatalf("addr = %q", backend.addr)
	}
	if backend.roleID != "role-from-file" {
		t.Fatalf("roleID = %q", backend.roleID)
	}
	sc, ok := backend.bootstrap.(SystemdCredsUserProvider)
	if !ok {
		t.Fatalf("bootstrap provider = %T, want SystemdCredsUserProvider", backend.bootstrap)
	}
	if sc.Path != "/enc/from-config.cred" {
		t.Fatalf("bootstrap path = %q", sc.Path)
	}

	// An explicit environment variable still wins over the file, for any one
	// setting -- the file is a fallback, never an override.
	t.Setenv("PARZIVAL_OPENBAO_ROLE_ID", "role-from-env")
	backend, err = NewOpenBaoFromEnv()
	if err != nil {
		t.Fatalf("NewOpenBaoFromEnv: %v", err)
	}
	if backend.roleID != "role-from-env" {
		t.Fatalf("roleID = %q, want env value to win", backend.roleID)
	}
}
