package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

const (
	defaultSystemdSecretIDName = "openbao-secret-id"
	openBaoConfigFileName      = "openbao.json"
)

// openBaoFileConfig is the on-disk fallback for the non-secret bootstrap
// settings normally supplied via PARZIVAL_OPENBAO_* environment variables.
// It exists because those variables reach only the shells that source
// ~/.bash.d/00_bashrc_env -- an interactive login shell. A cron job, a
// systemd --user unit, an AI coding agent's own non-interactive tool shell,
// or anything else that doesn't go through interactive shell startup never
// sees them and silently falls back to ambient mode. Reading a file instead
// makes every parzival invocation behave the same regardless of how it was
// spawned. An environment variable always wins when both are present, so
// this changes nothing for a caller that already sets them explicitly (e.g.
// a test, or a profile that wants a different AppRole).
type openBaoFileConfig struct {
	Auth             string `json:"auth,omitempty"`
	Addr             string `json:"addr,omitempty"`
	RoleID           string `json:"role_id,omitempty"`
	ApproleMount     string `json:"approle_mount,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	SecretIDProvider string `json:"secret_id_provider,omitempty"`
	SecretIDFile     string `json:"secret_id_file,omitempty"`
	SecretIDName     string `json:"secret_id_name,omitempty"`
	SecretIDUID      string `json:"secret_id_uid,omitempty"`
}

// loadOpenBaoFileConfig reads $PARZIVAL_CONFIG_HOME/openbao.json (see
// policy.ConfigDir). A missing or unparsable file is not an error -- it just
// means every setting comes from the environment, exactly as before this
// fallback existed.
func loadOpenBaoFileConfig() openBaoFileConfig {
	path := filepath.Join(policy.ConfigDir(), openBaoConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return openBaoFileConfig{}
	}
	var cfg openBaoFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return openBaoFileConfig{}
	}
	return cfg
}

// envOrFallback returns the environment variable's value, or fallback when
// the variable is unset or empty.
func envOrFallback(envVar, fallback string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fallback
}

// BootstrapProvider supplies OpenBao AppRole SecretID material to parzival.
// The provider is deliberately separate from OpenBao fetching so each platform
// can protect secret zero in its own way.
type BootstrapProvider interface {
	Name() string
	ReadSecretID(ctx context.Context) ([]byte, error)
}

// EnvBootstrapProvider reads a SecretID from an environment variable. It is a
// development/test provider, not a production protection mechanism.
type EnvBootstrapProvider struct {
	Var string
}

func (p EnvBootstrapProvider) Name() string { return "env" }

func (p EnvBootstrapProvider) ReadSecretID(context.Context) ([]byte, error) {
	name := p.Var
	if name == "" {
		name = "PARZIVAL_OPENBAO_SECRET_ID"
	}
	val := os.Getenv(name)
	if val == "" {
		return nil, fmt.Errorf("%s is empty", name)
	}
	return []byte(val), nil
}

// FileBootstrapProvider reads a SecretID from a named file. It exists for tests
// and controlled migration only; a normal readable file is not strong secret-zero
// protection.
type FileBootstrapProvider struct {
	Path string
}

func (p FileBootstrapProvider) Name() string { return "file" }

func (p FileBootstrapProvider) ReadSecretID(context.Context) ([]byte, error) {
	if p.Path == "" {
		return nil, fmt.Errorf("PARZIVAL_OPENBAO_SECRET_ID_FILE is empty")
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, err
	}
	return trimCredentialNewline(data), nil
}

// SystemdCredentialProvider reads a SecretID from systemd's runtime credential
// directory, usually supplied with LoadCredentialEncrypted=. systemd exposes the
// path through $CREDENTIALS_DIRECTORY.
type SystemdCredentialProvider struct {
	NameInDir string
	Dir       string
}

func (p SystemdCredentialProvider) Name() string { return "systemd-credential" }

func (p SystemdCredentialProvider) ReadSecretID(context.Context) ([]byte, error) {
	dir := p.Dir
	if dir == "" {
		dir = os.Getenv("CREDENTIALS_DIRECTORY")
	}
	if dir == "" {
		return nil, fmt.Errorf("CREDENTIALS_DIRECTORY is empty")
	}
	name := p.NameInDir
	if name == "" {
		name = os.Getenv("PARZIVAL_OPENBAO_SECRET_ID_NAME")
	}
	if name == "" {
		name = defaultSystemdSecretIDName
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return trimCredentialNewline(data), nil
}

// SystemdCredsUserProvider decrypts a SecretID protected with
// `systemd-creds encrypt --user`. Unlike SystemdCredentialProvider it needs no
// systemd unit and no $CREDENTIALS_DIRECTORY: parzival decrypts on demand,
// each time it needs the SecretID, by shelling out to `systemd-creds decrypt
// --user`. That command is served by systemd's privileged credential service
// rather than by parzival reading the host key
// (/var/lib/systemd/credential.secret, root:root, 0400) directly, so the
// calling user can decrypt only its own user-scoped credentials — the same
// host-key protection SystemdCredentialProvider gives an unattended service,
// made available to an interactive desktop session instead. This is the
// provider for an interactive workstation, where parzival's own CLI
// invocations (not a long-running systemd unit) need the SecretID.
type SystemdCredsUserProvider struct {
	// Path to the encrypted credential file, e.g.
	// ~/.config/parzival/openbao-secret-id.cred.
	Path string
	// CredName must match the --name given to `systemd-creds encrypt`.
	CredName string
	// UID targets a credential encrypted for a different user than the
	// calling process. `systemd-creds decrypt --user` alone implies
	// --uid=self (the caller's own uid), so a root-run consumer decrypting a
	// credential encrypted with `--uid=1000` (e.g. a shared systemd service
	// and an interactive user's cron job both reading the same credential)
	// must pass --uid explicitly. Root can decrypt another uid's user-scoped
	// credential ("except if privileges can be acquired", per
	// systemd-creds(1)) -- verified in practice. Leave empty to decrypt as
	// the calling user (the common case).
	UID string
	run runner
}

func (p SystemdCredsUserProvider) Name() string { return "systemd-creds-user" }

func (p SystemdCredsUserProvider) ReadSecretID(ctx context.Context) ([]byte, error) {
	if p.Path == "" {
		return nil, fmt.Errorf("PARZIVAL_OPENBAO_SECRET_ID_FILE is empty")
	}
	name := p.CredName
	if name == "" {
		name = os.Getenv("PARZIVAL_OPENBAO_SECRET_ID_NAME")
	}
	if name == "" {
		name = defaultSystemdSecretIDName
	}
	uid := p.UID
	if uid == "" {
		uid = os.Getenv("PARZIVAL_OPENBAO_SECRET_ID_UID")
	}
	run := p.run
	if run == nil {
		run = execRunner{}
	}
	args := []string{"decrypt", "--user"}
	if uid != "" {
		args = append(args, "--uid="+uid)
	}
	args = append(args, "--name="+name, p.Path)
	out, err := run.run(ctx, "systemd-creds", args...)
	if err != nil {
		return nil, fmt.Errorf("systemd-creds decrypt --user: %w", err)
	}
	return trimCredentialNewline(out), nil
}

func bootstrapProviderFromEnv(cfg openBaoFileConfig) (BootstrapProvider, error) {
	provider := envOrFallback("PARZIVAL_OPENBAO_SECRET_ID_PROVIDER", cfg.SecretIDProvider)
	secretIDFile := envOrFallback("PARZIVAL_OPENBAO_SECRET_ID_FILE", cfg.SecretIDFile)
	switch provider {
	case "", "systemd-credential", "systemd":
		return SystemdCredentialProvider{}, nil
	case "systemd-creds-user":
		return SystemdCredsUserProvider{
			Path:     secretIDFile,
			CredName: envOrFallback("PARZIVAL_OPENBAO_SECRET_ID_NAME", cfg.SecretIDName),
			UID:      envOrFallback("PARZIVAL_OPENBAO_SECRET_ID_UID", cfg.SecretIDUID),
		}, nil
	case "env":
		return EnvBootstrapProvider{}, nil
	case "file":
		return FileBootstrapProvider{Path: secretIDFile}, nil
	default:
		return nil, fmt.Errorf("unknown PARZIVAL_OPENBAO_SECRET_ID_PROVIDER %q (want systemd-credential, systemd-creds-user, env, or file)", provider)
	}
}

func trimCredentialNewline(data []byte) []byte {
	return bytes.TrimRight(data, "\r\n")
}
