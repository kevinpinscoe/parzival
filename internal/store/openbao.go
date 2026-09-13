package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/kevinpinscoe/parzival/internal/secret"
)

const (
	openBaoModeAmbient = "ambient"
	openBaoModeAppRole = "approle"
)

// OpenBao fetches secrets from an OpenBao (or Vault) KV v2 mount. In ambient
// mode it shells out to `bao` for compatibility. In approle mode it authenticates
// as parzival through AppRole and uses the HTTP API directly, avoiding BAO_TOKEN
// and default token files in the caller's shell.
type OpenBao struct {
	run       runner
	bin       string
	mode      string
	addr      string
	roleID    string
	authMount string
	namespace string
	bootstrap BootstrapProvider
	client    *http.Client
}

// NewOpenBao returns an OpenBao backend in ambient compatibility mode.
func NewOpenBao() *OpenBao {
	return &OpenBao{run: execRunner{}, bin: "bao", mode: openBaoModeAmbient}
}

// NewOpenBaoFromEnv returns an OpenBao backend configured from environment,
// falling back to $PARZIVAL_CONFIG_HOME/openbao.json for any setting whose
// environment variable is unset (see openBaoFileConfig) -- so a caller that
// never sourced an interactive shell's rc files, such as a cron job, a
// systemd --user unit, or an AI agent's own non-interactive tool shell,
// still gets a working configuration.
//
// Ambient mode is the compatibility default:
//
//	PARZIVAL_OPENBAO_AUTH=ambient
//
// AppRole broker-auth mode:
//
//	PARZIVAL_OPENBAO_AUTH=approle
//	BAO_ADDR=https://bao.example
//	PARZIVAL_OPENBAO_ROLE_ID=...
//	PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential|systemd-creds-user|env|file
func NewOpenBaoFromEnv() (*OpenBao, error) {
	cfg := loadOpenBaoFileConfig()
	mode := envOrFallback("PARZIVAL_OPENBAO_AUTH", cfg.Auth)
	if mode == "" {
		mode = openBaoModeAmbient
	}
	switch mode {
	case openBaoModeAmbient:
		return NewOpenBao(), nil
	case openBaoModeAppRole:
		addr := envOrFallback("BAO_ADDR", cfg.Addr)
		if addr == "" {
			addr = os.Getenv("VAULT_ADDR")
		}
		if addr == "" {
			return nil, fmt.Errorf("openbao approle mode requires BAO_ADDR or VAULT_ADDR")
		}
		roleID := envOrFallback("PARZIVAL_OPENBAO_ROLE_ID", cfg.RoleID)
		if roleID == "" {
			return nil, fmt.Errorf("openbao approle mode requires PARZIVAL_OPENBAO_ROLE_ID")
		}
		provider, err := bootstrapProviderFromEnv(cfg)
		if err != nil {
			return nil, err
		}
		authMount := envOrFallback("PARZIVAL_OPENBAO_APPROLE_MOUNT", cfg.ApproleMount)
		if authMount == "" {
			authMount = "approle"
		}
		namespace := envOrFallback("BAO_NAMESPACE", cfg.Namespace)
		if namespace == "" {
			namespace = os.Getenv("VAULT_NAMESPACE")
		}
		return &OpenBao{
			mode:      openBaoModeAppRole,
			addr:      addr,
			roleID:    roleID,
			authMount: authMount,
			namespace: namespace,
			bootstrap: provider,
			client:    http.DefaultClient,
		}, nil
	default:
		return nil, fmt.Errorf("unknown PARZIVAL_OPENBAO_AUTH %q (want ambient or approle)", mode)
	}
}

// Name implements Store.
func (*OpenBao) Name() string { return "openbao" }

// Capabilities implements Store.
func (o *OpenBao) Capabilities() Capabilities {
	if o.mode == openBaoModeAppRole {
		return Capabilities{
			EncryptedAtRest:          true,
			NonAmbientBrokerAuth:     true,
			ScopedStoreAuthorization: true,
			ShortLivedCredential:     true,
			BackendAudit:             true,
			UnattendedBootstrap:      true,
		}
	}
	return Capabilities{
		EncryptedAtRest:          true,
		ScopedStoreAuthorization: true,
		BackendAudit:             true,
	}
}

// Get implements Store.
func (o *OpenBao) Get(ctx context.Context, ref SecretRef) ([]byte, error) {
	mount, path, ok := strings.Cut(ref.Path, "/")
	if !ok || path == "" {
		return nil, fmt.Errorf("openbao reference %q must be <mount>/<path>#<field>", ref.Raw)
	}
	if o.mode == openBaoModeAppRole {
		return o.getAppRole(ctx, ref, mount, path)
	}
	return o.getAmbient(ctx, ref, mount, path)
}

// getAmbient runs `bao kv get -field=<field> -mount=<mount> <path>`. Only the
// field name, mount, and path appear on argv — never the secret. This mode
// inherits the caller's ambient CLI auth and is therefore compatibility mode,
// not the strongest unattended deployment shape.
func (o *OpenBao) getAmbient(ctx context.Context, ref SecretRef, mount, path string) ([]byte, error) {
	out, err := o.run.run(ctx, o.bin,
		"kv", "get",
		"-field="+ref.Field,
		"-mount="+mount,
		path,
	)
	if err != nil {
		return nil, fmt.Errorf("openbao: fetch %q via %s: %w", ref.Raw, o.bin, err)
	}
	// `bao -field` appends a single trailing newline when writing to a pipe; drop it.
	return bytes.TrimSuffix(out, []byte("\n")), nil
}

func (o *OpenBao) getAppRole(ctx context.Context, ref SecretRef, mount, path string) ([]byte, error) {
	token, err := o.loginAppRole(ctx)
	if err != nil {
		return nil, err
	}
	defer secret.Zero(token)

	reqURL, err := o.apiURL(mount, "data", path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	o.setHeaders(req, token)
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("openbao: fetch %q: %w", ref.Raw, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("openbao: fetch %q: %s", ref.Raw, responseError(resp))
	}

	var decoded struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("openbao: decode %q: %w", ref.Raw, err)
	}
	val, ok := decoded.Data.Data[ref.Field]
	if !ok {
		return nil, fmt.Errorf("openbao: field %q not found in %q", ref.Field, ref.Raw)
	}
	switch v := val.(type) {
	case string:
		return []byte(v), nil
	default:
		out, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("openbao: encode field %q from %q: %w", ref.Field, ref.Raw, err)
		}
		return out, nil
	}
}

func (o *OpenBao) loginAppRole(ctx context.Context) ([]byte, error) {
	if o.bootstrap == nil {
		return nil, fmt.Errorf("openbao approle mode has no bootstrap provider")
	}
	secretID, err := o.bootstrap.ReadSecretID(ctx)
	if err != nil {
		return nil, fmt.Errorf("openbao: read AppRole SecretID via %s: %w", o.bootstrap.Name(), err)
	}
	defer secret.Zero(secretID)

	loginURL, err := o.apiURL("auth", o.authMount, "login")
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{
		"role_id":   o.roleID,
		"secret_id": string(secretID),
	})
	if err != nil {
		return nil, err
	}
	defer secret.Zero(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.namespace != "" {
		req.Header.Set("X-Vault-Namespace", o.namespace)
	}
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("openbao: AppRole login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("openbao: AppRole login: %s", responseError(resp))
	}

	var decoded struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("openbao: decode AppRole login: %w", err)
	}
	if decoded.Auth.ClientToken == "" {
		return nil, fmt.Errorf("openbao: AppRole login response did not include auth.client_token")
	}
	return []byte(decoded.Auth.ClientToken), nil
}

func (o *OpenBao) setHeaders(req *http.Request, token []byte) {
	req.Header.Set("X-Vault-Token", string(token))
	if o.namespace != "" {
		req.Header.Set("X-Vault-Namespace", o.namespace)
	}
}

func (o *OpenBao) apiURL(parts ...string) (string, error) {
	base, err := url.Parse(o.addr)
	if err != nil {
		return "", fmt.Errorf("openbao: bad address %q: %w", o.addr, err)
	}
	elems := append([]string{"v1"}, parts...)
	base.Path, err = url.JoinPath(base.Path, elems...)
	if err != nil {
		return "", fmt.Errorf("openbao: build API path: %w", err)
	}
	return base.String(), nil
}

func (o *OpenBao) httpClient() *http.Client {
	if o.client != nil {
		return o.client
	}
	return http.DefaultClient
}

func responseError(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return resp.Status
	}
	return resp.Status + ": " + msg
}
