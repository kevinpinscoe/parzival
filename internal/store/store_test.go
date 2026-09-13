package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    SecretRef
		wantErr bool
	}{
		{name: "openbao", ref: "bao:app/gitea#token",
			want: SecretRef{Backend: "openbao", Path: "app/gitea", Field: "token", Raw: "bao:app/gitea#token"}},
		{name: "openbao nested path", ref: "bao:app/ci/deploy#password",
			want: SecretRef{Backend: "openbao", Path: "app/ci/deploy", Field: "password", Raw: "bao:app/ci/deploy#password"}},
		{name: "openbao missing field", ref: "bao:app/gitea", wantErr: true},
		{name: "openbao empty field", ref: "bao:app/gitea#", wantErr: true},
		{name: "openbao missing path", ref: "bao:#token", wantErr: true},
		{name: "onepassword", ref: "op://Private/Gitea/token",
			want: SecretRef{Backend: "onepassword", Path: "op://Private/Gitea/token", Raw: "op://Private/Gitea/token"}},
		{name: "gopass", ref: "gopass:web/gitea",
			want: SecretRef{Backend: "gopass", Path: "web/gitea", Raw: "gopass:web/gitea"}},
		{name: "gopass empty", ref: "gopass:", wantErr: true},
		{name: "unknown scheme", ref: "vault:foo", wantErr: true},
		{name: "empty", ref: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRef(%q) = %+v, want error", tt.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tt.ref, err)
			}
			if got != tt.want {
				t.Fatalf("ParseRef(%q) = %+v, want %+v", tt.ref, got, tt.want)
			}
		})
	}
}

// fakeRunner records the argv it was called with and returns canned output.
type fakeRunner struct {
	out  []byte
	err  error
	name string
	args []string
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.name, f.args = name, args
	return f.out, f.err
}

func TestOpenBaoGetTrimsNewlineAndBuildsArgv(t *testing.T) {
	fake := &fakeRunner{out: []byte("s3cr3t\n")}
	o := &OpenBao{run: fake, bin: "bao", mode: openBaoModeAmbient}
	ref, err := ParseRef("bao:app/gitea#token")
	if err != nil {
		t.Fatal(err)
	}

	got, err := o.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("Get = %q, want %q (trailing newline must be trimmed)", got, "s3cr3t")
	}
	wantArgs := []string{"kv", "get", "-field=token", "-mount=app", "gitea"}
	if !slices.Equal(fake.args, wantArgs) {
		t.Fatalf("argv = %v, want %v", fake.args, wantArgs)
	}
}

func TestOpenBaoAppRoleGet(t *testing.T) {
	t.Setenv("PARZIVAL_OPENBAO_SECRET_ID", "secret-id")
	var sawLogin, sawFetch bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			sawLogin = true
			if r.Method != http.MethodPost {
				t.Fatalf("login method = %s", r.Method)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["role_id"] != "role-id" || body["secret_id"] != "secret-id" {
				t.Fatalf("login body = %+v", body)
			}
			return jsonResponse(200, `{"auth":{"client_token":"client-token"}}`), nil
		case "/v1/app/data/gitea":
			sawFetch = true
			if r.Method != http.MethodGet {
				t.Fatalf("fetch method = %s", r.Method)
			}
			if got := r.Header.Get("X-Vault-Token"); got != "client-token" {
				t.Fatalf("X-Vault-Token = %q", got)
			}
			return jsonResponse(200, `{"data":{"data":{"token":"s3cr3t"}}}`), nil
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return nil, nil
	})}

	o := &OpenBao{
		mode:      openBaoModeAppRole,
		addr:      "https://bao.example",
		roleID:    "role-id",
		authMount: "approle",
		bootstrap: EnvBootstrapProvider{},
		client:    client,
	}
	ref, err := ParseRef("bao:app/gitea#token")
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("Get = %q", got)
	}
	if !sawLogin || !sawFetch {
		t.Fatalf("sawLogin=%v sawFetch=%v", sawLogin, sawFetch)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func TestOpenBaoCapabilities(t *testing.T) {
	ambient := (&OpenBao{mode: openBaoModeAmbient}).Capabilities()
	if ambient.NonAmbientBrokerAuth || ambient.ShortLivedCredential || ambient.UnattendedBootstrap {
		t.Fatalf("ambient capabilities too strong: %+v", ambient)
	}

	approle := (&OpenBao{mode: openBaoModeAppRole}).Capabilities()
	if !approle.StrongUnattended() {
		t.Fatalf("approle capabilities not strong unattended: %+v", approle)
	}
}

func TestOnePasswordGetBuildsArgv(t *testing.T) {
	fake := &fakeRunner{out: []byte("s3cr3t")}
	p := &OnePassword{run: fake, bin: "op"}
	ref, err := ParseRef("op://Private/Gitea/token")
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("Get = %q, want %q", got, "s3cr3t")
	}
	wantArgs := []string{"read", "--no-newline", "op://Private/Gitea/token"}
	if !slices.Equal(fake.args, wantArgs) {
		t.Fatalf("argv = %v, want %v", fake.args, wantArgs)
	}
}

func TestGopassUnimplemented(t *testing.T) {
	g := NewGopass()
	if _, err := g.Get(context.Background(), SecretRef{Backend: "gopass"}); err != ErrUnimplemented {
		t.Fatalf("Get err = %v, want ErrUnimplemented", err)
	}
}
