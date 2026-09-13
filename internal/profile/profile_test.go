package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), name+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndRender(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writeProfile(t, "aws", `{
	  "secrets": {"access":"bao:aws/x#id","secret":"bao:aws/x#key"},
	  "template": "[default]\naws_access_key_id = {{ .access }}\naws_secret_access_key = {{ .secret }}\n",
	  "inject": {"env":"AWS_SHARED_CREDENTIALS_FILE"}
	}`)

	p, err := Load("aws")
	if err != nil {
		t.Fatal(err)
	}
	if p.Inject.Env != "AWS_SHARED_CREDENTIALS_FILE" {
		t.Fatalf("inject.env = %q", p.Inject.Env)
	}
	if p.Inject.FileName() != "credential" {
		t.Fatalf("default filename = %q, want credential", p.Inject.FileName())
	}

	out, err := p.Render(map[string][]byte{"access": []byte("AKIA"), "secret": []byte("s3cr3t")})
	if err != nil {
		t.Fatal(err)
	}
	want := "[default]\naws_access_key_id = AKIA\naws_secret_access_key = s3cr3t\n"
	if string(out) != want {
		t.Fatalf("render =\n%q\nwant\n%q", out, want)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, err := Load("../etc/passwd"); err == nil {
		t.Fatal("expected error for name containing a slash")
	}
	if _, err := Load("missing"); err == nil {
		t.Fatal("expected error for missing profile")
	}
	writeProfile(t, "nosec", `{"secrets":{},"template":"x"}`)
	if _, err := Load("nosec"); err == nil {
		t.Fatal("expected error for a profile with no secrets")
	}
	writeProfile(t, "notmpl", `{"secrets":{"a":"bao:m/p#f"},"template":"   "}`)
	if _, err := Load("notmpl"); err == nil {
		t.Fatal("expected error for an empty template")
	}
}

// inject.filename may nest, for tools that read a fixed filename inside a
// config dir; inject.env_dir points a variable at the RAM dir itself.
func TestLoadNestedFilenameAndEnvDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	writeProfile(t, "tea", `{"secrets":{"token":"bao:app/gitea#token"},"template":"token: {{ .token }}",`+
		`"inject":{"filename":"tea/config.yml","env_dir":"XDG_CONFIG_HOME"}}`)
	p, err := Load("tea")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Inject.FileName(); got != "tea/config.yml" {
		t.Fatalf("FileName() = %q, want tea/config.yml", got)
	}
	if p.Inject.EnvDir != "XDG_CONFIG_HOME" {
		t.Fatalf("EnvDir = %q, want XDG_CONFIG_HOME", p.Inject.EnvDir)
	}
	// Unset filename still defaults.
	writeProfile(t, "plain", `{"secrets":{"a":"bao:m/p#f"},"template":"x"}`)
	p, err = Load("plain")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Inject.FileName(); got != "credential" {
		t.Fatalf("default FileName() = %q, want credential", got)
	}
}

// A filename that could place the rendered secret outside the RAM dir must be
// refused at load time, before anything is fetched.
func TestLoadRejectsEscapingFilename(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	bad := map[string]string{
		"abs":       "/etc/passwd",
		"parent":    "../escape",
		"midparent": "a/../../escape",
		"dotdot":    "..",
		"dot":       ".",
		"backslash": `sub\config.yml`,
	}
	for name, fn := range bad {
		body := `{"secrets":{"a":"bao:m/p#f"},"template":"x","inject":{"filename":"` + fn + `"}}`
		writeProfile(t, name, body)
		if _, err := Load(name); err == nil {
			t.Fatalf("Load with filename %q succeeded, want refusal", fn)
		}
	}
}

func TestRenderMissingKeyErrors(t *testing.T) {
	p := &Profile{Template: "{{ .nope }}"}
	if _, err := p.Render(map[string][]byte{"token": []byte("x")}); err == nil {
		t.Fatal("expected a missingkey error")
	}
}
