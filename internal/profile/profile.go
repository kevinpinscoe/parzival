// Package profile loads parzival exec profiles: a declarative JSON description
// of which secrets to fetch, how to render them into a file, and how to point a
// command at that file.
package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

// Profile is one tool's exec recipe.
type Profile struct {
	// Secrets maps a template variable name to a store reference string
	// (e.g. "token": "bao:app/gitea#token").
	Secrets map[string]string `json:"secrets"`
	// Template is a Go text/template rendered with the fetched secret values.
	Template string `json:"template"`
	// Inject describes how the child command is pointed at the rendered file.
	Inject Inject `json:"inject"`
}

// Inject controls how the rendered RAM file is exposed to the command.
type Inject struct {
	// Env, if set, is an environment variable set to the rendered file's path.
	Env string `json:"env,omitempty"`
	// EnvDir, if set, is an environment variable set to the RAM *directory's*
	// path. Tools that read a fixed filename inside a config directory, and
	// offer no flag or env var for the file itself, need this instead of Env —
	// e.g. `tea`, which reads only $XDG_CONFIG_HOME/tea/config.yml.
	EnvDir string `json:"env_dir,omitempty"`
	// Filename, if set, is the rendered file's path relative to the RAM dir. It
	// may name subdirectories ("tea/config.yml"), which are created 0700. It
	// must stay inside the RAM dir. Defaults to "credential".
	Filename string `json:"filename,omitempty"`
}

// FileName returns the cleaned relative path to use for the rendered file.
func (i Inject) FileName() string {
	if i.Filename != "" {
		return filepath.Clean(i.Filename)
	}
	return "credential"
}

// validateFilename rejects an inject.filename that is absolute or that could
// escape the RAM dir. Rendered secrets must never land outside the dir that
// Cleanup wipes.
func validateFilename(name string) error {
	if name == "" {
		return nil // the "credential" default is used
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, `\`) || strings.Contains(name, `\`) {
		return fmt.Errorf("inject.filename %q must be a relative path using /", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." {
		return fmt.Errorf("inject.filename %q does not name a file", name)
	}
	if slices.Contains(strings.Split(clean, "/"), "..") {
		return fmt.Errorf("inject.filename %q must not traverse outside the RAM dir", name)
	}
	return nil
}

// Load reads and validates the named profile from the profiles directory.
func Load(name string) (*Profile, error) {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("invalid profile name %q", name)
	}
	path := filepath.Join(Dir(), name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile %q: parse %s: %w", name, path, err)
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("profile %q: no secrets defined", name)
	}
	if strings.TrimSpace(p.Template) == "" {
		return nil, fmt.Errorf("profile %q: empty template", name)
	}
	if err := validateFilename(p.Inject.Filename); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return &p, nil
}

// Render fills the profile template with the given secret values. A template
// reference to a name not present in secrets is an error rather than a blank.
func (p *Profile) Render(secrets map[string][]byte) ([]byte, error) {
	tmpl, err := template.New("profile").Option("missingkey=error").Parse(p.Template)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	// text/template needs comparable values; convert each secret to a string.
	// The rendered output is written only to the RAM file; these transient
	// string copies are freed by the GC.
	data := make(map[string]any, len(secrets))
	for k, v := range secrets {
		data[k] = string(v)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return buf.Bytes(), nil
}

// Dir returns the profiles directory (<config>/profiles), where <config> is
// $PARZIVAL_CONFIG_HOME if set, else $XDG_CONFIG_HOME/parzival, else
// ~/.config/parzival.
func Dir() string {
	return filepath.Join(configHome(), "profiles")
}

func configHome() string {
	if p := os.Getenv("PARZIVAL_CONFIG_HOME"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "parzival")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "parzival")
}
