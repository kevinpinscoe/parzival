package consumer

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// teaDefinition is the worked example the stage-1 acceptance criteria were
// originally written against.
const teaDefinition = `{
  "schema": 1,
  "name": "tea",
  "executable": "/usr/bin/tea",
  "profile": "tea-gitea-config",
  "operations": {
    "repos-list": {
      "argv": ["repos", "list", "--owner", "${owner}", "--output", "json"],
      "inputs": {
        "owner": { "pattern": "[A-Za-z0-9][A-Za-z0-9._-]{0,38}", "max_length": 39 }
      },
      "response": "json"
    }
  }
}`

func mustParse(t *testing.T, src string) *Definition {
	t.Helper()
	d, err := Parse([]byte(src), "test.json")
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return d
}

func parseErr(t *testing.T, src string) string {
	t.Helper()
	if _, err := Parse([]byte(src), "test.json"); err != nil {
		return err.Error()
	}
	t.Fatal("Parse: expected an error, got none")
	return ""
}

// --- the definition is a trust-root file, so parsing is strict ---------------

func TestParseRejectsUnknownField(t *testing.T) {
	// The rule policy.Parse follows, for the same reason: a constraint this
	// binary is too old to read must not become an absent constraint.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["x"],"response":"text"}},
	         "sandbox":"strict"}`
	if got := parseErr(t, src); !strings.Contains(got, "sandbox") {
		t.Errorf("error should name the unknown field, got: %s", got)
	}
}

func TestParseRejectsNewerSchema(t *testing.T) {
	src := `{"schema":99,"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["x"],"response":"text"}}}`
	if got := parseErr(t, src); !strings.Contains(got, "schema 99") {
		t.Errorf("error should name the declared schema, got: %s", got)
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	if got := parseErr(t, teaDefinition+`{"name":"other"}`); !strings.Contains(got, "trailing data") {
		t.Errorf("expected a trailing-data error, got: %s", got)
	}
}

func TestParseValidatesExecutable(t *testing.T) {
	for _, tc := range []struct{ name, exe, want string }{
		{"empty", "", "executable is required"},
		{"relative", "tea", "absolute path"},
		{"relative with dir", "./bin/tea", "absolute path"},
		{"traversal", "/usr/bin/../bin/tea", "clean path"},
		{"trailing slash", "/usr/bin/tea/", "clean path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `{"name":"tea","executable":"` + tc.exe + `","profile":"p",
			         "operations":{"o":{"argv":["x"],"response":"text"}}}`
			if got := parseErr(t, src); !strings.Contains(got, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, got)
			}
		})
	}
}

func TestParseRejectsProfilePath(t *testing.T) {
	// The profile is resolved against the broker's own root-owned directory. A
	// definition naming a path could reach outside it.
	for _, p := range []string{"", "../elsewhere/p", "sub/p", "..", ".", `a\\b`, "Tea", "-lead", "p p"} {
		src := `{"name":"tea","executable":"/usr/bin/tea","profile":"` + p + `",
		         "operations":{"o":{"argv":["x"],"response":"text"}}}`
		if got := parseErr(t, src); !strings.Contains(got, "bare profile name") {
			t.Errorf("profile %q: expected a bare-name error, got: %s", p, got)
		}
	}
	// And the ordinary case still parses.
	if d := mustParse(t, teaDefinition); d.Profile != "tea-gitea-config" {
		t.Errorf("profile = %q", d.Profile)
	}
}

func TestParseRejectsEmptyOperations(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p","operations":{}}`
	if got := parseErr(t, src); !strings.Contains(got, "no operations defined") {
		t.Errorf("expected a no-operations error, got: %s", got)
	}
}

func TestParseRejectsUndeclaredPlaceholder(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["--owner","${owner}"],"response":"text"}}}`
	if got := parseErr(t, src); !strings.Contains(got, "not a declared input") {
		t.Errorf("expected an undeclared-input error, got: %s", got)
	}
}

func TestParseRejectsUnreferencedInput(t *testing.T) {
	// A declared-but-unused input means the author believes a value is
	// constrained and reaching the consumer. It is not.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["list"],
	         "inputs":{"owner":{"pattern":"[a-z]+"}},"response":"text"}}}`
	if got := parseErr(t, src); !strings.Contains(got, "never referenced by argv") {
		t.Errorf("expected an unreferenced-input error, got: %s", got)
	}
}

func TestParseRequiresInputPattern(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["${owner}"],
	         "inputs":{"owner":{}},"response":"text"}}}`
	if got := parseErr(t, src); !strings.Contains(got, "pattern is required") {
		t.Errorf("expected a missing-pattern error, got: %s", got)
	}
}

func TestParseValidatesResponse(t *testing.T) {
	for _, tc := range []struct{ resp, want string }{
		{"", "response is required"},
		{"yaml", `must be "json" or "text"`},
	} {
		src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
		         "operations":{"o":{"argv":["x"],"response":"` + tc.resp + `"}}}`
		if got := parseErr(t, src); !strings.Contains(got, tc.want) {
			t.Errorf("response %q: expected %q, got: %s", tc.resp, tc.want, got)
		}
	}
}

func TestParseRejectsUnterminatedPlaceholder(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["${owner"],"response":"text"}}}`
	if got := parseErr(t, src); !strings.Contains(got, "unterminated") {
		t.Errorf("expected an unterminated-placeholder error, got: %s", got)
	}
}

// --- input validation is the part a client can actually reach ---------------

func TestPatternIsAnchoredByThePackage(t *testing.T) {
	// The definition's author wrote an unanchored pattern. If the package
	// honoured it as written, a substring match would accept anything with a
	// valid-looking prefix — validation that looks present and is not. This is
	// the single most load-bearing test in the package.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"repos-list":{"argv":["--owner","${owner}"],
	         "inputs":{"owner":{"pattern":"[a-z]+"}},"response":"json"}}}`
	d := mustParse(t, src)

	if _, err := d.BuildArgv("repos-list", map[string]string{"owner": "acme"}); err != nil {
		t.Fatalf("a valid owner should be accepted: %v", err)
	}
	for _, bad := range []string{"acme extra", "acme;id", "acme/../../etc", "ACME", "acme "} {
		if _, err := d.BuildArgv("repos-list", map[string]string{"owner": bad}); err == nil {
			t.Errorf("owner %q was accepted by an unanchored pattern", bad)
		}
	}
}

func TestBuildArgvWorkedExample(t *testing.T) {
	d := mustParse(t, teaDefinition)
	got, err := d.BuildArgv("repos-list", map[string]string{"owner": "acme"})
	if err != nil {
		t.Fatalf("BuildArgv: %v", err)
	}
	want := []string{"/usr/bin/tea", "repos", "list", "--owner", "acme", "--output", "json"}
	if !slices.Equal(got, want) {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestBuildArgvRejectsUnknownOperation(t *testing.T) {
	d := mustParse(t, teaDefinition)
	if _, err := d.BuildArgv("repos-delete", map[string]string{"owner": "acme"}); err == nil {
		t.Fatal("an operation the definition does not declare was accepted")
	}
}

// TestClientCannotSelectItsOwnTarget is the acceptance criterion stated
// directly: the client may name an operation and validated inputs, and nothing
// else. There is no field for an executable, a profile, a config path, an
// environment variable, or a raw flag, so each arrives as an unknown input.
func TestClientCannotSelectItsOwnTarget(t *testing.T) {
	d := mustParse(t, teaDefinition)
	for _, attempt := range []string{"executable", "profile", "config", "env", "XDG_CONFIG_HOME", "flags", "output"} {
		inputs := map[string]string{"owner": "acme", attempt: "/bin/cat"}
		if _, err := d.BuildArgv("repos-list", inputs); err == nil {
			t.Errorf("input %q was accepted; a client must not be able to select its own target", attempt)
		} else if !strings.Contains(err.Error(), "unknown input") {
			t.Errorf("input %q: expected an unknown-input error, got: %v", attempt, err)
		}
	}
}

func TestBuildArgvRequiresDeclaredInputs(t *testing.T) {
	d := mustParse(t, teaDefinition)
	if _, err := d.BuildArgv("repos-list", nil); err == nil {
		t.Fatal("a missing required input was accepted")
	}
}

func TestBuildArgvOptionalInput(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["list","${owner}"],
	         "inputs":{"owner":{"pattern":"[a-z]*","optional":true}},"response":"text"}}}`
	d := mustParse(t, src)
	got, err := d.BuildArgv("o", nil)
	if err != nil {
		t.Fatalf("an omitted optional input should substitute empty: %v", err)
	}
	if !slices.Equal(got, []string{"/usr/bin/tea", "list", ""}) {
		t.Errorf("argv = %q", got)
	}
}

func TestBuildArgvRejectsControlCharacters(t *testing.T) {
	// Checked independently of the pattern: a pattern is written about the
	// shape of a valid value, not about what a NUL or a newline does to a
	// consumer's argument parsing or to whoever later reads its log.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["${v}"],
	         "inputs":{"v":{"pattern":"(?s).*"}},"response":"text"}}}`
	d := mustParse(t, src)
	for name, bad := range map[string]string{
		"NUL":       "acme\x00rm",
		"newline":   "acme\nrm -rf /",
		"CR":        "acme\rrm",
		"tab":       "acme\trm",
		"escape":    "acme\x1b[2J",
		"backspace": "acme\bx",
	} {
		if _, err := d.BuildArgv("o", map[string]string{"v": bad}); err == nil {
			t.Errorf("%s: a control character was accepted", name)
		}
	}
}

func TestBuildArgvRejectsLeadingDash(t *testing.T) {
	// An argv element beginning with "-" is read as an option by essentially
	// every consumer, which would let a client change what the fixed argv means
	// without ever naming a flag.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["list","${v}"],
	         "inputs":{"v":{"pattern":"[-A-Za-z]+"}},"response":"text"}}}`
	d := mustParse(t, src)
	if _, err := d.BuildArgv("o", map[string]string{"v": "--token"}); err == nil {
		t.Fatal("a value beginning with a dash was accepted without allow_leading_dash")
	}

	optIn := strings.Replace(src, `"pattern":"[-A-Za-z]+"`, `"pattern":"[-A-Za-z]+","allow_leading_dash":true`, 1)
	d2 := mustParse(t, optIn)
	if _, err := d2.BuildArgv("o", map[string]string{"v": "--token"}); err != nil {
		t.Fatalf("allow_leading_dash should permit it: %v", err)
	}
}

func TestBuildArgvEnforcesMaxLength(t *testing.T) {
	d := mustParse(t, teaDefinition)
	if _, err := d.BuildArgv("repos-list", map[string]string{"owner": strings.Repeat("a", 40)}); err == nil {
		t.Fatal("a value over max_length was accepted")
	}

	// And the default applies when the definition sets no bound.
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["${v}"],
	         "inputs":{"v":{"pattern":"a*"}},"response":"text"}}}`
	d2 := mustParse(t, src)
	if _, err := d2.BuildArgv("o", map[string]string{"v": strings.Repeat("a", defaultMaxInputLength+1)}); err == nil {
		t.Fatalf("a value over the %d-byte default was accepted", defaultMaxInputLength)
	}
}

// TestArgvStaysAVector guards the property the whole design rests on: a value
// containing spaces, quotes, or shell metacharacters becomes exactly one argv
// element. Nothing here is ever joined into a command line.
func TestArgvStaysAVector(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["list","${v}","--json"],
	         "inputs":{"v":{"pattern":"[^\\x00-\\x1f]*"}},"response":"text"}}}`
	d := mustParse(t, src)
	for _, v := range []string{`a b c`, `a" "b`, `$(id)`, "`id`", `a;id`, `a|id`, `*`} {
		got, err := d.BuildArgv("o", map[string]string{"v": v})
		if err != nil {
			t.Fatalf("value %q: %v", v, err)
		}
		if len(got) != 4 {
			t.Errorf("value %q produced %d argv elements, want 4: %q", v, len(got), got)
		}
		if got[2] != v {
			t.Errorf("value %q was altered to %q", v, got[2])
		}
	}
}

func TestEmbeddedPlaceholder(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["--owner=${owner}"],
	         "inputs":{"owner":{"pattern":"[a-z]+"}},"response":"text"}}}`
	d := mustParse(t, src)
	got, err := d.BuildArgv("o", map[string]string{"owner": "acme"})
	if err != nil {
		t.Fatalf("BuildArgv: %v", err)
	}
	if !slices.Equal(got, []string{"/usr/bin/tea", "--owner=acme"}) {
		t.Errorf("argv = %q", got)
	}
}

// TestValidationErrorsNeverEchoTheValue keeps a narrow input pattern from
// becoming an oracle a client can question one guess at a time — and keeps the
// value out of any log the error is later written to.
func TestValidationErrorsNeverEchoTheValue(t *testing.T) {
	src := `{"name":"tea","executable":"/usr/bin/tea","profile":"p",
	         "operations":{"o":{"argv":["${v}"],
	         "inputs":{"v":{"pattern":"[a-z]+","max_length":4}},"response":"text"}}}`
	d := mustParse(t, src)
	const secretish = "hunter2ZZZ"
	for _, v := range []string{secretish, "-" + secretish, secretish + "\x00"} {
		_, err := d.BuildArgv("o", map[string]string{"v": v})
		if err == nil {
			t.Fatalf("value %q should have been refused", v)
		}
		if strings.Contains(err.Error(), secretish) {
			t.Errorf("error echoed the rejected value: %v", err)
		}
	}
}

// --- loading -----------------------------------------------------------------

func TestLoadFromConfigDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PARZIVAL_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "consumers"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "consumers", "tea.json"), []byte(teaDefinition), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Load("tea")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Name != "tea" || d.Executable != "/usr/bin/tea" {
		t.Errorf("loaded %+v", d)
	}
}

func TestLoadRejectsPathTraversalInName(t *testing.T) {
	t.Setenv("PARZIVAL_CONFIG_HOME", t.TempDir())
	for _, name := range []string{"../policy", "sub/tea", "", ".", "Tea", `a\b`} {
		if _, err := Load(name); err == nil {
			t.Errorf("Load(%q) should have been refused", name)
		}
	}
}

func TestBuildArgvRefusesUncompiledDefinition(t *testing.T) {
	// A Definition built in Go rather than through Parse has no compiled
	// pattern. The safe answer to "is this value allowed" is then no, not yes.
	d := &Definition{
		Name:       "tea",
		Executable: "/usr/bin/tea",
		Profile:    "p",
		Operations: map[string]Operation{
			"o": {Argv: []string{"${v}"}, Inputs: map[string]Input{"v": {Pattern: "[a-z]+"}}, Response: ResponseText},
		},
	}
	if _, err := d.BuildArgv("o", map[string]string{"v": "acme"}); err == nil {
		t.Fatal("an unvalidated definition accepted an input")
	}
}

// TestShippedExampleParses keeps examples/consumers/ from rotting away from the
// validator. An example that no longer parses is worse than none: it is the
// first thing an administrator copies.
func TestShippedExampleParses(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "examples", "consumers", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no example consumer definitions found")
	}
	for _, path := range matches {
		d, err := LoadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		// And every declared operation builds an argv from a value its own
		// pattern accepts, so an example cannot ship a constraint that admits
		// nothing.
		for opName, op := range d.Operations {
			inputs := map[string]string{}
			for inName := range op.Inputs {
				inputs[inName] = "example"
			}
			if _, err := d.BuildArgv(opName, inputs); err != nil {
				t.Errorf("%s: operation %q rejected a plausible input: %v", path, opName, err)
			}
		}
	}
}

// --- LoadAll -----------------------------------------------------------------

func writeDef(t *testing.T, dir, filename, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func TestLoadAllParsesEveryDefinition(t *testing.T) {
	dir := t.TempDir()
	writeDef(t, dir, "tea.json", teaDefinition)
	other := `{"schema":1,"name":"other","executable":"/usr/bin/other","profile":"p",
	           "operations":{"o":{"argv":["x"],"response":"text"}}}`
	writeDef(t, dir, "other.json", other)
	writeDef(t, dir, "README.md", "not a definition, and not .json")

	defs, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: unexpected error: %v", err)
	}
	if len(defs) != 2 {
		t.Fatalf("LoadAll: got %d definitions, want 2 (got keys %v)", len(defs), sortedKeys(defs))
	}
	if defs["tea"] == nil || defs["tea"].Name != "tea" {
		t.Errorf("LoadAll: missing or mis-keyed %q", "tea")
	}
	if defs["other"] == nil || defs["other"].Name != "other" {
		t.Errorf("LoadAll: missing or mis-keyed %q", "other")
	}
}

func TestLoadAllRejectsDuplicateName(t *testing.T) {
	dir := t.TempDir()
	// Two different files, same declared consumer Name — an ambiguity this
	// package refuses rather than letting file order decide silently.
	writeDef(t, dir, "a.json", teaDefinition)
	writeDef(t, dir, "b.json", teaDefinition)

	_, err := LoadAll(dir)
	if err == nil {
		t.Fatal("LoadAll: expected an error for duplicate consumer name, got none")
	}
	if !strings.Contains(err.Error(), "tea") {
		t.Errorf("LoadAll: error should name the duplicated consumer, got: %v", err)
	}
}

func TestLoadAllMissingDirReturnsEmpty(t *testing.T) {
	defs, err := LoadAll(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadAll: unexpected error for a missing directory: %v", err)
	}
	if defs != nil {
		t.Errorf("LoadAll: got %v, want nil for a missing directory", defs)
	}
}

func TestLoadAllRejectsAnInvalidDefinitionInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	writeDef(t, dir, "tea.json", teaDefinition)
	writeDef(t, dir, "broken.json", `{"schema":1,"name":"broken"}`) // missing executable/profile/operations

	_, err := LoadAll(dir)
	if err == nil {
		t.Fatal("LoadAll: expected an error for an invalid definition, got none")
	}
}
