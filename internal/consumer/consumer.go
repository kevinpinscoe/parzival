// Package consumer defines and validates consumer definitions: the
// administrator's statement of which fixed executable may use a brokered
// credential, and which named operations a client may cause it to run.
//
// A profile (internal/profile) says how to prepare a consumer's credentials. A
// consumer definition says exactly which invocations of that consumer a client
// may ask for. The two are deliberately separate files with different owners: a
// profile is a rendering recipe, while a definition is a trust-root statement
// and lives somewhere the client cannot write.
//
// Nothing here fetches, renders, or handles a secret. This package turns a
// client's named operation plus its typed inputs into an argv vector, or
// refuses. It is the part of the boundary that can be reasoned about — and
// tested — without a daemon; see SERVICE-PROTOCOL.md for the interface it
// serves and THREAT-MODEL.md §4d for what the boundary does and does not cover.
package consumer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// SchemaVersion is the consumer-definition format this binary understands. A
// definition declaring a higher version is refused rather than partially
// applied, for the same reason policy.SchemaVersion exists: strict parsing
// catches a new field an old binary would ignore, but only a version number
// catches a field whose meaning changed without its name changing.
const SchemaVersion = 1

// Response shapes a consumer's stdout may be validated against.
const (
	ResponseJSON = "json"
	ResponseText = "text"
)

// defaultMaxInputLength bounds an input whose definition does not set one. It is
// deliberately small: an operation that genuinely needs more says so, and the
// author of a definition that does not say so has not thought about it.
const defaultMaxInputLength = 256

// Definition is one consumer: a fixed executable, the profile that prepares its
// credential, and the closed set of operations a client may request.
type Definition struct {
	// Schema is the definition format version. 0 means unspecified.
	Schema int `json:"schema,omitempty"`
	// Name is the consumer's name, and the first half of an operation's
	// qualified name ("tea" in "tea.repos-list").
	Name string `json:"name"`
	// Description is free text for the administrator. It is never matched on,
	// and never reaches a client. It is a declared field because parsing
	// rejects unknown ones, so an ad-hoc "comment" key would refuse the file.
	Description string `json:"description,omitempty"`
	// Executable is the absolute path of the binary the broker runs. It is
	// never supplied, influenced, or selected by a client.
	Executable string `json:"executable"`
	// Profile names the parzival profile that renders this consumer's
	// credential. A bare name, resolved by the broker against its own
	// root-owned profile directory.
	Profile string `json:"profile"`
	// Operations is the closed set of invocations a client may request. A
	// consumer with no operations grants nothing and is refused, because an
	// empty allowlist in a file whose purpose is to allow is far more likely
	// to be a truncated edit than an intention.
	Operations map[string]Operation `json:"operations"`
}

// Operation is one permitted invocation of a consumer.
type Operation struct {
	// Description is free text for the administrator; see Definition.Description.
	Description string `json:"description,omitempty"`
	// Argv is the argument vector, excluding argv[0]. An element may contain
	// ${name} placeholders naming declared inputs. It is a vector and is never
	// joined into a string — nothing here is parsed by a shell.
	Argv []string `json:"argv"`
	// Inputs declares the values a client may supply, and what each may be.
	Inputs map[string]Input `json:"inputs,omitempty"`
	// Response is the shape the consumer's stdout is validated against:
	// ResponseJSON or ResponseText.
	Response string `json:"response"`
	// TimeoutSeconds bounds the operation. 0 means the broker's default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// ResponseConfig is trusted, administrator-owned configuration for this
	// operation's response validator: deployment facts the approved response
	// must be checked against, such as the exact origin a returned URL must
	// have. They belong to the deployment, not the product, so they live here
	// in the root-owned definition rather than compiled into the binary. They
	// are read only from this file and never from a client request. The
	// validator registered for the operation declares which keys it requires
	// and what values are valid; the broker refuses to start on a missing,
	// unknown or invalid key, and on configuration given to an operation whose
	// validator takes none.
	ResponseConfig map[string]string `json:"response_config,omitempty"`
}

// maxResponseConfigValue bounds one response_config value in bytes. These are
// short deployment facts (an origin, an identifier), not documents.
const maxResponseConfigValue = 1024

// Input constrains one client-supplied value.
type Input struct {
	// Description is free text for the administrator; see Definition.Description.
	Description string `json:"description,omitempty"`
	// Pattern is an RE2 expression the value must match. It is anchored by this
	// package rather than by its author — an unanchored pattern that matches a
	// substring is the classic way a validated input turns out not to be.
	Pattern string `json:"pattern"`
	// MaxLength bounds the value in bytes. 0 means defaultMaxInputLength.
	MaxLength int `json:"max_length,omitempty"`
	// Optional marks an input the client may omit. An omitted optional input
	// substitutes as the empty string.
	Optional bool `json:"optional,omitempty"`
	// AllowLeadingDash permits a value beginning with "-". Without it such a
	// value is refused, because an argv element beginning with a dash is read
	// as an option by essentially every consumer — which would let a client
	// change what the fixed argv means without ever naming a flag.
	AllowLeadingDash bool `json:"allow_leading_dash,omitempty"`

	re *regexp.Regexp // compiled during validation; never serialized
}

// Parse decodes and validates consumer-definition bytes. name appears in error
// messages so a candidate file reports its own name.
func Parse(data []byte, name string) (*Definition, error) {
	if name == "" {
		name = "consumer definition"
	}

	// Reject unknown fields instead of ignoring them. A definition written for
	// a newer parzival than the installed binary would otherwise degrade in
	// silence: an unread "inputs" constraint, or an unread bound on what an
	// operation may do, becomes an absent one. Refusing to run beats enforcing
	// less than the administrator wrote.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d Definition
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	// Anything after the first JSON value means the file is not what it looks
	// like — a truncated edit, a stray second object. Do not guess which half
	// to obey.
	if dec.More() {
		return nil, fmt.Errorf("parse %s: trailing data after the consumer definition", name)
	}
	if err := d.validate(name); err != nil {
		return nil, err
	}
	return &d, nil
}

// LoadFile reads and validates a consumer definition from path.
func LoadFile(path string) (*Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("consumer definition: %w", err)
	}
	return Parse(data, filepath.Base(path))
}

// Load reads the named consumer definition from the consumers directory.
func Load(name string) (*Definition, error) {
	if !validName(name) {
		return nil, fmt.Errorf("invalid consumer name %q", name)
	}
	return LoadFile(filepath.Join(Dir(), name+".json"))
}

// LoadAll reads and validates every *.json file in dir as a consumer
// definition, keyed by each definition's own Name — not its filename, though
// every shipped definition keeps the two equal for readability. A missing dir
// returns (nil, nil): whether zero consumers is fatal is a decision for the
// caller (a broker refuses to start on it; a generic loader should not assume
// that for every caller). Two files declaring the same consumer Name is
// refused rather than letting the lexicographically later file silently win —
// ambiguity in a trust root is refused, not resolved by file ordering.
func LoadAll(dir string) (map[string]*Definition, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("consumer definitions: read %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	defs := make(map[string]*Definition, len(names))
	sources := make(map[string]string, len(names)) // Definition.Name -> filename that declared it
	for _, name := range names {
		def, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if prior, ok := sources[def.Name]; ok {
			return nil, fmt.Errorf("consumer definitions: %q and %q both declare consumer %q", prior, name, def.Name)
		}
		defs[def.Name] = def
		sources[def.Name] = name
	}
	return defs, nil
}

// Dir returns the consumer-definition directory (<config>/consumers).
//
// In a deployed service mode this directory is root-owned and not writable by
// the client identity; VerifyTrustRoot checks that, and the broker refuses to
// start when it does not hold.
func Dir() string { return filepath.Join(configHome(), "consumers") }

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

// nameRE is the shape of a consumer name, an operation name, and an input name.
// Restrictive on purpose: these names appear in a qualified operation string, in
// argv placeholders, and in audit records, and a name needing quoting in any of
// those is a name that will eventually be mis-split.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func validName(s string) bool { return nameRE.MatchString(s) }

func (d *Definition) validate(file string) error {
	if d.Schema > SchemaVersion {
		return fmt.Errorf("%s declares schema %d but this parzival understands %d — upgrade parzival (refusing rather than enforcing a weaker rule than written)",
			file, d.Schema, SchemaVersion)
	}
	if d.Schema < 0 {
		return fmt.Errorf("%s declares a negative schema %d", file, d.Schema)
	}
	if !validName(d.Name) {
		return fmt.Errorf("%s: consumer name %q must match %s", file, d.Name, nameRE)
	}
	if err := validateExecutable(d.Executable); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	// The broker resolves this against its own root-owned profile directory, so
	// a name that is a path — or that merely contains something a path
	// separator could later be made of — is refused outright rather than
	// cleaned up. Same shape as a consumer name, for the same reason.
	if !validName(d.Profile) {
		return fmt.Errorf("%s: profile %q must be a bare profile name matching %s, not a path", file, d.Profile, nameRE)
	}
	if len(d.Operations) == 0 {
		return fmt.Errorf("%s: no operations defined — a consumer definition that permits nothing is more likely truncated than intended", file)
	}
	for _, opName := range sortedKeys(d.Operations) {
		if !validName(opName) {
			return fmt.Errorf("%s: operation name %q must match %s", file, opName, nameRE)
		}
		op := d.Operations[opName]
		if err := op.validate(); err != nil {
			return fmt.Errorf("%s: operation %q: %w", file, opName, err)
		}
		d.Operations[opName] = op // keep the compiled input patterns
	}
	return nil
}

// validateExecutable requires an absolute, clean path. A relative path would be
// resolved against the broker's working directory, and a path containing ".."
// hides what it actually names from whoever reviews the definition — which is
// the one thing a trust-root file has to be good at.
func validateExecutable(path string) error {
	if path == "" {
		return fmt.Errorf("executable is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("executable %q must be an absolute path", path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("executable %q must be a clean path (no \"..\", no trailing or repeated separators)", path)
	}
	return nil
}

func (op *Operation) validate() error {
	switch op.Response {
	case ResponseJSON, ResponseText:
	case "":
		return fmt.Errorf("response is required (%q or %q)", ResponseJSON, ResponseText)
	default:
		return fmt.Errorf("response %q must be %q or %q", op.Response, ResponseJSON, ResponseText)
	}
	if op.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds %d must not be negative", op.TimeoutSeconds)
	}
	for _, key := range sortedKeys(op.ResponseConfig) {
		if !validName(key) {
			return fmt.Errorf("response_config key %q must match %s", key, nameRE)
		}
		v := op.ResponseConfig[key]
		if v == "" {
			return fmt.Errorf("response_config %q must not be empty", key)
		}
		if len(v) > maxResponseConfigValue {
			return fmt.Errorf("response_config %q is longer than %d bytes", key, maxResponseConfigValue)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("response_config %q contains a control character", key)
			}
		}
	}
	for inName := range op.Inputs {
		if !validName(inName) {
			return fmt.Errorf("input name %q must match %s", inName, nameRE)
		}
		in := op.Inputs[inName]
		if err := in.compile(); err != nil {
			return fmt.Errorf("input %q: %w", inName, err)
		}
		op.Inputs[inName] = in
	}

	referenced := map[string]bool{}
	for i, elem := range op.Argv {
		names, err := placeholders(elem)
		if err != nil {
			return fmt.Errorf("argv[%d] %q: %w", i, elem, err)
		}
		for _, n := range names {
			if _, ok := op.Inputs[n]; !ok {
				return fmt.Errorf("argv[%d] references ${%s}, which is not a declared input", i, n)
			}
			referenced[n] = true
		}
	}
	// An input nothing substitutes is either a typo in the placeholder or a
	// leftover from an edit. Either way the administrator believes a value is
	// constrained and reaching the consumer, and it is not.
	for _, inName := range sortedKeys(op.Inputs) {
		if !referenced[inName] {
			return fmt.Errorf("input %q is declared but never referenced by argv", inName)
		}
	}
	return nil
}

func (in *Input) compile() error {
	if in.Pattern == "" {
		return fmt.Errorf("pattern is required — an input with no pattern is not validated")
	}
	if in.MaxLength < 0 {
		return fmt.Errorf("max_length %d must not be negative", in.MaxLength)
	}
	// Anchor here rather than trusting the author to have done it. An
	// unanchored pattern matches a substring, so "^[a-z]+$" written as "[a-z]+"
	// accepts "acme; rm -rf /" — validation that looks present and is not.
	re, err := regexp.Compile(`\A(?:` + in.Pattern + `)\z`)
	if err != nil {
		return fmt.Errorf("pattern %q does not compile: %w", in.Pattern, err)
	}
	in.re = re
	return nil
}

// maxLength returns the effective byte bound for this input.
func (in Input) maxLength() int {
	if in.MaxLength > 0 {
		return in.MaxLength
	}
	return defaultMaxInputLength
}

// BuildArgv validates inputs against the named operation and returns the full
// argv vector to execute, with the definition's absolute executable at index 0.
//
// It is the only path from client-supplied data to something that gets executed,
// and it is a vector throughout: no element is ever joined, quoted, or handed to
// a shell. A refusal here means no credential is fetched, because the broker
// validates before it touches the store (SERVICE-PROTOCOL.md, "Serving one
// request", steps 6 and 7).
func (d *Definition) BuildArgv(opName string, inputs map[string]string) ([]string, error) {
	op, ok := d.Operations[opName]
	if !ok {
		return nil, fmt.Errorf("unknown operation %q for consumer %q", opName, d.Name)
	}

	// An input the operation does not declare is refused rather than dropped. A
	// client sending one is asking for something, and silently ignoring it
	// leaves the client believing it got it.
	for _, given := range sortedKeys(inputs) {
		if _, ok := op.Inputs[given]; !ok {
			return nil, fmt.Errorf("operation %q: unknown input %q", opName, given)
		}
	}

	values := make(map[string]string, len(op.Inputs))
	for _, inName := range sortedKeys(op.Inputs) {
		in := op.Inputs[inName]
		v, present := inputs[inName]
		if !present {
			if !in.Optional {
				return nil, fmt.Errorf("operation %q: input %q is required", opName, inName)
			}
			values[inName] = ""
			continue
		}
		if err := in.check(v); err != nil {
			// The value is never echoed back. An operation with a narrow
			// pattern would otherwise answer "was it this?" one guess at a
			// time, and the client's own value is not always the client's own
			// secret to be shown in a log.
			return nil, fmt.Errorf("operation %q: input %q: %w", opName, inName, err)
		}
		values[inName] = v
	}

	argv := make([]string, 0, len(op.Argv)+1)
	argv = append(argv, d.Executable)
	for i, elem := range op.Argv {
		rendered, err := substitute(elem, values)
		if err != nil {
			return nil, fmt.Errorf("operation %q: argv[%d]: %w", opName, i, err)
		}
		argv = append(argv, rendered)
	}
	return argv, nil
}

// check applies this input's bounds to a client-supplied value.
func (in Input) check(v string) error {
	if in.re == nil {
		// Unreachable through Parse, which compiles every pattern. Reaching it
		// means a Definition was built by hand and never validated, and the
		// safe answer to "is this value allowed" with no pattern is no.
		return fmt.Errorf("input has no compiled pattern (definition was not validated)")
	}
	if len(v) > in.maxLength() {
		return fmt.Errorf("value is %d bytes, over the %d-byte limit", len(v), in.maxLength())
	}
	// Checked independently of the pattern. A pattern is written by a human who
	// was thinking about the shape of a valid value, not about what a NUL, a
	// newline, or an escape sequence does to a consumer's argument parsing, its
	// log file, or the terminal of whoever later reads that log.
	for _, r := range v {
		if r == 0 {
			return fmt.Errorf("value contains a NUL byte")
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("value contains a control character")
		}
	}
	if !in.AllowLeadingDash && strings.HasPrefix(v, "-") {
		return fmt.Errorf("value begins with %q, which a consumer reads as an option (set allow_leading_dash if that is intended)", "-")
	}
	if !in.re.MatchString(v) {
		return fmt.Errorf("value does not match the declared pattern")
	}
	return nil
}

// placeholders returns the input names referenced by ${name} in s, in order of
// appearance. A "$" not followed by "{" is a literal dollar sign.
func placeholders(s string) ([]string, error) {
	var names []string
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return nil, fmt.Errorf("unterminated ${ ... } placeholder")
		}
		name := s[i+2 : i+2+end]
		if !validName(name) {
			return nil, fmt.Errorf("placeholder ${%s} is not a valid input name", name)
		}
		names = append(names, name)
		i += 2 + end
	}
	return names, nil
}

// substitute replaces every ${name} in s with its value. Values have already
// been checked by Input.check; substitution itself performs no escaping and
// needs none, because the result is one element of an argv vector rather than
// part of a command line.
func substitute(s string, values map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			b.WriteByte(s[i])
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ ... } placeholder")
		}
		name := s[i+2 : i+2+end]
		v, ok := values[name]
		if !ok {
			return "", fmt.Errorf("no value for ${%s}", name)
		}
		b.WriteString(v)
		i += 2 + end
	}
	return b.String(), nil
}

// sortedKeys returns m's keys in sorted order, so that validation and error
// reporting are deterministic rather than depending on Go's map iteration.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
