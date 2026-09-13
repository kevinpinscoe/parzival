// Package policy gates every secret fetch behind an approval policy keyed to the
// secret reference, a self-asserted identity label, and the current time.
//
// The posture is strict deny-by-default: with no policy file, nothing is allowed;
// with a policy file, a request is allowed only if some rule matches it. This is
// advisory provenance + audit + mistake-prevention, NOT a same-uid security
// boundary (see THREAT-MODEL.md) — a co-resident same-uid process can bypass
// parzival entirely. Every decision is written to an append-only audit log.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Delivery modes. The mode says how the value reaches the consumer, which
// decides whether it can end up in a recording sink (log, transcript, CI
// output). ModeGet writes the raw value to stdout or a caller-supplied fd, so
// the caller — not parzival — controls where it lands. ModeExec and ModeMount
// place it in a 0600 RAM file the consumer opens directly, so there is no
// stream to capture. See THREAT-MODEL.md §4b.
const (
	ModeGet   = "get"
	ModeExec  = "exec"
	ModeMount = "mount"
)

func knownMode(m string) bool {
	return m == ModeGet || m == ModeExec || m == ModeMount
}

// Request is one authorization query.
type Request struct {
	Ref      string    // the secret reference being fetched
	Identity string    // self-asserted label from --as / $PARZIVAL_IDENTITY (may be empty)
	Mode     string    // delivery mode: ModeGet, ModeExec or ModeMount
	Time     time.Time // evaluation time (local)
	Caller   string    // optional provenance (e.g. a mount open() caller uid/pid/exe); logged, never matched
}

// Rule allows or denies requests matching all of its non-empty conditions.
type Rule struct {
	Allow bool `json:"allow"`
	// Description is free-text for the operator; it is never matched on. It
	// exists as a declared field because parsing rejects unknown ones, so an
	// ad-hoc "comment" key would refuse the whole policy.
	Description string   `json:"description,omitempty"`
	Secrets     []string `json:"secrets,omitempty"`    // globs on the ref (* and ? wildcards)
	Identities  []string `json:"identities,omitempty"` // globs on the identity label
	Modes       []string `json:"modes,omitempty"`      // delivery modes this rule covers: get / exec / mount
	Weekdays    []string `json:"weekdays,omitempty"`   // e.g. "Mon", "Monday" (case-insensitive)
	Monthdays   []int    `json:"monthdays,omitempty"`  // 1..31
	Hours       string   `json:"hours,omitempty"`      // "HH:MM-HH:MM" local; supports wrap-around
}

// SchemaVersion is the policy format this binary understands. A policy.json may
// declare a "schema"; if it names a higher version, Load refuses the file rather
// than enforcing less than the operator wrote.
//
// It exists alongside unknown-field rejection because the two catch different
// regressions: unknown-field rejection catches a *new field* an old binary would
// ignore, while the schema catches a field whose *meaning* changed without its
// name changing (which no amount of parsing strictness can detect).
const SchemaVersion = 1

// Policy is an ordered rule list; the first matching rule decides.
type Policy struct {
	Schema int    `json:"schema,omitempty"` // 0 = unspecified; > SchemaVersion is refused
	Rules  []Rule `json:"rules"`
}

// Decision is the outcome of evaluating a Request.
type Decision struct {
	Allow  bool
	Reason string
}

// DeniedError is returned by Authorize when a request is not allowed.
type DeniedError struct {
	Req    Request
	Reason string
}

func (e *DeniedError) Error() string {
	id := e.Req.Identity
	if id == "" {
		id = "(none)"
	}
	msg := fmt.Sprintf("denied by policy: ref %q identity %s mode %s at %s — %s (define an allow-rule in %s; see examples/policy.json)",
		e.Req.Ref, id, e.Req.Mode, e.Req.Time.Format("Mon 15:04"), e.Reason, filepath.Join(ConfigDir(), "policy.json"))
	// The commonest mode-based refusal, worth naming so it is not mistaken for a
	// missing rule: the identity is allowed brokered delivery but not the raw value.
	if e.Req.Mode == ModeGet {
		msg += "\nnote: if this identity is restricted to brokered delivery, use `parzival exec` or `parzival mount` — `get` writes the raw value to a stream the caller controls"
	}
	return msg
}

// Authorize loads the policy, evaluates r, writes an audit entry, and returns nil
// if allowed or a *DeniedError (or a load error) otherwise.
func Authorize(r Request) error {
	p, exists, err := Load()
	if err != nil {
		writeAudit(r, "ERROR", err.Error())
		return fmt.Errorf("policy: %w", err)
	}

	var d Decision
	switch {
	case !exists:
		d = Decision{Allow: false, Reason: "no policy file (strict deny-by-default)"}
	default:
		d = p.Evaluate(r)
	}

	if d.Allow {
		writeAudit(r, "ALLOW", d.Reason)
		return nil
	}
	writeAudit(r, "DENY", d.Reason)
	return &DeniedError{Req: r, Reason: d.Reason}
}

// Evaluate returns the decision for r: the first matching rule wins, else deny.
func (p *Policy) Evaluate(r Request) Decision {
	for i, rule := range p.Rules {
		if rule.matches(r) {
			return Decision{Allow: rule.Allow, Reason: fmt.Sprintf("rule %d", i)}
		}
	}
	return Decision{Allow: false, Reason: "no matching rule (default deny)"}
}

func (rule Rule) matches(r Request) bool {
	if len(rule.Secrets) > 0 && !anyWildcard(rule.Secrets, r.Ref) {
		return false
	}
	if len(rule.Identities) > 0 && !anyWildcard(rule.Identities, r.Identity) {
		return false
	}
	// An allowlist, deliberately: a rule listing ["exec","mount"] does not match a
	// get, which then falls through to default-deny. That is how an identity is
	// granted brokered delivery while being refused the raw value — and a mode
	// added in future is not silently granted by an existing rule.
	if len(rule.Modes) > 0 && !anyWildcard(rule.Modes, r.Mode) {
		return false
	}
	if len(rule.Weekdays) > 0 && !weekdayMatches(rule.Weekdays, r.Time) {
		return false
	}
	if len(rule.Monthdays) > 0 && !intIn(rule.Monthdays, r.Time.Day()) {
		return false
	}
	if rule.Hours != "" && !hoursMatch(rule.Hours, r.Time) {
		return false
	}
	return true
}

// Path returns the live policy file's location.
func Path() string { return filepath.Join(ConfigDir(), "policy.json") }

// Load reads the live policy file. It returns (policy, exists, error); exists is
// false when no file is present (the strict deny-by-default case).
func Load() (*Policy, bool, error) { return LoadFile(Path()) }

// LoadFile reads a policy from an arbitrary path, using exactly the parsing and
// validation the live policy gets. Editing tools validate a candidate through
// this — a second, more permissive parser written for the editor would let a
// candidate pass review and then be refused by the binary that has to enforce
// it, which is the failure the strictness below exists to prevent.
func LoadFile(path string) (*Policy, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	p, err := Parse(data, filepath.Base(path))
	if err != nil {
		return nil, true, err
	}
	return p, true, nil
}

// Parse decodes and validates policy bytes. name appears in error messages so a
// candidate file reports its own name rather than the live policy's.
func Parse(data []byte, name string) (*Policy, error) {
	if name == "" {
		name = "policy.json"
	}

	// Reject unknown fields instead of ignoring them. A policy written for a
	// newer parzival than the installed binary would otherwise degrade in
	// silence — a rule meant to restrict an identity to exec/mount loses its
	// unread "modes" field and becomes an unrestricted allow, with no warning.
	// Refusing to run beats quietly enforcing less than the operator wrote.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse %s: %w%s", name, err, staleBinaryHint(err))
	}
	// Anything after the first JSON value means the file is not what it looks
	// like (truncation, a stray second object); do not guess which half to obey.
	if dec.More() {
		return nil, fmt.Errorf("parse %s: trailing data after the policy object", name)
	}
	if err := p.validate(name); err != nil {
		return nil, err
	}
	return &p, nil
}

// staleBinaryHint appends the likely cause of an unknown-field error: the
// installed binary predates a field the policy uses.
func staleBinaryHint(err error) string {
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		return ""
	}
	return "\nthis parzival does not understand that field — it is probably older than the policy." +
		"\nrebuild/upgrade parzival, or remove the field. Refusing rather than enforcing a weaker rule than written."
}

// validate enforces the policy-level constraints that JSON decoding cannot:
// schema version, and per-rule value ranges. name identifies the file in error
// messages so a candidate reports its own name.
func (p *Policy) validate(name string) error {
	if name == "" {
		name = "policy.json"
	}
	if p.Schema > SchemaVersion {
		return fmt.Errorf("%s declares schema %d but this parzival understands %d — upgrade parzival (refusing rather than enforcing a weaker rule than written)",
			name, p.Schema, SchemaVersion)
	}
	if p.Schema < 0 {
		return fmt.Errorf("%s declares a negative schema %d", name, p.Schema)
	}
	for i, r := range p.Rules {
		if r.Hours != "" {
			if _, _, err := parseHours(r.Hours); err != nil {
				return fmt.Errorf("rule %d: bad hours %q: %w", i, r.Hours, err)
			}
		}
		for _, wd := range r.Weekdays {
			if _, ok := weekdayNum(wd); !ok {
				return fmt.Errorf("rule %d: unknown weekday %q", i, wd)
			}
		}
		for _, md := range r.Monthdays {
			if md < 1 || md > 31 {
				return fmt.Errorf("rule %d: monthday %d out of range 1..31", i, md)
			}
		}
		// Reject unknown modes loudly. A typo would otherwise make the rule match
		// nothing — failing closed, but silently, which reads as "policy ignored".
		if bad := slices.IndexFunc(r.Modes, func(m string) bool { return !knownMode(m) }); bad >= 0 {
			return fmt.Errorf("rule %d: unknown mode %q (want %s, %s or %s)",
				i, r.Modes[bad], ModeGet, ModeExec, ModeMount)
		}
	}
	return nil
}

// ConfigDir returns parzival's config directory: $PARZIVAL_CONFIG_HOME if set,
// else $XDG_CONFIG_HOME/parzival, else ~/.config/parzival. The dedicated
// override lets tooling isolate parzival's config without disturbing other tools
// (e.g. `op`) that also read $XDG_CONFIG_HOME.
func ConfigDir() string {
	if p := os.Getenv("PARZIVAL_CONFIG_HOME"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "parzival")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "parzival")
}

// stateDir returns $XDG_STATE_HOME/parzival or ~/.local/state/parzival.
func stateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "parzival")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "parzival")
}

// writeAudit appends one decision line to the audit log. It never records a
// secret value — only the reference. Best effort: a logging failure does not
// block the request.
func writeAudit(r Request, decision, reason string) {
	dir := stateDir()
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	id := r.Identity
	if id == "" {
		id = "-"
	}
	mode := r.Mode
	if mode == "" {
		mode = "-"
	}
	line := fmt.Sprintf("%s\t%s\tidentity=%s\tmode=%s\tref=%s\treason=%s",
		r.Time.Format(time.RFC3339), decision, id, mode, r.Ref, reason)
	if r.Caller != "" {
		line += "\tcaller=" + r.Caller
	}
	fmt.Fprintln(f, line)
}

// --- matching helpers ---

func anyWildcard(patterns []string, s string) bool {
	for _, p := range patterns {
		if wildcardMatch(p, s) {
			return true
		}
	}
	return false
}

// wildcardMatch reports whether s matches pattern, where * matches any run of
// characters (including separators) and ? matches any single character. Unlike
// filepath.Match, * is not stopped by "/", which suits flat secret references.
func wildcardMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		if px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]) {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			star, mark = px, sx
			px++
		} else if star != -1 {
			px = star + 1
			mark++
			sx = mark
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

func weekdayMatches(names []string, t time.Time) bool {
	today := t.Weekday()
	for _, n := range names {
		if w, ok := weekdayNum(n); ok && w == today {
			return true
		}
	}
	return false
}

func weekdayNum(name string) (time.Weekday, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sun", "sunday":
		return time.Sunday, true
	case "mon", "monday":
		return time.Monday, true
	case "tue", "tues", "tuesday":
		return time.Tuesday, true
	case "wed", "weds", "wednesday":
		return time.Wednesday, true
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, true
	case "fri", "friday":
		return time.Friday, true
	case "sat", "saturday":
		return time.Saturday, true
	}
	return 0, false
}

func intIn(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// hoursMatch reports whether t's local time-of-day falls in the "HH:MM-HH:MM"
// window. If start > end the window wraps past midnight.
func hoursMatch(spec string, t time.Time) bool {
	start, end, err := parseHours(spec)
	if err != nil {
		return false
	}
	now := t.Hour()*60 + t.Minute()
	if start <= end {
		return now >= start && now <= end
	}
	return now >= start || now <= end
}

func parseHours(spec string) (start, end int, err error) {
	lo, hi, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, fmt.Errorf("want HH:MM-HH:MM")
	}
	start, err = parseHM(lo)
	if err != nil {
		return 0, 0, err
	}
	end, err = parseHM(hi)
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func parseHM(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("want HH:MM, got %q", s)
	}
	hh, err := strconv.Atoi(h)
	if err != nil || hh < 0 || hh > 23 {
		return 0, fmt.Errorf("bad hour in %q", s)
	}
	mm, err := strconv.Atoi(m)
	if err != nil || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("bad minute in %q", s)
	}
	return hh*60 + mm, nil
}
