// Package agent detects whether parzival is running inside an AI coding
// agent's tool shell.
//
// This exists for one threat, and it is not an adversary: the *honest* agent.
// THREAT-MODEL.md §4b names accidental disclosure to a recording sink as the
// most probable leak in practice, and an AI agent is the sharpest case of it —
// a raw fetch puts the value into the agent's context, the model provider, the
// terminal, and any on-disk session log the launcher keeps, all from one
// command, and every copy is permanent.
//
// The policy cannot see this. An identity label is self-asserted (--as /
// $PARZIVAL_IDENTITY, no process inspection), so a policy that documents an
// identity as "human-run, no AI or transcript involved" documents an intention
// and enforces nothing: an agent types the same label and receives the same
// value. Detection here is what turns that documented intention into a runtime
// refusal.
//
// # What this is not
//
// It is not a security boundary and cannot be one. The markers are environment
// variables, so anything that can unset an environment variable defeats it —
// which is consistent with the rest of parzival's model, where a same-uid
// process can bypass the broker entirely. It is a mistake-prevention control
// aimed at the case that actually happens: an on-task, directive-compliant
// agent reaching for `get` because `get` was the only tool that answered its
// question.
//
// # Completeness
//
// The marker list below is best-effort and is not claimed to be exhaustive. A
// harness that sets none of these is not detected, and that is a documented
// limit rather than a bug. PARZIVAL_AGENT exists so any harness — one released
// after this list was written, or an operator's own wrapper script — can
// declare itself without waiting for a parzival release.
package agent

import "os"

// Marker is one environment variable whose presence identifies an agent
// harness, together with the harness it identifies.
type Marker struct {
	Env   string // environment variable name
	Agent string // human-readable harness name, for the refusal message
}

// markers are checked in order; the first one present decides. Presence alone
// counts — a marker set to any non-empty value identifies the harness, because
// harnesses are not consistent about what they set these to and a value check
// would fail open on the next release that changes one.
//
// Order matters only for which name appears in the refusal message, so the
// explicit self-declaration is checked first: an operator who set it wants to
// be told that is why.
var markers = []Marker{
	{Env: "PARZIVAL_AGENT", Agent: "an AI agent harness (declared by $PARZIVAL_AGENT)"},
	{Env: "CLAUDECODE", Agent: "Claude Code"},
	{Env: "CLAUDE_CODE_ENTRYPOINT", Agent: "Claude Code"},
	{Env: "CLAUDE_CODE_SESSION_ID", Agent: "Claude Code"},
	{Env: "CURSOR_AGENT", Agent: "Cursor"},
	{Env: "CURSOR_TRACE_ID", Agent: "Cursor"},
	{Env: "CODEX_SANDBOX", Agent: "OpenAI Codex CLI"},
	// AI_AGENT is the generic marker: harnesses that set it carry their own
	// name and version in the value, and it is last so a more specific marker
	// names the harness first.
	{Env: "AI_AGENT", Agent: "an AI agent harness"},
}

// Detect reports whether this process is running under a recognised AI agent
// harness, and which marker identified it.
func Detect() (Marker, bool) { return detect(os.Getenv) }

// detect takes its environment lookup as an argument so tests can exercise
// every marker without mutating the test process's own environment — the same
// reason internal/store takes a runner interface.
func detect(getenv func(string) string) (Marker, bool) {
	for _, m := range markers {
		if getenv(m.Env) != "" {
			return m, true
		}
	}
	return Marker{}, false
}

// Markers returns the environment variables that identify an agent harness, in
// check order. `parzival doctor` reports them so an operator can see what the
// refusal keys on without reading the source.
func Markers() []Marker {
	out := make([]Marker, len(markers))
	copy(out, markers)
	return out
}
