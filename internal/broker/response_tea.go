package broker

import (
	"encoding/json"
	"fmt"
)

// repoSummary is the response shape of `tea repos list --owner ... --output
// json`, confirmed against a live run of the real tea v0.15.1 CLI against
// real Gitea (CHECKPOINT.md, 2026-09-10) — not guessed from `tea repos list
// --help`, which names available fields but not their JSON shape. It matches
// tea's default --fields set (owner,name,type,ssh); examples/consumers/
// tea.json's argv does not override --fields.
type repoSummary struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	SSH   string `json:"ssh"`
}

// responseValidator canonicalizes and validates a consumer's raw captured
// stdout for one operation. It never forwards raw bytes to the client: it
// decodes stdout into the operation's typed, approved shape and re-marshals
// that typed value fresh, so trailing garbage, an unexpected top-level
// shape, or a field the client has no business seeing can never ride along
// as part of what's returned as "the approved result".
type responseValidator func(raw []byte) (json.RawMessage, error)

// responseValidators is keyed by "<consumer>.<operation>". An operation with
// no registered validator here has no approved response shape and cannot be
// served over the socket — broker.go's startup checks refuse to start a
// consumer definition whose declared operations have no matching entry here.
var responseValidators = map[string]responseValidator{
	"tea.repos-list": canonicalizeTeaReposList,
}

// canonicalizeTeaReposList decodes raw against repoSummary's shape — using
// decodeExactlyOne, so both an unexpected shape and non-whitespace trailing
// data after a well-formed array are refused — then re-marshals the typed
// value fresh as the canonical result.
func canonicalizeTeaReposList(raw []byte) (json.RawMessage, error) {
	var repos []repoSummary
	if err := decodeExactlyOne(raw, &repos); err != nil {
		return nil, fmt.Errorf("tea.repos-list: response did not match the approved shape: %w", err)
	}
	canonical, err := json.Marshal(repos)
	if err != nil {
		return nil, fmt.Errorf("tea.repos-list: marshal canonical response: %w", err)
	}
	return canonical, nil
}
