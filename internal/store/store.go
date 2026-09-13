// Package store abstracts the encrypted secret backends Parzival can fetch
// from. A caller parses a reference string with ParseRef, resolves it to a
// Store with Resolve, and calls Get to obtain the raw secret bytes.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrUnimplemented is returned by backends that are stubbed but not yet built.
var ErrUnimplemented = errors.New("store backend not implemented")

// SecretRef is a parsed reference to a single secret in a backend.
type SecretRef struct {
	Backend string // "openbao", "onepassword", or "gopass"
	Path    string // backend-specific location
	Field   string // field within the secret (empty for backends that embed it in Path)
	Raw     string // the original reference string, kept for error messages
}

// Store fetches secret material from one backend.
type Store interface {
	// Name reports the backend's short name, for logs and errors.
	Name() string
	// Capabilities reports the backend security properties parzival can rely on.
	// Backends are intentionally not equivalent: an interactive password manager
	// can satisfy encrypted-at-rest and runtime delivery, while an unattended
	// broker mode also needs non-ambient auth, scoped store policy, TTLs, and
	// backend audit to make parzival policy meaningful.
	Capabilities() Capabilities
	// Get returns the raw secret bytes for ref. The caller owns the returned
	// slice and is responsible for wiping it after use.
	Get(ctx context.Context, ref SecretRef) ([]byte, error)
}

// ParseRef parses a secret reference string into a SecretRef. The scheme prefix
// selects the backend.
//
// Supported forms:
//
//	bao:<mount>/<path>#<field>    OpenBao KV v2, e.g. bao:app/gitea#token
//	op://<vault>/<item>/<field>   1Password native secret reference
//	gopass:<path>                 gopass (not yet implemented)
func ParseRef(ref string) (SecretRef, error) {
	switch {
	case strings.HasPrefix(ref, "op://"):
		// The whole reference is handed to `op read` verbatim.
		return SecretRef{Backend: "onepassword", Path: ref, Raw: ref}, nil

	case strings.HasPrefix(ref, "bao:"):
		body := strings.TrimPrefix(ref, "bao:")
		path, field, ok := strings.Cut(body, "#")
		if !ok || field == "" {
			return SecretRef{}, fmt.Errorf("openbao reference %q must include a #<field>", ref)
		}
		if path == "" {
			return SecretRef{}, fmt.Errorf("openbao reference %q is missing <mount>/<path>", ref)
		}
		return SecretRef{Backend: "openbao", Path: path, Field: field, Raw: ref}, nil

	case strings.HasPrefix(ref, "gopass:"):
		path := strings.TrimPrefix(ref, "gopass:")
		if path == "" {
			return SecretRef{}, fmt.Errorf("gopass reference %q is missing a path", ref)
		}
		return SecretRef{Backend: "gopass", Path: path, Raw: ref}, nil

	default:
		return SecretRef{}, fmt.Errorf("unrecognized secret reference %q: expected a bao:, op://, or gopass: prefix", ref)
	}
}

// Resolve returns the Store that can serve ref.
func Resolve(ref SecretRef) (Store, error) {
	switch ref.Backend {
	case "openbao":
		return NewOpenBaoFromEnv()
	case "onepassword":
		return NewOnePassword(), nil
	case "gopass":
		return NewGopass(), nil
	default:
		return nil, fmt.Errorf("no store backend for %q", ref.Backend)
	}
}
