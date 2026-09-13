package broker

import (
	"fmt"
	"os"

	"github.com/kevinpinscoe/parzival/internal/consumer"
)

// AuthzSchemaVersion is the only authorization-file format version this
// binary understands. Unlike consumer.SchemaVersion/policy.SchemaVersion —
// which accept Schema <= their current version, treating an omitted/zero
// value as "unspecified" and therefore current — authz.json is a brand-new
// stage-2 format with no legacy version to be lenient about. schema must
// equal this value exactly; an omitted field (Go zero value 0) is refused
// exactly like any other wrong value, not silently treated as current.
const AuthzSchemaVersion = 1

// AuthzEntry grants one kernel-verified peer uid a closed set of operations.
// There is no allow/deny distinction: an entry only grants, so a peer with no
// matching entry is denied by omission (deny-by-default).
type AuthzEntry struct {
	UID         uint32   `json:"uid"`
	Description string   `json:"description,omitempty"`
	Operations  []string `json:"operations"`
}

// AuthzFile is the broker's peer-authorization trust root: a separate,
// administrator-owned file from any consumer definition — never policy.json
// (user-owned, keyed on a
// self-asserted --as label, the wrong shape for a kernel-verified peer), and
// never folded into a consumer definition, so the two stay independently
// editable: this file answers "which kernel-authenticated peer may invoke
// which operation", never "what is this operation".
//
// Entries is a slice, not a map[uid]..., because encoding/json silently keeps
// the *last* duplicate key when unmarshalling into a Go map — precisely the
// "degrades silently" failure this project refuses elsewhere. A slice lets
// Validate see every entry as written and explicitly refuse what a map would
// have hidden.
type AuthzFile struct {
	Schema  int          `json:"schema"`
	Entries []AuthzEntry `json:"entries"`
}

// Parse decodes and structurally validates authorization-file bytes: strict
// unknown-field rejection, the exact schema-version requirement, and every
// check that needs no data beyond the file itself — no duplicate uid, no
// empty or duplicate-within-entry operations list, and every operation
// string syntactically well-formed. It does not check that an operation
// actually resolves against any consumer definition; that cross-file check
// is Validate, which needs the broker's already-loaded definitions.
func Parse(data []byte, name string) (*AuthzFile, error) {
	if name == "" {
		name = "authorization file"
	}
	var a AuthzFile
	if err := decodeExactlyOne(data, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if a.Schema != AuthzSchemaVersion {
		return nil, fmt.Errorf(
			"%s declares schema %d but this parzival requires exactly schema %d (authz.json is a new stage-2 format with no legacy version to accept)",
			name, a.Schema, AuthzSchemaVersion)
	}
	if len(a.Entries) == 0 {
		return nil, fmt.Errorf("%s: no entries — an authorization file that grants nothing is more likely truncated than intended", name)
	}

	seenUID := make(map[uint32]bool, len(a.Entries))
	for i, e := range a.Entries {
		if seenUID[e.UID] {
			return nil, fmt.Errorf(
				"%s: uid %d appears in more than one entry — merge into a single entry rather than repeating it (this file does not union across duplicate entries)",
				name, e.UID)
		}
		seenUID[e.UID] = true

		if len(e.Operations) == 0 {
			return nil, fmt.Errorf("%s: entry %d (uid %d): no operations — an entry that grants nothing is more likely truncated than intended", name, i, e.UID)
		}
		seenOp := make(map[string]bool, len(e.Operations))
		for _, op := range e.Operations {
			if seenOp[op] {
				return nil, fmt.Errorf("%s: entry %d (uid %d): operation %q listed more than once", name, i, e.UID, op)
			}
			seenOp[op] = true
			if _, _, ok := splitOperationRef(op); !ok {
				return nil, fmt.Errorf("%s: entry %d (uid %d): operation %q is not a syntactically valid <consumer>.<operation> reference", name, i, e.UID, op)
			}
		}
	}
	return &a, nil
}

// LoadFile reads and parses an authorization file from path. It does not run
// trust-root verification — that is the caller's job (broker.go), using the
// same consumer.VerifyTrustRoot check applied to consumer definitions.
func LoadFile(path string) (*AuthzFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authorization file: %w", err)
	}
	return Parse(data, path)
}

// Validate confirms every operation string named in a is actually declared by
// some loaded consumer definition. It is a separate step from Parse because
// it needs data Parse does not have: the broker's already-loaded, trust-root
// -verified consumer definitions. Any unresolved reference refuses — an
// authorization file must never grant an operation that does not exist,
// which would otherwise be silently meaningless rather than refused.
func (a *AuthzFile) Validate(defs map[string]*consumer.Definition) error {
	for _, e := range a.Entries {
		for _, op := range e.Operations {
			consumerName, opName, ok := splitOperationRef(op)
			if !ok {
				// Unreachable through Parse, which already checked this; kept
				// as a defensive check against an AuthzFile built by hand
				// (e.g. directly in a test) rather than through Parse.
				return fmt.Errorf("authorization file: entry (uid %d): operation %q is not a valid reference", e.UID, op)
			}
			def, ok := defs[consumerName]
			if !ok {
				return fmt.Errorf("authorization file: entry (uid %d): operation %q names consumer %q, which is not a loaded consumer definition", e.UID, op, consumerName)
			}
			if _, ok := def.Operations[opName]; !ok {
				return fmt.Errorf("authorization file: entry (uid %d): operation %q is not declared by consumer %q", e.UID, op, consumerName)
			}
		}
	}
	return nil
}

// Decide reports whether uid is authorized for operation, matching purely on
// the operation string — it never requires operation to resolve against a
// consumer definition. This is deliberate: enumeration safety requires
// authorization to be decidable before the broker discloses, via its
// response status, whether an operation exists at all, so Decide has to work
// on the string alone (see session.go). Parse already guarantees at most one
// entry per uid, so returning on the first match is safe.
func (a *AuthzFile) Decide(uid uint32, operation string) bool {
	for _, e := range a.Entries {
		if e.UID != uid {
			continue
		}
		for _, op := range e.Operations {
			if op == operation {
				return true
			}
		}
		return false
	}
	return false
}
