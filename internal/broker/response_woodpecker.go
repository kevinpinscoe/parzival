package broker

import (
	"encoding/json"
	"fmt"
)

// woodpeckerRepoSecretSetResult is the declared response shape of the
// woodpecker.repo-secret-set helper (parzival-k-fed-config's
// hosts/fldw/parzival-broker/woodpecker-secret-set.sh): which of the fixed
// secret names was written, and whether it was created or replaced.
//
// Unlike kuma.push-mint, every field here is also checked against a closed
// set of values, not just decoded. Both fields are strings, and a string
// field that accepted anything would be a channel a faulty helper could use
// to hand the secret it just wrote back to the client. Restricting each one
// to the handful of values the helper can legitimately send closes that.
type woodpeckerRepoSecretSetResult struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

// woodpeckerSecretNames are the only Woodpecker secret names the operation
// may write. Must stay in step with the consumer definition's `name` input
// pattern in parzival-k-fed-config's broker/consumers/woodpecker.json.
var woodpeckerSecretNames = map[string]bool{
	"gitea_user":  true,
	"gitea_token": true,
}

var woodpeckerSecretActions = map[string]bool{
	"created": true,
	"updated": true,
}

func init() {
	responseValidators["woodpecker.repo-secret-set"] = canonicalizeWoodpeckerRepoSecretSet
}

// canonicalizeWoodpeckerRepoSecretSet decodes raw against
// woodpeckerRepoSecretSetResult's shape (decodeExactlyOne refuses unknown
// fields and trailing data), checks each field against its closed value set,
// then re-marshals the typed value fresh as the canonical result.
func canonicalizeWoodpeckerRepoSecretSet(raw []byte) (json.RawMessage, error) {
	var result woodpeckerRepoSecretSetResult
	if err := decodeExactlyOne(raw, &result); err != nil {
		return nil, fmt.Errorf("woodpecker.repo-secret-set: response did not match the approved shape: %w", err)
	}
	// The offending value is deliberately not included in either error: it
	// is exactly the data this check exists to keep from travelling further.
	if !woodpeckerSecretNames[result.Name] {
		return nil, fmt.Errorf("woodpecker.repo-secret-set: response name is not an approved secret name")
	}
	if !woodpeckerSecretActions[result.Action] {
		return nil, fmt.Errorf("woodpecker.repo-secret-set: response action is not an approved value")
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("woodpecker.repo-secret-set: marshal canonical response: %w", err)
	}
	return canonical, nil
}
