package broker

import (
	"encoding/json"
	"fmt"
)

// kumaPushMintResult is kuma-push-mint.sh's declared response shape
// (parzival-k-fed-config's hosts/fldw/parzival-broker/kuma-push-mint.sh):
// exactly one of two forms, both carrying `created`, with either `push_url`
// (a new token was minted) or `reason` (it already existed and was refused).
// DisallowUnknownFields in decodeExactlyOne means every field either form
// can send must be declared here, and nothing else.
type kumaPushMintResult struct {
	Created bool   `json:"created"`
	PushURL string `json:"push_url,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func init() {
	responseValidators["kuma.push-mint"] = canonicalizeKumaPushMint
}

// canonicalizeKumaPushMint decodes raw against kumaPushMintResult's shape --
// using decodeExactlyOne, so an unexpected field or trailing data after a
// well-formed object is refused -- then re-marshals the typed value fresh as
// the canonical result. See response_tea.go's canonicalizeTeaReposList for
// the pattern this follows.
func canonicalizeKumaPushMint(raw []byte) (json.RawMessage, error) {
	var result kumaPushMintResult
	if err := decodeExactlyOne(raw, &result); err != nil {
		return nil, fmt.Errorf("kuma.push-mint: response did not match the approved shape: %w", err)
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("kuma.push-mint: marshal canonical response: %w", err)
	}
	return canonical, nil
}
