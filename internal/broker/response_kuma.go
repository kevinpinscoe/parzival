package broker

import (
	"encoding/json"
	"fmt"
	"strings"
)

// kumaPushMintResult is kuma-push-mint.sh's declared response shape
// (parzival-k-fed-config's hosts/fldw/parzival-broker/kuma-push-mint.sh):
// exactly one of two forms, both carrying `created`, with either `push_url`
// (a new token was minted) or `reason` (nothing was minted, and why).
// DisallowUnknownFields in decodeExactlyOne means every field either form
// can send must be declared here, and nothing else.
//
// KO-60 closed `reason` to kumaPushMintReasons. It used to accept any string,
// which is a channel a faulty helper could use to hand back something it
// should not, and the helper now distinguishes permission_denied from
// already_exists instead of reporting every denial as the latter.
type kumaPushMintResult struct {
	Created bool   `json:"created"`
	PushURL string `json:"push_url,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var kumaPushMintReasons = map[string]bool{
	"already_exists":    true,
	"permission_denied": true,
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
	// The offending value is never included in an error.
	if result.Created {
		if result.Reason != "" || !strings.HasPrefix(result.PushURL, "https://") ||
			!strings.Contains(result.PushURL, "/api/push/") {
			return nil, fmt.Errorf("kuma.push-mint: created response is not coherent")
		}
	} else if result.PushURL != "" || !kumaPushMintReasons[result.Reason] {
		return nil, fmt.Errorf("kuma.push-mint: refused response is not an approved reason")
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("kuma.push-mint: marshal canonical response: %w", err)
	}
	return canonical, nil
}
