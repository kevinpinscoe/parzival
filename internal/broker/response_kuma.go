package broker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
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

// The exact push_url contract of the deployed helper, derived from
// parzival-k-fed-config's hosts/fldw/parzival-broker/kuma-push-mint.sh (the
// repo copy and /usr/local/libexec/parzival-broker/kuma-push-mint.sh, which
// agree as of 2026-09-23):
//
//	KUMA_PUBLIC_URL="https://uptime.kevininscoe.com"
//	push_token=$(/usr/bin/openssl rand -hex 16)   -> 32 lowercase hex characters
//	push_url="${KUMA_PUBLIC_URL}/api/push/${push_token}"
//
// If the helper's origin or token generation ever changes, this must change
// with it, in the same pull request pair.
const (
	kumaPushMintScheme = "https"
	kumaPushMintHost   = "uptime.kevininscoe.com"
	kumaPushMintPrefix = "/api/push/"
)

var kumaPushMintTokenRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// validKumaPushMintURL parses raw and requires every component to be exactly
// what the helper produces: https, the one approved host (no port), no
// userinfo, no query (not even an empty "?"), no fragment, no opaque or
// escaped path, and a path of exactly /api/push/<token> with a token of
// exactly 32 lowercase hex characters. It then requires the whole string to
// equal the canonical form rebuilt from those parts, so no encoding the
// parser normalises away can slip through.
func validKumaPushMintURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != kumaPushMintScheme || u.Host != kumaPushMintHost || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.RawPath != "" {
		return false
	}
	if len(u.Path) <= len(kumaPushMintPrefix) || u.Path[:len(kumaPushMintPrefix)] != kumaPushMintPrefix {
		return false
	}
	token := u.Path[len(kumaPushMintPrefix):]
	if !kumaPushMintTokenRE.MatchString(token) {
		return false
	}
	return raw == kumaPushMintScheme+"://"+kumaPushMintHost+kumaPushMintPrefix+token
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
		if result.Reason != "" || !validKumaPushMintURL(result.PushURL) {
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
