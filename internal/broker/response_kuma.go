package broker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// kumaPushMintResult is the kuma.push-mint helper's declared response shape:
// exactly one of two forms, both carrying `created`, with either `push_url`
// (a new token was minted) or `reason` (nothing was minted, and why).
// DisallowUnknownFields in decodeExactlyOne means every field either form
// can send must be declared here, and nothing else.
//
// `reason` is closed to kumaPushMintReasons, and `push_url` must be exactly
// the URL the helper builds: the deployment's configured push origin, then
// /api/push/, then a token of exactly kumaPushMintTokenRE. No field accepts
// an arbitrary value, so no field is a channel a faulty helper could use to
// hand back something it should not.
type kumaPushMintResult struct {
	Created bool   `json:"created"`
	PushURL string `json:"push_url,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var kumaPushMintReasons = map[string]bool{
	"already_exists":    true,
	"permission_denied": true,
}

// kumaPushOriginKey is the operation's one response_config key: the exact
// public origin of the Uptime Kuma instance the helper mints push URLs for,
// as scheme://host[:port]. It is deployment configuration, supplied by the
// administrator in the root-owned consumer definition, and is never
// compiled in; the public product has no business knowing any deployment's
// hostname.
const kumaPushOriginKey = "push_origin"

// The helper's path and token contract: push_url = <push_origin> +
// "/api/push/" + a token from `openssl rand -hex 16`, which is exactly 32
// lowercase hexadecimal characters. If the helper's token generation ever
// changes, this changes with it.
const kumaPushMintPrefix = "/api/push/"

var kumaPushMintTokenRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func init() {
	configuredResponseValidators["kuma.push-mint"] = configuredResponseValidator{
		keys:     []string{kumaPushOriginKey},
		check:    checkKumaPushOrigin,
		validate: canonicalizeKumaPushMint,
	}
}

// checkKumaPushOrigin requires the configured value to be a bare HTTPS
// origin written in its canonical form: lowercase scheme and host, an
// optional explicit numeric port, and nothing else (no userinfo, path,
// trailing slash, query or fragment). Requiring the canonical spelling means
// canonicalizeKumaPushMint can compare origins as exact strings.
func checkKumaPushOrigin(cfg map[string]string) error {
	origin := cfg[kumaPushOriginKey]
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("%s is not a URL", kumaPushOriginKey)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%s must be a bare https origin (scheme://host[:port], nothing else)", kumaPushOriginKey)
	}
	if u.Host != strings.ToLower(u.Host) || u.Hostname() == "" {
		return fmt.Errorf("%s host must be written in lowercase", kumaPushOriginKey)
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	canonical := "https://" + host
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return fmt.Errorf("%s port must be a canonical number from 1 to 65535", kumaPushOriginKey)
		}
		canonical += ":" + p
	}
	// Rebuilt from its parts, so an empty port ("host:"), a stray character
	// or any other non-canonical spelling fails here.
	if origin != canonical {
		return fmt.Errorf("%s must be written in canonical form", kumaPushOriginKey)
	}
	return nil
}

// validKumaPushMintURL parses raw and requires every component to be exactly
// what the helper produces for the configured origin: https, the configured
// host, a port only if the configured origin states one (and then that
// port), no userinfo, no query (not even an empty "?"), no fragment, no
// opaque or escaped path, and a path of exactly /api/push/<token>, where the
// token matches kumaPushMintTokenRE. It then requires the whole string to
// equal the canonical form rebuilt from the origin and token, so no encoding
// the parser normalises away can slip through.
func validKumaPushMintURL(raw, origin string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.Scheme+"://"+u.Host != origin || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.RawPath != "" {
		return false
	}
	if !strings.HasPrefix(u.Path, kumaPushMintPrefix) {
		return false
	}
	token := u.Path[len(kumaPushMintPrefix):]
	if !kumaPushMintTokenRE.MatchString(token) {
		return false
	}
	return raw == origin+kumaPushMintPrefix+token
}

// canonicalizeKumaPushMint decodes raw against kumaPushMintResult's shape --
// using decodeExactlyOne, so an unexpected field or trailing data after a
// well-formed object is refused -- checks both forms against their closed
// sets and the trusted configuration, then re-marshals the typed value fresh
// as the canonical result. The offending value is never included in an
// error.
func canonicalizeKumaPushMint(raw []byte, cfg map[string]string) (json.RawMessage, error) {
	var result kumaPushMintResult
	if err := decodeExactlyOne(raw, &result); err != nil {
		return nil, fmt.Errorf("kuma.push-mint: response did not match the approved shape: %w", err)
	}
	if result.Created {
		if result.Reason != "" || !validKumaPushMintURL(result.PushURL, cfg[kumaPushOriginKey]) {
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
