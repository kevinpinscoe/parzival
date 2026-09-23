package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeKumaPushMintAcceptsCreated(t *testing.T) {
	raw := []byte(`{"created":true,"push_url":"https://uptime.kevininscoe.com/api/push/0123456789abcdef0123456789abcdef"}`)
	got, err := canonicalizeKumaPushMint(raw)
	if err != nil {
		t.Fatalf("canonicalizeKumaPushMint: unexpected error: %v", err)
	}
	var result kumaPushMintResult
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("canonicalize output did not re-decode: %v", err)
	}
	if !result.Created || result.PushURL != "https://uptime.kevininscoe.com/api/push/0123456789abcdef0123456789abcdef" {
		t.Errorf("canonicalizeKumaPushMint: got %+v", result)
	}
}

func TestCanonicalizeKumaPushMintAcceptsAlreadyExists(t *testing.T) {
	raw := []byte(`{"created":false,"reason":"already_exists"}`)
	got, err := canonicalizeKumaPushMint(raw)
	if err != nil {
		t.Fatalf("canonicalizeKumaPushMint: unexpected error: %v", err)
	}
	var result kumaPushMintResult
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("canonicalize output did not re-decode: %v", err)
	}
	if result.Created || result.Reason != "already_exists" {
		t.Errorf("canonicalizeKumaPushMint: got %+v", result)
	}
}

func TestCanonicalizeKumaPushMintRejectsWrongTopLevelShape(t *testing.T) {
	_, err := canonicalizeKumaPushMint([]byte(`["not", "an", "object"]`))
	if err == nil {
		t.Fatal("canonicalizeKumaPushMint: expected an error for a non-object top level, got none")
	}
}

func TestCanonicalizeKumaPushMintRejectsUnknownField(t *testing.T) {
	_, err := canonicalizeKumaPushMint([]byte(`{"created":true,"push_url":"https://x","extra":"field"}`))
	if err == nil {
		t.Fatal("canonicalizeKumaPushMint: expected an error for an unexpected field, got none")
	}
}

func TestCanonicalizeKumaPushMintRejectsTrailingData(t *testing.T) {
	_, err := canonicalizeKumaPushMint([]byte(`{"created":true,"push_url":"https://x"}garbage`))
	if err == nil {
		t.Fatal("canonicalizeKumaPushMint: expected an error for trailing data, got none")
	}
}

// The result never carries a field this consumer's script doesn't emit --
// specifically, it never has any way to smuggle a role_id, secret_id, or
// AppRole token through as an "approved" field, because kumaPushMintResult
// declares exactly created/push_url/reason and nothing else. This test
// documents that guarantee rather than exercising new behavior.
func TestCanonicalizeKumaPushMintCannotCarryACredentialField(t *testing.T) {
	_, err := canonicalizeKumaPushMint([]byte(`{"created":true,"push_url":"https://x","secret_id":"leaked"}`))
	if err == nil {
		t.Fatal("canonicalizeKumaPushMint: expected an error when a credential-shaped field is present, got none")
	}
}

func TestResponseValidatorsRegistersKumaPushMint(t *testing.T) {
	if _, ok := responseValidators["kuma.push-mint"]; !ok {
		t.Fatal("responseValidators: \"kuma.push-mint\" is not registered")
	}
}

func TestCanonicalizeKumaPushMintAcceptsPermissionDenied(t *testing.T) {
	got, err := canonicalizeKumaPushMint([]byte(`{"created":false,"reason":"permission_denied"}`))
	if err != nil {
		t.Fatalf("canonicalizeKumaPushMint: unexpected error: %v", err)
	}
	if string(got) != `{"created":false,"reason":"permission_denied"}` {
		t.Errorf("canonicalizeKumaPushMint: got %s", got)
	}
}

// KO-60: reason is a closed set, and the two forms cannot be mixed.
func TestCanonicalizeKumaPushMintRejectsIncoherentOrUnknownForms(t *testing.T) {
	for _, raw := range []string{
		`{"created":false,"reason":"hvs.SENTINELtoken"}`,
		`{"created":false,"reason":""}`,
		`{"created":false}`,
		`{"created":false,"reason":"already_exists","push_url":"https://x/api/push/abc"}`,
		`{"created":true}`,
		`{"created":true,"push_url":"https://x/api/push/abc","reason":"already_exists"}`,
		`{"created":true,"push_url":"hvs.SENTINELtoken"}`,
		`{"created":true,"push_url":"http://x/api/push/abc"}`,
	} {
		_, err := canonicalizeKumaPushMint([]byte(raw))
		if err == nil {
			t.Errorf("%s: expected refusal, got none", raw)
			continue
		}
		if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("%s: error leaks the value: %v", raw, err)
		}
	}
}

const mintGood = "https://uptime.kevininscoe.com/api/push/0123456789abcdef0123456789abcdef"

func mintCreated(url string) []byte {
	b, _ := json.Marshal(map[string]any{"created": true, "push_url": url})
	return b
}

func TestKumaPushMintAcceptsTheExactHelperForm(t *testing.T) {
	got, err := canonicalizeKumaPushMint(mintCreated(mintGood))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"created":true,"push_url":"`+mintGood+`"}` {
		t.Errorf("got %s", got)
	}
}

// Sentinel material in every URL component must be refused, and never echoed
// in the error.
func TestKumaPushMintRejectsSentinelInEveryURLComponent(t *testing.T) {
	const s = "sentinel0tok"
	tok := "0123456789abcdef0123456789abcdef"
	bad := map[string]string{
		"hostname":            "https://" + s + ".uptime.kevininscoe.com/api/push/" + tok,
		"hostname suffix":     "https://uptime.kevininscoe.com." + s + ".example/api/push/" + tok,
		"other host":          "https://" + s + ".example/api/push/" + tok,
		"port":                "https://uptime.kevininscoe.com:8443/api/push/" + tok,
		"userinfo user":       "https://" + s + "@uptime.kevininscoe.com/api/push/" + tok,
		"userinfo user:pass":  "https://u:" + s + "@uptime.kevininscoe.com/api/push/" + tok,
		"query":               mintGood + "?t=" + s,
		"empty query":         mintGood + "?",
		"fragment":            mintGood + "#" + s,
		"empty fragment":      mintGood + "#",
		"extra path suffix":   mintGood + "/" + s,
		"extra path prefix":   "https://uptime.kevininscoe.com/" + s + "/api/push/" + tok,
		"trailing slash":      mintGood + "/",
		"dot segment":         "https://uptime.kevininscoe.com/api/push/../push/" + tok,
		"encoded slash":       "https://uptime.kevininscoe.com/api/push%2F" + tok,
		"encoded token":       "https://uptime.kevininscoe.com/api/push/%30123456789abcdef0123456789abcdef",
		"http scheme":         "http://uptime.kevininscoe.com/api/push/" + tok,
		"uppercase scheme":    "HTTPS://uptime.kevininscoe.com/api/push/" + tok,
		"uppercase host":      "https://UPTIME.kevininscoe.com/api/push/" + tok,
		"token too short":     "https://uptime.kevininscoe.com/api/push/" + tok[:31],
		"token too long":      mintGood + "0",
		"token oversized":     "https://uptime.kevininscoe.com/api/push/" + tok + tok + tok,
		"token uppercase hex": "https://uptime.kevininscoe.com/api/push/0123456789ABCDEF0123456789ABCDEF",
		"token non-hex":       "https://uptime.kevininscoe.com/api/push/" + s + "0123456789abcdef0123",
		"token empty":         "https://uptime.kevininscoe.com/api/push/",
		"no path":             "https://uptime.kevininscoe.com",
		"leading space":       " " + mintGood,
		"trailing newline":    mintGood + "\n",
		"opaque":              "https:uptime.kevininscoe.com/api/push/" + tok,
	}
	for name, u := range bad {
		_, err := canonicalizeKumaPushMint(mintCreated(u))
		if err == nil {
			t.Errorf("%s: expected refusal of %q", name, u)
			continue
		}
		if strings.Contains(err.Error(), s) || strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error leaks URL material: %v", name, err)
		}
	}
}
