package broker

import (
	"encoding/json"
	"testing"
)

func TestCanonicalizeKumaPushMintAcceptsCreated(t *testing.T) {
	raw := []byte(`{"created":true,"push_url":"https://uptime.kevininscoe.com/api/push/abc123"}`)
	got, err := canonicalizeKumaPushMint(raw)
	if err != nil {
		t.Fatalf("canonicalizeKumaPushMint: unexpected error: %v", err)
	}
	var result kumaPushMintResult
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("canonicalize output did not re-decode: %v", err)
	}
	if !result.Created || result.PushURL != "https://uptime.kevininscoe.com/api/push/abc123" {
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
