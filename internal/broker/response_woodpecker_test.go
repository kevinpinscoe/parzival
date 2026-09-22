package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeWoodpeckerRepoSecretSetAcceptsEachApprovedCombination(t *testing.T) {
	for _, name := range []string{"gitea_user", "gitea_token"} {
		for _, action := range []string{"created", "updated"} {
			raw := []byte(`{"name":"` + name + `","action":"` + action + `"}`)
			got, err := canonicalizeWoodpeckerRepoSecretSet(raw)
			if err != nil {
				t.Fatalf("%s/%s: unexpected error: %v", name, action, err)
			}
			var result woodpeckerRepoSecretSetResult
			if err := json.Unmarshal(got, &result); err != nil {
				t.Fatalf("%s/%s: canonical output did not re-decode: %v", name, action, err)
			}
			if result.Name != name || result.Action != action {
				t.Errorf("%s/%s: got %+v", name, action, result)
			}
		}
	}
}

func TestCanonicalizeWoodpeckerRepoSecretSetRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"wrong top level":  `["gitea_token","created"]`,
		"unknown field":    `{"name":"gitea_token","action":"created","extra":"x"}`,
		"trailing data":    `{"name":"gitea_token","action":"created"}garbage`,
		"second object":    `{"name":"gitea_token","action":"created"}{"name":"gitea_user","action":"created"}`,
		"missing action":   `{"name":"gitea_token"}`,
		"missing name":     `{"action":"created"}`,
		"empty object":     `{}`,
		"not json":         `OK: secret set`,
		"wrong value type": `{"name":"gitea_token","action":true}`,
	}
	for label, raw := range cases {
		if _, err := canonicalizeWoodpeckerRepoSecretSet([]byte(raw)); err == nil {
			t.Errorf("%s: expected an error, got none", label)
		}
	}
}

func TestCanonicalizeWoodpeckerRepoSecretSetRejectsUnapprovedValues(t *testing.T) {
	cases := map[string]string{
		"other secret name":  `{"name":"web1_deploy_key","action":"created"}`,
		"case variant":       `{"name":"GITEA_TOKEN","action":"created"}`,
		"other action":       `{"name":"gitea_token","action":"deleted"}`,
		"empty action":       `{"name":"gitea_token","action":""}`,
		"padded name":        `{"name":" gitea_token","action":"created"}`,
		"value in name slot": `{"name":"glpat-0123456789abcdef","action":"created"}`,
	}
	for label, raw := range cases {
		if _, err := canonicalizeWoodpeckerRepoSecretSet([]byte(raw)); err == nil {
			t.Errorf("%s: expected an error, got none", label)
		}
	}
}

// A credential-shaped field has nowhere to go: the result type declares
// exactly name and action, and decodeExactlyOne refuses anything else.
func TestCanonicalizeWoodpeckerRepoSecretSetCannotCarryACredentialField(t *testing.T) {
	for _, field := range []string{"value", "token", "secret", "response"} {
		raw := `{"name":"gitea_token","action":"created","` + field + `":"leaked"}`
		if _, err := canonicalizeWoodpeckerRepoSecretSet([]byte(raw)); err == nil {
			t.Errorf("field %q: expected an error, got none", field)
		}
	}
}

// Rejecting a smuggled value is only half the property; the error must not
// repeat it either, since errors are logged.
func TestCanonicalizeWoodpeckerRepoSecretSetErrorsDoNotEchoValues(t *testing.T) {
	const sentinel = "SENTINEL-not-a-real-token"
	for _, raw := range []string{
		`{"name":"` + sentinel + `","action":"created"}`,
		`{"name":"gitea_token","action":"` + sentinel + `"}`,
	} {
		_, err := canonicalizeWoodpeckerRepoSecretSet([]byte(raw))
		if err == nil {
			t.Fatalf("expected an error for %s", raw)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("error repeats the rejected value: %v", err)
		}
	}
}

func TestResponseValidatorsRegistersWoodpeckerRepoSecretSet(t *testing.T) {
	if _, ok := responseValidators["woodpecker.repo-secret-set"]; !ok {
		t.Fatal(`responseValidators: "woodpecker.repo-secret-set" is not registered`)
	}
}
