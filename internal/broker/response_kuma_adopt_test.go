package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// A plausible push token and URL. None of these may ever survive
// canonicalization in any form.
const adoptSentinel = "SENTINELtok9Qz"

func adoptResp(result string, written bool, matches string) []byte {
	return []byte(`{"result":"` + result + `","monitor_id":89,"slug":"container-crashloop",` +
		`"openbao_written":` + map[bool]string{true: "true", false: "false"}[written] +
		`,"stored_matches_live":` + matches + `}`)
}

func TestKumaAdoptAcceptsEveryCoherentOutcome(t *testing.T) {
	cases := []struct {
		result  string
		written bool
		matches string
	}{
		{"adopted", true, "true"},
		{"already_adopted", false, "true"},
		{"conflict", false, "false"},
		{"write_mismatch", true, "false"},
		{"write_unverified", true, "null"},
		{"window_closed", false, "null"},
		{"not_found", false, "null"},
		{"not_push", false, "null"},
		{"no_live_token", false, "null"},
		{"soft_deleted", false, "null"},
		{"kuma_unavailable", false, "null"},
		{"openbao_unavailable", false, "null"},
		{"kuma_changed_during_adopt", false, "null"},
		{"kuma_changed_during_adopt", true, "null"},
	}
	for _, c := range cases {
		got, err := canonicalizeKumaAdoptPushAdopt(adoptResp(c.result, c.written, c.matches))
		if err != nil {
			t.Errorf("%s/%v/%s: unexpected error: %v", c.result, c.written, c.matches, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("canonical output did not re-decode: %v", err)
		}
		if len(m) != 5 || m["result"] != c.result || m["slug"] != "container-crashloop" {
			t.Errorf("%s: canonical output wrong: %s", c.result, got)
		}
	}
}

func TestKumaAdoptRejectsIncoherentOutcomes(t *testing.T) {
	bad := []struct {
		result  string
		written bool
		matches string
	}{
		{"adopted", false, "true"},          // adopted without a write
		{"adopted", true, "false"},          // adopted but not equal
		{"already_adopted", true, "true"},   // "already" but wrote
		{"conflict", true, "false"},         // a conflict must never write
		{"conflict", false, "true"},         // a conflict cannot match
		{"write_mismatch", true, "true"},    // mismatch that matches
		{"window_closed", false, "true"},    // no comparison happened
		{"window_closed", true, "null"},     // refusal that wrote
		{"not_found", false, "false"},       // null required, not false
		{"write_unverified", false, "null"}, // unverified implies a write
		{"write_unverified", true, "true"},  // unverified cannot claim a match
	}
	for _, c := range bad {
		if _, err := canonicalizeKumaAdoptPushAdopt(adoptResp(c.result, c.written, c.matches)); err == nil {
			t.Errorf("%s/%v/%s: expected refusal, got none", c.result, c.written, c.matches)
		}
	}
}

func TestKumaAdoptRejectsUnknownResult(t *testing.T) {
	if _, err := canonicalizeKumaAdoptPushAdopt(adoptResp("overwritten", true, "true")); err == nil {
		t.Fatal("expected refusal of an unapproved result")
	}
}

func TestKumaAdoptRejectsMissingFields(t *testing.T) {
	// Both a comparing result and a null-comparison result: for the latter, an
	// absent stored_matches_live would otherwise be indistinguishable from null.
	bases := [][]byte{
		adoptResp("already_adopted", false, "true"),
		adoptResp("window_closed", false, "null"),
	}
	for _, base := range bases {
		for _, drop := range []string{"result", "monitor_id", "slug", "openbao_written", "stored_matches_live"} {
			var m map[string]json.RawMessage
			_ = json.Unmarshal(base, &m)
			delete(m, drop)
			raw, _ := json.Marshal(m)
			if _, err := canonicalizeKumaAdoptPushAdopt(raw); err == nil {
				t.Errorf("%s missing %q: expected refusal, got none", base, drop)
			}
		}
	}
}

// Every way a faulty helper could try to hand the token back to the client.
func TestKumaAdoptCannotCarryTokenMaterial(t *testing.T) {
	url := "https://uptime.kevininscoe.com/api/push/" + adoptSentinel
	attempts := []string{
		// extra fields
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":true,"stored_matches_live":true,"push_url":"` + url + `"}`,
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":true,"stored_matches_live":true,"token":"` + adoptSentinel + `"}`,
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":true,"stored_matches_live":true,"fingerprint":"ab12"}`,
		// token smuggled through the string fields
		`{"result":"` + adoptSentinel + `","monitor_id":89,"slug":"x","openbao_written":false,"stored_matches_live":null}`,
		`{"result":"adopted","monitor_id":89,"slug":"` + url + `","openbao_written":true,"stored_matches_live":true}`,
		`{"result":"adopted","monitor_id":89,"slug":"` + strings.ToLower(adoptSentinel) + `-` + strings.Repeat("a", 60) + `","openbao_written":true,"stored_matches_live":true}`,
		// wrong types
		`{"result":"adopted","monitor_id":"` + adoptSentinel + `","slug":"x","openbao_written":true,"stored_matches_live":true}`,
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":"` + adoptSentinel + `","stored_matches_live":true}`,
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":true,"stored_matches_live":"` + adoptSentinel + `"}`,
		// trailing data
		`{"result":"adopted","monitor_id":89,"slug":"x","openbao_written":true,"stored_matches_live":true}` + adoptSentinel,
	}
	for i, raw := range attempts {
		got, err := canonicalizeKumaAdoptPushAdopt([]byte(raw))
		if err == nil {
			t.Errorf("attempt %d: expected refusal, got %s", i, got)
			continue
		}
		if strings.Contains(err.Error(), adoptSentinel) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(adoptSentinel)) {
			t.Errorf("attempt %d: error message leaks the sentinel: %v", i, err)
		}
	}
}

func TestKumaAdoptRejectsOutOfRangeMonitorID(t *testing.T) {
	for _, id := range []string{"0", "-1", "1000000000", "1.5", "99999999999999999999"} {
		raw := `{"result":"not_found","monitor_id":` + id + `,"slug":"x","openbao_written":false,"stored_matches_live":null}`
		if _, err := canonicalizeKumaAdoptPushAdopt([]byte(raw)); err == nil {
			t.Errorf("monitor_id %s: expected refusal", id)
		}
	}
}

func TestKumaAdoptIsRegistered(t *testing.T) {
	if _, ok := responseValidators["kuma-adopt.push-adopt"]; !ok {
		t.Fatal("kuma-adopt.push-adopt has no registered response validator")
	}
}
