package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// A plausible push token. It must never survive canonicalization in any form.
const adoptSentinel = "SENTINELtok9Qz"

func adoptResp(result string, written bool, matches string) []byte {
	return []byte(`{"result":"` + result + `","openbao_written":` +
		map[bool]string{true: "true", false: "false"}[written] +
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
		if len(m) != 3 || m["result"] != c.result || m["openbao_written"] != c.written {
			t.Errorf("%s: canonical output wrong: %s", c.result, got)
		}
	}
}

// Every outcome in the table is covered above, so a new enum value cannot be
// added without a coherence test.
func TestKumaAdoptOutcomeTableIsFullyTested(t *testing.T) {
	if len(adoptOutcomes) != 13 {
		t.Fatalf("adoptOutcomes has %d entries; update the tests alongside it", len(adoptOutcomes))
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
		{"write_unverified", false, "null"}, // unverified implies a write
		{"write_unverified", true, "true"},  // unverified cannot claim a match
		{"window_closed", false, "true"},    // no comparison happened
		{"window_closed", true, "null"},     // refusal that wrote
		{"not_found", false, "false"},       // null required, not false
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
	// A comparing result and a null-comparison result: for the latter, an
	// absent stored_matches_live would otherwise be indistinguishable from null.
	bases := [][]byte{
		adoptResp("already_adopted", false, "true"),
		adoptResp("window_closed", false, "null"),
	}
	for _, base := range bases {
		for _, drop := range []string{"result", "openbao_written", "stored_matches_live"} {
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

// The removed monitor_id and slug fields are now unknown fields: a helper
// still sending them is refused, so neither can become a free-form channel
// again by accident.
func TestKumaAdoptRejectsTheRemovedEchoFields(t *testing.T) {
	for _, extra := range []string{
		`"monitor_id":89`,
		`"slug":"container-crashloop"`,
		`"monitor_id":89,"slug":"container-crashloop"`,
	} {
		raw := `{"result":"already_adopted","openbao_written":false,"stored_matches_live":true,` + extra + `}`
		if _, err := canonicalizeKumaAdoptPushAdopt([]byte(raw)); err == nil {
			t.Errorf("%s: expected refusal of a removed field", extra)
		}
	}
}

// Every way a faulty helper could try to hand token material back. With no
// free-form string or numeric field in the shape, each must be refused.
func TestKumaAdoptCannotCarryTokenMaterial(t *testing.T) {
	url := "https://uptime.kevininscoe.com/api/push/" + adoptSentinel
	const ok = `"result":"adopted","openbao_written":true,"stored_matches_live":true`
	attempts := []string{
		// extra fields of every JSON type
		`{` + ok + `,"push_url":"` + url + `"}`,
		`{` + ok + `,"token":"` + adoptSentinel + `"}`,
		`{` + ok + `,"fingerprint":"ab12"}`,
		`{` + ok + `,"token_length":20}`,
		`{` + ok + `,"detail":{"t":"` + adoptSentinel + `"}}`,
		`{` + ok + `,"n":[1,2,3]}`,
		// smuggled through the one string field
		`{"result":"` + adoptSentinel + `","openbao_written":false,"stored_matches_live":null}`,
		`{"result":"adopted ` + adoptSentinel + `","openbao_written":true,"stored_matches_live":true}`,
		// wrong types for the booleans
		`{"result":"adopted","openbao_written":"` + adoptSentinel + `","stored_matches_live":true}`,
		`{"result":"adopted","openbao_written":1,"stored_matches_live":true}`,
		`{"result":"adopted","openbao_written":true,"stored_matches_live":"` + adoptSentinel + `"}`,
		`{"result":"adopted","openbao_written":true,"stored_matches_live":20}`,
		// trailing data
		`{` + ok + `}` + adoptSentinel,
		`{` + ok + `}{"token":"` + adoptSentinel + `"}`,
	}
	for i, raw := range attempts {
		got, err := canonicalizeKumaAdoptPushAdopt([]byte(raw))
		if err == nil {
			t.Errorf("attempt %d: expected refusal, got %s", i, got)
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(adoptSentinel)) {
			t.Errorf("attempt %d: error message leaks the sentinel: %v", i, err)
		}
	}
}

// The canonical output is re-marshalled from the approved struct, so it has
// exactly three keys whatever the helper's key order or spacing.
func TestKumaAdoptCanonicalIsFresh(t *testing.T) {
	got, err := canonicalizeKumaAdoptPushAdopt([]byte(
		"{ \"stored_matches_live\" : null ,\n \"openbao_written\":false, \"result\":\"window_closed\" }"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"result":"window_closed","openbao_written":false,"stored_matches_live":null}` {
		t.Errorf("canonical output not freshly marshalled: %s", got)
	}
}

func TestKumaAdoptIsRegistered(t *testing.T) {
	if _, ok := responseValidators["kuma-adopt.push-adopt"]; !ok {
		t.Fatal("kuma-adopt.push-adopt has no registered response validator")
	}
}
