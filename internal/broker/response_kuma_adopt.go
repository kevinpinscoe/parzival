package broker

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// kumaAdoptPushAdoptResult is the declared response shape of the
// kuma-adopt.push-adopt helper (parzival-k-fed-config's
// hosts/fldw/parzival-broker/kuma-push-adopt.py). The helper copies an
// EXISTING Uptime Kuma push token into OpenBao, or proves the copy already
// there equals the live token. It never returns the token, a URL, a hash, a
// fingerprint, or anything derived from the token.
//
// This is stricter than kuma.push-mint's validator, which accepts any
// string in `reason`, and it follows woodpecker.repo-secret-set's rule:
// every field is decoded AND checked against a closed set. It goes one step
// further than that validator because the fields are not independent:
//
//   - every key is required. Pointer fields make a missing key detectable,
//     where a plain field would silently decode it as its zero value.
//   - `result` must be one of the known outcomes.
//   - `slug` must match the consumer's input pattern and bound, so it cannot
//     carry anything the client did not already send.
//   - `openbao_written` and `stored_matches_live` must agree with `result`
//     (adoptOutcomes). An incoherent combination, such as "adopted" without
//     a write, is a faulty helper and is refused rather than passed on.
type kumaAdoptPushAdoptResult struct {
	Result            *string `json:"result"`
	MonitorID         *int64  `json:"monitor_id"`
	Slug              *string `json:"slug"`
	OpenBaoWritten    *bool   `json:"openbao_written"`
	StoredMatchesLive *bool   `json:"stored_matches_live"`
	// storedMatchesLiveSet records that the key was present even when its
	// value is JSON null, which a *bool alone cannot distinguish from absent.
	storedMatchesLiveSet bool
}

// UnmarshalJSON records whether stored_matches_live was present (it is
// nullable, so presence is separate from value), then decodes into an alias
// type through decodeExactlyOne, which keeps unknown-field refusal intact.
// The alias has no UnmarshalJSON method, so this does not recurse.
func (r *kumaAdoptPushAdoptResult) UnmarshalJSON(data []byte) error {
	type alias kumaAdoptPushAdoptResult
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	_, r.storedMatchesLiveSet = keys["stored_matches_live"]
	return decodeExactlyOne(data, (*alias)(r))
}

// adoptOutcome is what a result permits. written/matches are nil where the
// result allows either value (matches: nil means "must be JSON null").
type adoptOutcome struct {
	written     *bool // nil: either true or false is coherent
	matches     *bool // nil with matchesNull: must be null
	matchesNull bool
}

var (
	adoptTrue  = true
	adoptFalse = false
)

// adoptOutcomes must stay in step with RESULTS in kuma-push-adopt.py.
var adoptOutcomes = map[string]adoptOutcome{
	// A new OpenBao entry was created and read back equal to the live token.
	"adopted": {written: &adoptTrue, matches: &adoptTrue},
	// OpenBao already held a token equal to the live one: nothing written.
	"already_adopted": {written: &adoptFalse, matches: &adoptTrue},
	// OpenBao holds a DIFFERENT token: never overwritten.
	"conflict": {written: &adoptFalse, matches: &adoptFalse},
	// Created, but the read-back differs from the live token: an alarm.
	"write_mismatch": {written: &adoptTrue, matches: &adoptFalse},
	// Refusals and failures: no comparison was completed.
	"window_closed":       {written: &adoptFalse, matchesNull: true},
	"not_found":           {written: &adoptFalse, matchesNull: true},
	"not_push":            {written: &adoptFalse, matchesNull: true},
	"no_live_token":       {written: &adoptFalse, matchesNull: true},
	"soft_deleted":        {written: &adoptFalse, matchesNull: true},
	"kuma_unavailable":    {written: &adoptFalse, matchesNull: true},
	"openbao_unavailable": {written: &adoptFalse, matchesNull: true},
	// The live monitor changed between the first and second read. The write,
	// if any, happened before the change was seen, so either value is
	// coherent for openbao_written.
	"kuma_changed_during_adopt": {written: nil, matchesNull: true},
}

// kumaAdoptSlugRE and kumaAdoptSlugMax mirror broker/consumers/kuma-adopt.json's
// `slug` input in parzival-k-fed-config.
var kumaAdoptSlugRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

const (
	kumaAdoptSlugMax      = 64
	kumaAdoptMonitorIDMax = 999999999
)

func init() {
	responseValidators["kuma-adopt.push-adopt"] = canonicalizeKumaAdoptPushAdopt
}

// canonicalizeKumaAdoptPushAdopt decodes raw strictly (no unknown fields, no
// trailing data), checks every field against its closed set and the
// result's coherence rules, then re-marshals a fresh value as the canonical
// result. No offending value is ever placed in an error: it is exactly the
// data this check exists to stop.
func canonicalizeKumaAdoptPushAdopt(raw []byte) (json.RawMessage, error) {
	const op = "kuma-adopt.push-adopt"
	var r kumaAdoptPushAdoptResult
	if err := decodeExactlyOne(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: response did not match the approved shape: %w", op, err)
	}
	if r.Result == nil || r.MonitorID == nil || r.Slug == nil || r.OpenBaoWritten == nil ||
		!r.storedMatchesLiveSet {
		return nil, fmt.Errorf("%s: response is missing a required field", op)
	}
	outcome, ok := adoptOutcomes[*r.Result]
	if !ok {
		return nil, fmt.Errorf("%s: response result is not an approved value", op)
	}
	if *r.MonitorID < 1 || *r.MonitorID > kumaAdoptMonitorIDMax {
		return nil, fmt.Errorf("%s: response monitor_id is out of range", op)
	}
	if len(*r.Slug) > kumaAdoptSlugMax || !kumaAdoptSlugRE.MatchString(*r.Slug) {
		return nil, fmt.Errorf("%s: response slug is not an approved value", op)
	}
	if outcome.written != nil && *r.OpenBaoWritten != *outcome.written {
		return nil, fmt.Errorf("%s: openbao_written is incoherent with the result", op)
	}
	switch {
	case outcome.matchesNull && r.StoredMatchesLive != nil:
		return nil, fmt.Errorf("%s: stored_matches_live must be null for this result", op)
	case !outcome.matchesNull && (r.StoredMatchesLive == nil || *r.StoredMatchesLive != *outcome.matches):
		return nil, fmt.Errorf("%s: stored_matches_live is incoherent with the result", op)
	}
	canonical, err := json.Marshal(struct {
		Result            string `json:"result"`
		MonitorID         int64  `json:"monitor_id"`
		Slug              string `json:"slug"`
		OpenBaoWritten    bool   `json:"openbao_written"`
		StoredMatchesLive *bool  `json:"stored_matches_live"`
	}{*r.Result, *r.MonitorID, *r.Slug, *r.OpenBaoWritten, r.StoredMatchesLive})
	if err != nil {
		return nil, fmt.Errorf("%s: marshal canonical response: %w", op, err)
	}
	return canonical, nil
}
