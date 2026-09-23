package broker

import (
	"encoding/json"
	"fmt"
)

// kumaAdoptPushAdoptResult is the declared response shape of the
// kuma-adopt.push-adopt helper (a deployment's own executable; the product
// ships none). The helper copies an
// EXISTING Uptime Kuma push token into OpenBao, or proves the copy already
// there equals the live token. It never returns the token or anything
// derived from it.
//
// The response is deliberately a closed enum plus two booleans, and nothing
// else:
//
//	{"result": "...", "openbao_written": bool, "stored_matches_live": bool|null}
//
// There is no string or numeric field whose value the helper chooses, so
// there is no channel through which a faulty helper could hand token
// material back to the client. The client already knows the monitor ID and
// slug it supplied. Echoing them back could prove only syntax, never
// equality with what was sent, so the first version's monitor_id and slug
// were removed.
//
// Like kuma.push-mint's and woodpecker.repo-secret-set's validators, every
// field is decoded AND checked against a closed set. The fields are not
// independent, so this validator also requires:
//
//   - every key present; pointer fields make a missing key detectable, and
//     stored_matches_live's presence is tracked separately from its value
//     because it is nullable
//   - `result` one of adoptOutcomes
//   - `openbao_written` and `stored_matches_live` coherent with `result`
//     (for example, "conflict" can never have written, and "adopted" must
//     have written and matched)
type kumaAdoptPushAdoptResult struct {
	Result            *string `json:"result"`
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

// adoptOutcome is what a result permits. written is nil where either value is
// coherent. matchesNull means stored_matches_live must be JSON null;
// otherwise it must equal *matches.
type adoptOutcome struct {
	written     *bool
	matches     *bool
	matchesNull bool
}

var (
	adoptTrue  = true
	adoptFalse = false
)

// adoptOutcomes must stay in step with the helper's own result table.
var adoptOutcomes = map[string]adoptOutcome{
	// A new OpenBao entry was created and read back equal to the live token.
	"adopted": {written: &adoptTrue, matches: &adoptTrue},
	// OpenBao already held a token equal to the live one: nothing written.
	"already_adopted": {written: &adoptFalse, matches: &adoptTrue},
	// OpenBao holds a DIFFERENT token: never overwritten.
	"conflict": {written: &adoptFalse, matches: &adoptFalse},
	// Created, but the read-back differs from the live token: an alarm.
	"write_mismatch": {written: &adoptTrue, matches: &adoptFalse},
	// Created, but the read-back could not be performed (a window granting
	// create without read, or OpenBao failing mid-operation): unverified.
	"write_unverified": {written: &adoptTrue, matchesNull: true},
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
	if r.Result == nil || r.OpenBaoWritten == nil || !r.storedMatchesLiveSet {
		return nil, fmt.Errorf("%s: response is missing a required field", op)
	}
	outcome, ok := adoptOutcomes[*r.Result]
	if !ok {
		return nil, fmt.Errorf("%s: response result is not an approved value", op)
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
		OpenBaoWritten    bool   `json:"openbao_written"`
		StoredMatchesLive *bool  `json:"stored_matches_live"`
	}{*r.Result, *r.OpenBaoWritten, r.StoredMatchesLive})
	if err != nil {
		return nil, fmt.Errorf("%s: marshal canonical response: %w", op, err)
	}
	return canonical, nil
}
