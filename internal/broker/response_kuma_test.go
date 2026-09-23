package broker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kevinpinscoe/parzival/internal/consumer"
)

// A neutral example deployment. No real deployment's origin belongs in the
// product: the value comes from the administrator's consumer definition.
const (
	mintOrigin = "https://uptime.example.test"
	mintToken  = "0123456789abcdef0123456789abcdef"
	mintGood   = mintOrigin + "/api/push/" + mintToken
)

var mintCfg = map[string]string{"push_origin": mintOrigin}

func mint(raw string) (json.RawMessage, error) {
	return canonicalizeKumaPushMint([]byte(raw), mintCfg)
}

func mintCreated(url string) string {
	b, _ := json.Marshal(map[string]any{"created": true, "push_url": url})
	return string(b)
}

func TestKumaPushMintAcceptsTheExactHelperForm(t *testing.T) {
	got, err := mint(mintCreated(mintGood))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"created":true,"push_url":"`+mintGood+`"}` {
		t.Errorf("got %s", got)
	}
}

func TestKumaPushMintAcceptsRefusedReasons(t *testing.T) {
	for _, reason := range []string{"already_exists", "permission_denied"} {
		want := `{"created":false,"reason":"` + reason + `"}`
		got, err := mint(want)
		if err != nil || string(got) != want {
			t.Errorf("%s: got %s, %v", reason, got, err)
		}
	}
}

func TestKumaPushMintRejectsShapeViolations(t *testing.T) {
	for _, raw := range []string{
		`["not", "an", "object"]`,
		`{"created":true,"push_url":"` + mintGood + `","extra":"field"}`,
		`{"created":true,"push_url":"` + mintGood + `"}garbage`,
		`{"created":true,"push_url":"` + mintGood + `","role_id":"x"}`,
		`{"created":false,"reason":"SENTINEL-reason"}`,
		`{"created":false,"reason":""}`,
		`{"created":false}`,
		`{"created":false,"reason":"already_exists","push_url":"` + mintGood + `"}`,
		`{"created":true}`,
		`{"created":true,"push_url":"` + mintGood + `","reason":"already_exists"}`,
	} {
		_, err := mint(raw)
		if err == nil {
			t.Errorf("%s: expected refusal, got none", raw)
			continue
		}
		if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("%s: error leaks the value: %v", raw, err)
		}
	}
}

// Sentinel material in every URL component must be refused, and never echoed
// in the error.
func TestKumaPushMintRejectsSentinelInEveryURLComponent(t *testing.T) {
	const s = "sentinel0tok"
	tok := mintToken
	bad := map[string]string{
		"hostname prefix":     "https://" + s + ".uptime.example.test/api/push/" + tok,
		"hostname suffix":     "https://uptime.example.test." + s + ".example/api/push/" + tok,
		"other host":          "https://" + s + ".example/api/push/" + tok,
		"unconfigured port":   "https://uptime.example.test:8443/api/push/" + tok,
		"userinfo user":       "https://" + s + "@uptime.example.test/api/push/" + tok,
		"userinfo user:pass":  "https://u:" + s + "@uptime.example.test/api/push/" + tok,
		"query":               mintGood + "?t=" + s,
		"empty query":         mintGood + "?",
		"fragment":            mintGood + "#" + s,
		"empty fragment":      mintGood + "#",
		"extra path suffix":   mintGood + "/" + s,
		"extra path prefix":   "https://uptime.example.test/" + s + "/api/push/" + tok,
		"trailing slash":      mintGood + "/",
		"dot segment":         "https://uptime.example.test/api/push/../push/" + tok,
		"encoded slash":       "https://uptime.example.test/api/push%2F" + tok,
		"encoded token":       "https://uptime.example.test/api/push/%30123456789abcdef0123456789abcdef",
		"http scheme":         "http://uptime.example.test/api/push/" + tok,
		"uppercase scheme":    "HTTPS://uptime.example.test/api/push/" + tok,
		"uppercase host":      "https://UPTIME.example.test/api/push/" + tok,
		"token too short":     mintOrigin + "/api/push/" + tok[:31],
		"token too long":      mintGood + "0",
		"token oversized":     mintOrigin + "/api/push/" + tok + tok + tok,
		"token uppercase hex": mintOrigin + "/api/push/0123456789ABCDEF0123456789ABCDEF",
		"token non-hex":       mintOrigin + "/api/push/" + s + "0123456789abcdef0123",
		"token empty":         mintOrigin + "/api/push/",
		"no path":             mintOrigin,
		"leading space":       " " + mintGood,
		"trailing newline":    mintGood + "\n",
		"opaque":              "https:uptime.example.test/api/push/" + tok,
	}
	for name, u := range bad {
		_, err := mint(mintCreated(u))
		if err == nil {
			t.Errorf("%s: expected refusal of %q", name, u)
			continue
		}
		if strings.Contains(err.Error(), s) || strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error leaks URL material: %v", name, err)
		}
	}
}

// A port is allowed only when the configured origin states one, and then
// only that port.
func TestKumaPushMintPortFollowsTheConfiguredOrigin(t *testing.T) {
	withPort := map[string]string{"push_origin": "https://uptime.example.test:8443"}
	ok := "https://uptime.example.test:8443/api/push/" + mintToken
	if _, err := canonicalizeKumaPushMint([]byte(mintCreated(ok)), withPort); err != nil {
		t.Errorf("configured port: unexpected refusal: %v", err)
	}
	for _, u := range []string{
		mintGood, // port omitted
		"https://uptime.example.test:9443/api/push/" + mintToken,
		"https://uptime.example.test:08443/api/push/" + mintToken,
	} {
		if _, err := canonicalizeKumaPushMint([]byte(mintCreated(u)), withPort); err == nil {
			t.Errorf("%s: expected refusal against a configured :8443", u)
		}
	}
}

// The expected origin is the configured one, not any compiled-in host: the
// same URL is refused under a different deployment's configuration.
func TestKumaPushMintOriginComesFromConfiguration(t *testing.T) {
	other := map[string]string{"push_origin": "https://status.example.test"}
	if _, err := canonicalizeKumaPushMint([]byte(mintCreated(mintGood)), other); err == nil {
		t.Fatal("a push_url for one origin was accepted under another origin's configuration")
	}
	good := "https://status.example.test/api/push/" + mintToken
	if _, err := canonicalizeKumaPushMint([]byte(mintCreated(good)), other); err != nil {
		t.Errorf("configured origin refused: %v", err)
	}
}

func TestCheckKumaPushOrigin(t *testing.T) {
	for _, ok := range []string{
		"https://uptime.example.test",
		"https://uptime.example.test:8443",
		"https://192.0.2.10",
		"https://[2001:db8::1]:8443",
	} {
		if err := checkKumaPushOrigin(map[string]string{"push_origin": ok}); err != nil {
			t.Errorf("%q: unexpected refusal: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://uptime.example.test",
		"https://uptime.example.test/",
		"https://uptime.example.test/api",
		"https://u:p@uptime.example.test",
		"https://uptime.example.test?x=1",
		"https://uptime.example.test?",
		"https://uptime.example.test#f",
		"https://UPTIME.example.test",
		"HTTPS://uptime.example.test",
		"https://uptime.example.test:0",
		"https://uptime.example.test:65536",
		"https://uptime.example.test:08443",
		"https://uptime.example.test:",
		"https://",
		"uptime.example.test",
		"https:uptime.example.test",
	} {
		if err := checkKumaPushOrigin(map[string]string{"push_origin": bad}); err == nil {
			t.Errorf("%q: expected refusal", bad)
		}
	}
}

func TestValidatorForKumaPushMintConfiguration(t *testing.T) {
	op := func(cfg map[string]string) consumer.Operation {
		return consumer.Operation{Response: consumer.ResponseJSON, ResponseConfig: cfg}
	}
	v, err := validatorFor("kuma.push-mint", op(mintCfg))
	if err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	if _, err := v([]byte(mintCreated(mintGood))); err != nil {
		t.Errorf("bound validator refused a valid response: %v", err)
	}
	for name, cfg := range map[string]map[string]string{
		"missing":     nil,
		"empty map":   {},
		"extra key":   {"push_origin": mintOrigin, "other": "x"},
		"wrong key":   {"origin": mintOrigin},
		"bad origin":  {"push_origin": "http://uptime.example.test"},
		"with a path": {"push_origin": mintOrigin + "/"},
	} {
		if _, err := validatorFor("kuma.push-mint", op(cfg)); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

// A plain validator refuses configuration it would never read.
func TestValidatorForRefusesConfigOnPlainValidators(t *testing.T) {
	op := consumer.Operation{Response: consumer.ResponseJSON,
		ResponseConfig: map[string]string{"push_origin": mintOrigin}}
	for _, name := range []string{"tea.repos-list", "kuma-adopt.push-adopt"} {
		if _, err := validatorFor(name, op); err == nil {
			t.Errorf("%s: response_config accepted by a validator that takes none", name)
		}
	}
	if _, err := validatorFor("nope.missing", consumer.Operation{}); err != errNoResponseValidator {
		t.Errorf("unknown operation: got %v", err)
	}
}

// Configuration changes after resolution cannot affect the bound validator.
func TestValidatorForCopiesConfiguration(t *testing.T) {
	cfg := map[string]string{"push_origin": mintOrigin}
	v, err := validatorFor("kuma.push-mint", consumer.Operation{Response: consumer.ResponseJSON, ResponseConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	cfg["push_origin"] = "https://attacker.example.test"
	if _, err := v([]byte(mintCreated(mintGood))); err != nil {
		t.Errorf("bound validator followed a later mutation: %v", err)
	}
}

// No operation may be registered as both a plain and a configured validator.
func TestNoValidatorRegisteredTwice(t *testing.T) {
	for name := range configuredResponseValidators {
		if _, dup := responseValidators[name]; dup {
			t.Errorf("%s is registered as both a plain and a configured validator", name)
		}
	}
	if _, ok := configuredResponseValidators["kuma.push-mint"]; !ok {
		t.Error("kuma.push-mint is not registered as a configured validator")
	}
}
