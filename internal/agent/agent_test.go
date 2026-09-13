package agent

import "testing"

// env builds a getenv function over a fixed map, so a test can present exactly
// one marker without touching the real environment — which, in a test binary
// that itself may be run from an agent shell, would otherwise make the result
// depend on who ran `go test`.
func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

func TestDetectFindsEveryMarker(t *testing.T) {
	for _, m := range Markers() {
		got, ok := detect(env(map[string]string{m.Env: "1"}))
		if !ok {
			t.Errorf("marker %s set: want detected, got not detected", m.Env)
			continue
		}
		if got.Env != m.Env {
			t.Errorf("marker %s set: identified by %s, want %s", m.Env, got.Env, m.Env)
		}
	}
}

func TestDetectCleanEnvironment(t *testing.T) {
	if m, ok := detect(env(nil)); ok {
		t.Errorf("clean environment: want not detected, got %s (%s)", m.Env, m.Agent)
	}
}

// An empty value is absence. A harness that exports a marker as "" has not
// identified itself, and treating that as a detection would refuse `get` in an
// ordinary shell where something happened to clear the variable.
func TestDetectEmptyValueIsNotPresence(t *testing.T) {
	if m, ok := detect(env(map[string]string{"CLAUDECODE": ""})); ok {
		t.Errorf("CLAUDECODE set to empty: want not detected, got %s", m.Env)
	}
}

// Any non-empty value counts. Harnesses are not consistent about what they set
// these to, and a value check would fail open the first time one changed.
func TestDetectAnyNonEmptyValue(t *testing.T) {
	for _, v := range []string{"1", "0", "false", "cli", "claude-code_2-1-263_agent"} {
		if _, ok := detect(env(map[string]string{"CLAUDE_CODE_ENTRYPOINT": v})); !ok {
			t.Errorf("CLAUDE_CODE_ENTRYPOINT=%q: want detected, got not detected", v)
		}
	}
}

// The explicit self-declaration wins, so an operator who set PARZIVAL_AGENT is
// told that is why rather than being shown some other harness's marker.
func TestDetectPrefersExplicitDeclaration(t *testing.T) {
	m, ok := detect(env(map[string]string{
		"PARZIVAL_AGENT": "1",
		"CLAUDECODE":     "1",
		"AI_AGENT":       "something",
	}))
	if !ok {
		t.Fatal("want detected, got not detected")
	}
	if m.Env != "PARZIVAL_AGENT" {
		t.Errorf("identified by %s, want PARZIVAL_AGENT", m.Env)
	}
}

// AI_AGENT is the catch-all and must not shadow a marker that can name the
// harness precisely.
func TestDetectGenericMarkerIsLast(t *testing.T) {
	m, ok := detect(env(map[string]string{"AI_AGENT": "x", "CURSOR_AGENT": "1"}))
	if !ok {
		t.Fatal("want detected, got not detected")
	}
	if m.Env != "CURSOR_AGENT" {
		t.Errorf("identified by %s, want CURSOR_AGENT", m.Env)
	}
}

// Markers hands out a copy: a caller that mutates the returned slice must not
// be able to disable a marker for the whole process.
func TestMarkersReturnsACopy(t *testing.T) {
	got := Markers()
	if len(got) == 0 {
		t.Fatal("Markers returned nothing")
	}
	first := got[0]
	got[0] = Marker{Env: "TAMPERED", Agent: "tampered"}
	if Markers()[0] != first {
		t.Error("mutating the returned slice changed the package's marker list")
	}
}
