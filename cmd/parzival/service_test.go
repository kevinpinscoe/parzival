package main

import (
	"errors"
	"testing"

	"github.com/kevinpinscoe/parzival/internal/broker"
)

func TestInputFlagsSetAccumulates(t *testing.T) {
	f := make(inputFlags)
	if err := f.Set("owner=acme"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("type=source"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f["owner"] != "acme" || f["type"] != "source" {
		t.Errorf("got %+v", f)
	}
}

func TestInputFlagsSetRejectsMalformed(t *testing.T) {
	f := make(inputFlags)
	for _, s := range []string{"", "novalue", "=noname"} {
		if err := f.Set(s); err == nil {
			t.Errorf("Set(%q) should have been rejected", s)
		}
	}
}

func TestServiceStatusExitCode(t *testing.T) {
	cases := []struct {
		status string
		want   int
	}{
		{broker.StatusDenied, serviceExitDenied},
		{broker.StatusInvalid, serviceExitInvalid},
		{broker.StatusError, serviceExitError},
		{broker.StatusUnavailable, serviceExitUnavailable},
		{"SOMETHING_UNKNOWN", 1},
	}
	for _, c := range cases {
		if got := serviceStatusExitCode(c.status); got != c.want {
			t.Errorf("serviceStatusExitCode(%q) = %d, want %d", c.status, got, c.want)
		}
	}
}

func TestRunServiceRejectsWrongArgumentCount(t *testing.T) {
	if err := runService(nil); err == nil {
		t.Error("runService with no operation argument should fail")
	}
	if err := runService([]string{"a.b", "c.d"}); err == nil {
		t.Error("runService with two operation arguments should fail")
	}
}

func TestRunServiceRejectsMalformedInput(t *testing.T) {
	err := runService([]string{"--input", "novalue", "tea.repos-list"})
	if err == nil {
		t.Fatal("expected a flag-parsing error for a malformed --input")
	}
}

func TestRunServiceUnreachableBrokerIsNotAnExitError(t *testing.T) {
	// No broker is listening at this socket path, so Dial fails before any
	// protocol status exists to map — this must be a plain error (main's
	// generic os.Exit(1) path), not an *exitError carrying one of the
	// protocol-status codes, which would misleadingly claim the broker
	// itself answered.
	err := runService([]string{"--socket", t.TempDir() + "/no-such-socket", "tea.repos-list"})
	if err == nil {
		t.Fatal("expected an error when no broker is reachable")
	}
	var ee *exitError
	if errors.As(err, &ee) {
		t.Errorf("unreachable-broker error should not be an *exitError (got code %d) — that would misreport it as a protocol-level status", ee.code)
	}
}
