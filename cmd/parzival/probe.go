package main

// `parzival probe` — answer "would this fetch succeed?" without returning the
// value.
//
// This verb exists because its absence caused a leak. Verifying
// that an OpenBao ACL grant actually landed is ordinary work, and until now the
// only tool that could answer it was `parzival get` — which answers by handing
// back the plaintext. So the workflow itself pushed the operator, human or AI,
// toward the one command that can put a credential in a transcript, and the
// only thing standing between that and a clean check was remembering to
// redirect the output every single time. That discipline failed on the twelfth
// call of a session whose previous eleven were correct.
//
// Refusing `get` in an agent shell (see refuseAgentShell in main.go) without
// also providing this would remove the leak and leave the need, which is how a
// control gets worked around. The two changes are a pair.
//
// # Why it takes no --mode
//
// The question is "can this identity reach this ref at all", so probe tries the
// delivery modes in order and reports the first the policy permits. That keeps
// it usable against a policy written before probe existed: it introduces no new
// mode value, needs no rule edit, and grants nothing — an identity that can
// exec a ref could already learn whether the fetch succeeds by running exec.
//
// # What it does not report
//
// Not the value, not its length, not a prefix, not a hash. The verdict
// vocabulary is exactly what an operator was reconstructing by hand with
// `| wc -c` before this existed: OK, EMPTY, DENIED, ERROR.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kevinpinscoe/parzival/internal/policy"
	"github.com/kevinpinscoe/parzival/internal/secret"
	"github.com/kevinpinscoe/parzival/internal/store"
)

// probe exit statuses. They are distinct so a script can tell the four verdicts
// apart without parsing text — "denied by policy" and "the backend refused" are
// different problems with different fixes, and collapsing both into 1 is what
// made an operator reach for `get` to find out which had happened.
const (
	probeExitEmpty  = 3
	probeExitDenied = 4
	probeExitError  = 5
)

// probeModeOrder is the order modes are tried in. `get` first: the question
// an operator most often has is whether an identity can still read a raw
// value, and naming the mode that allowed the fetch
// answers it in the same breath as the reachability check.
var probeModeOrder = []string{policy.ModeGet, policy.ModeExec, policy.ModeMount}

func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	as := fs.String("as", "", "identity label for the approval policy (or $PARZIVAL_IDENTITY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("probe requires exactly one secret reference (got %d)", fs.NArg())
	}

	ref, err := store.ParseRef(fs.Arg(0))
	if err != nil {
		return err
	}
	identity := resolveIdentity(*as)
	now := time.Now()

	p, exists, err := policy.Load()
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	fmt.Printf("Ref:      %s\n", ref.Raw)
	fmt.Printf("Identity: %s\n", identityLabel(identity))

	// No policy file at all is the strict deny-by-default case. Report it as the
	// refusal it is rather than probing three modes that cannot be allowed.
	if !exists {
		fmt.Printf("\nDENIED\n\nReached:  no mode — no policy at %s (strict deny-by-default)\n", policy.Path())
		return &exitError{code: probeExitDenied}
	}

	mode, reason, ok := probeReachableMode(p, ref.Raw, identity, now)
	if !ok {
		fmt.Println("\nDENIED")
		fmt.Println("\nReached:  no mode — get, exec and mount are all denied")
		for _, m := range probeModeOrder {
			d := p.Evaluate(policy.Request{Ref: ref.Raw, Identity: identity, Mode: m, Time: now})
			fmt.Printf("  %-5s  %s\n", m, d.Reason)
		}
		// One honest audit record, under the mode the caller most likely wanted.
		// Probing each mode through Authorize would write three, two of them
		// denials that no caller ever made.
		logProbeDecision(ref.Raw, identity, policy.ModeGet, now)
		return &exitError{code: probeExitDenied}
	}

	if err := logProbeDecision(ref.Raw, identity, mode, now); err != nil {
		// The policy allowed it a moment ago and refuses it now, or the audit log
		// could not be written. Either is a real refusal, not a probe result.
		fmt.Println("\nDENIED")
		fmt.Fprintln(os.Stderr, "parzival:", err)
		return &exitError{code: probeExitDenied}
	}

	backend, err := store.Resolve(ref)
	if err != nil {
		fmt.Printf("\nERROR\n\nReached:  %s (%s)\n", mode, reason)
		fmt.Fprintln(os.Stderr, "parzival:", err)
		return &exitError{code: probeExitError}
	}

	buf, err := backend.Get(context.Background(), ref)
	if err != nil {
		// The interesting failure, and the one this verb was built for: the
		// policy permits the fetch and the store refuses it, which is what an
		// un-granted OpenBao ACL looks like from here.
		fmt.Printf("\nERROR\n\nReached:  %s (%s)\nBackend:  the store refused or failed the fetch\n", mode, reason)
		fmt.Fprintln(os.Stderr, "parzival:", err)
		return &exitError{code: probeExitError}
	}
	defer secret.Zero(buf)

	if len(buf) == 0 {
		fmt.Printf("\nEMPTY\n\nReached:  %s (%s)\nValue:    the fetch succeeded and returned zero bytes\n", mode, reason)
		return &exitError{code: probeExitEmpty}
	}

	fmt.Printf("\nOK\n\nReached:  %s (%s)\nValue:    present — not shown, and probe never shows it\n", mode, reason)
	return nil
}

// probeReachableMode returns the first delivery mode the policy permits for this
// ref and identity, and the reason the decision names (the deciding rule).
func probeReachableMode(p *policy.Policy, ref, identity string, at time.Time) (mode, reason string, ok bool) {
	for _, m := range probeModeOrder {
		d := p.Evaluate(policy.Request{Ref: ref, Identity: identity, Mode: m, Time: at})
		if d.Allow {
			return m, d.Reason, true
		}
	}
	return "", "", false
}

// logProbeDecision writes the one audit record a probe is entitled to.
//
// A probe performs a real fetch against the store, so it belongs in the audit
// log — unlike `policy what-if`, which simulates and deliberately writes
// nothing. Caller marks it as a probe so a reader can tell a reachability check
// from a delivery: the log's job is to answer what was actually retrieved, and
// a probe retrieved nothing the caller can see.
func logProbeDecision(ref, identity, mode string, at time.Time) error {
	return policy.Authorize(policy.Request{
		Ref: ref, Identity: identity, Mode: mode, Time: at, Caller: "probe",
	})
}

func identityLabel(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
}

// probeExitCode extracts a probe verdict's exit status from the error runProbe
// returned, for tests and for callers that need the numeric verdict.
func probeExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}
