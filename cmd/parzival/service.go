package main

// `parzival service` — call an operation through the broker: the client
// side of SERVICE-PROTOCOL.md, for a caller (a human, a script, an AI
// agent) that must use a brokered credential without ever being able to
// read it.
//
// This is a different shape from get/exec/mount/probe above: those all
// authorize against this process's own approval policy and fetch the value
// (or a delivery of it) into this process. `service` authorizes nothing
// itself and never touches the store — it dials the broker's socket, names
// an operation and typed inputs, and prints back exactly what the broker
// decided to return. The broker is the thing enforcing the boundary; this
// command is just a client of it, same trust level as any other caller on
// the far side of the socket. See internal/broker/client.go and
// SERVICE-PROTOCOL.md's "Relationship to the existing CLI" table, which
// frames service mode as replacing get/exec/mount/--as for a caller that has
// moved behind a broker rather than talking to the store directly.
//
// Exit codes mirror probe's approach (distinct, non-parsed) rather than
// forwarding a child process's own exit status (there is no child here):
//
//	0  OK           the operation succeeded; the canonical result is on stdout
//	3  DENIED       the broker refused — not authorized for this operation
//	4  INVALID      the request was malformed or an input failed validation
//	5  ERROR        the broker attempted the operation and it failed
//	6  UNAVAILABLE  the broker cannot serve requests right now
//	1  (other)      a transport-level failure — could not reach the broker at
//	                all, or its response could not be understood; see stderr

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kevinpinscoe/parzival/internal/broker"
)

// defaultServiceSocket matches cmd/parzival-broker/main.go's own default
// (`-socket`/$PARZIVAL_BROKER_SOCKET), so an unconfigured caller on the same
// host finds the broker without extra setup.
const defaultServiceSocket = "/run/parzival/broker.sock"

const (
	serviceExitDenied      = 3
	serviceExitInvalid     = 4
	serviceExitError       = 5
	serviceExitUnavailable = 6
)

// serviceStatusExitCode maps SERVICE-PROTOCOL.md's closed status vocabulary
// to a distinct exit code, so a script can branch on $? without parsing
// stderr text — the same reasoning probe's exit codes document above them.
func serviceStatusExitCode(status string) int {
	switch status {
	case broker.StatusDenied:
		return serviceExitDenied
	case broker.StatusInvalid:
		return serviceExitInvalid
	case broker.StatusError:
		return serviceExitError
	case broker.StatusUnavailable:
		return serviceExitUnavailable
	default:
		// Unreachable against a correctly-behaving broker (the vocabulary is
		// closed), but a transport bug or a future protocol version should
		// not panic a caller — treat as a generic failure.
		return 1
	}
}

// inputFlags accumulates repeated --input name=value flags into a map.
// flag.Value is implemented so `-input owner=acme -input type=source` both
// land in the same request, matching how a caller thinks about "give me
// these named inputs" rather than one flag holding everything.
type inputFlags map[string]string

func (f inputFlags) String() string {
	if len(f) == 0 {
		return ""
	}
	parts := make([]string, 0, len(f))
	for k, v := range f {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (f inputFlags) Set(s string) error {
	name, value, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return fmt.Errorf("--input must be name=value, got %q", s)
	}
	f[name] = value
	return nil
}

func runService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	socketPath := fs.String("socket", envOr("PARZIVAL_BROKER_SOCKET", defaultServiceSocket), "broker AF_UNIX socket path (or $PARZIVAL_BROKER_SOCKET)")
	inputs := make(inputFlags)
	fs.Var(inputs, "input", "name=value input for the operation; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("service requires exactly one operation reference, <consumer>.<operation> (got %d)", fs.NArg())
	}
	operation := fs.Arg(0)

	c, err := broker.Dial(*socketPath)
	if err != nil {
		return fmt.Errorf("could not reach the broker at %s: %w", *socketPath, err)
	}
	defer c.Close()

	resp, err := c.Call(operation, inputs)
	if err != nil {
		return fmt.Errorf("service call failed: %w", err)
	}

	if resp.Status == broker.StatusOK {
		fmt.Println(string(resp.Result))
		return nil
	}

	code, message := "", ""
	if resp.Error != nil {
		code, message = resp.Error.Code, resp.Error.Message
	}
	fmt.Fprintf(os.Stderr, "parzival: %s (%s): %s\n", resp.Status, code, message)
	return &exitError{code: serviceStatusExitCode(resp.Status)}
}

// envOr returns $name if set and non-empty, else def. Mirrors
// cmd/parzival-broker/main.go's own helper of the same name (a separate
// binary — not shared code, deliberately small enough not to be worth a
// package for).
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
