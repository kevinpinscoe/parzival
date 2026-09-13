// Command faketea is a hermetic stand-in for the real `tea` CLI, used only by
// internal/broker's tests. It accepts the same argv shape
// examples/consumers/tea.json builds ("repos list --owner <owner> --output
// json") and branches on the --owner value to produce canned behavior for
// each broker acceptance-test scenario. No real tea binary, network access,
// or Gitea credential is involved.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// repoSummary mirrors the shape internal/broker's response_tea.go expects —
// the confirmed real output of `tea repos list --owner ... --output json`
// (tea v0.15.1, default --fields set).
type repoSummary struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	SSH   string `json:"ssh"`
}

func main() {
	owner := ownerArg(os.Args[1:])
	switch owner {
	case "slow":
		// Long enough to exceed any short test-configured operation timeout.
		time.Sleep(5 * time.Second)
		emit([]repoSummary{{Owner: owner, Name: "repo", Type: "source", SSH: "ssh://x"}})

	case "huge":
		// Well over the 1 MiB response bound, still syntactically valid JSON
		// on its own — proves the bound is enforced by size, not shape.
		big := strings.Repeat("x", 2*1024*1024)
		fmt.Print(`[{"owner":"` + owner + `","name":"` + big + `","type":"source","ssh":"ssh://x"}]`)

	case "malformed":
		// Decodes as JSON but does not match the approved array-of-repoSummary
		// shape.
		fmt.Print(`{"not":"an array"}`)

	case "trailing":
		// A complete, valid response followed by non-whitespace trailing
		// bytes within the same stdout stream.
		fmt.Print(`[{"owner":"` + owner + `","name":"repo","type":"source","ssh":"ssh://x"}]garbage-trailing-bytes`)

	case "failing":
		// Nonzero exit with stderr that echoes something that looks like a
		// credential — proves the broker never persists stderr content
		// anywhere, only its length/the exit status.
		fmt.Fprintln(os.Stderr, "error: token gt_FAKESECRETVALUE1234567890 was rejected by the server")
		os.Exit(1)

	case "dump-env":
		// Proves the constructed child environment is exactly the minimal
		// set the broker builds — nothing inherited from the broker's own
		// process environment.
		env := os.Environ()
		b, _ := json.Marshal(env)
		os.Stdout.Write(b)

	default:
		emit([]repoSummary{
			{Owner: owner, Name: "repo-one", Type: "source", SSH: "ssh://git@example.test/" + owner + "/repo-one.git"},
			{Owner: owner, Name: "repo-two", Type: "fork", SSH: "ssh://git@example.test/" + owner + "/repo-two.git"},
		})
	}
}

func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}

func ownerArg(args []string) string {
	for i, a := range args {
		if a == "--owner" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
