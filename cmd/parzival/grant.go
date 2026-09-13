package main

// `parzival policy grant` and `parzival policy apply` — the commands that change
// the live policy.
//
// Both own the whole transaction rather than any step of it, because the steps
// are only safe in order and only safe together:
//
//	build → place → candidate → validate → analyse → delta → diff → confirm
//	      → back up → install atomically → verify → restore on failure
//
// Two properties are worth stating outright, because every design decision below
// follows from one of them.
//
// **The live policy is not touched until a complete candidate has passed every
// check.** Not appended to, not opened for writing, not partially rewritten. The
// candidate is built in memory, written to its own file, and re-read through the
// production parser; only then is anything installed, and installation is a
// rename over the top.
//
// **What the operator approved is what gets installed.** The delta, the diff and
// the what-if table are all computed from the same candidate object that is
// later marshalled and renamed into place, and the installed file is re-read and
// compared afterwards. An editor that showed one thing and installed another
// would be worse than no editor, since it would carry the operator's confidence
// without deserving it.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

// stringList collects a repeatable flag: --secret A --secret B.
//
// Repetition rather than a comma-separated list, because a secret ref and an
// identity glob may legitimately contain a comma, and splitting on one would
// silently mangle a rule into something the operator did not write.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// --- policy grant ---------------------------------------------------------

func runPolicyGrant(args []string) error {
	fs := flag.NewFlagSet("policy grant", flag.ContinueOnError)
	var secrets, identities stringList
	fs.Var(&secrets, "secret", "secret reference or glob to grant (repeat for several)")
	fs.Var(&identities, "identity", "identity label or glob to grant to (repeat for several)")
	tool := fs.String("tool", "", "the tool or consumer needing access (recorded in the rule's description)")
	goal := fs.String("goal", "", "why access is needed (recorded in the rule's description)")
	modes := fs.String("modes", "", "delivery modes, comma-separated (default: exec,mount — raw get is never granted unless named)")
	weekdays := fs.String("weekdays", "", "limit the rule to these weekdays, comma-separated (e.g. Mon,Tue)")
	monthdays := fs.String("monthdays", "", "limit the rule to these days of the month, comma-separated")
	hours := fs.String("hours", "", "limit the rule to this local time window, HH:MM-HH:MM")
	at := fs.Int("at", -1, "insert at this rule index instead of the computed one (use only when placement is reported ambiguous)")
	interactive := fs.Bool("interactive", false, "prompt for the grant's details instead of taking them from flags")
	apply := fs.Bool("apply", false, "install the result; without this the candidate is written and analysed but the live policy is untouched")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (for non-interactive use; requires --apply)")
	file := fs.String("file", "", "policy file to edit (default: the live policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy grant takes no positional arguments (got %q)", fs.Arg(0))
	}

	req := policy.GrantRequest{
		Tool: *tool, Goal: *goal,
		Secrets: secrets, Identities: identities,
		Modes: splitCommas(*modes), Weekdays: splitCommas(*weekdays), Hours: *hours,
	}
	var err error
	if req.Monthdays, err = parseMonthdays(*monthdays); err != nil {
		return err
	}

	if *interactive {
		if req, err = gatherInteractively(os.Stdin, os.Stdout, req); err != nil {
			return err
		}
	}

	// Warn before the rule is built, not after it is installed. The operator can
	// still ask for it — this is a capability, not a prohibition — but it should
	// never be something they discover afterwards.
	if req.GrantsRawGet() {
		fmt.Println()
		fmt.Println("WARNING: this rule permits the caller to retrieve the raw secret value.")
		fmt.Println()
		fmt.Println("  Brokered exec or mount access may be sufficient and exposes less secret")
		fmt.Println("  material to the caller: with exec or mount the value is placed in a 0600")
		fmt.Println("  RAM-backed file the consumer opens, and never enters a stream the caller")
		fmt.Println("  controls. With get it goes to the caller's stdout, which may be a log, a")
		fmt.Println("  terminal, CI output, or an AI agent's transcript.")
	}

	rule, err := policy.BuildGrantRule(req)
	if err != nil {
		return err
	}

	live, path, exists, err := loadPolicyFile(*file)
	if err != nil {
		return err
	}
	if !exists {
		// Granting the first rule on a host with no policy is legitimate. Say so,
		// rather than treating an absent file as an error.
		fmt.Printf("no policy at %s — this grant creates it\n", path)
		live = &policy.Policy{Schema: policy.SchemaVersion}
	}

	// --- placement ---
	pl := live.AnalyzeRuleInsertion(rule)
	index := pl.Index
	switch {
	case *at >= 0:
		index = *at
		fmt.Printf("\nPlacement: rule %d, as given by --at.\n", index)
		if pl.Err != nil {
			fmt.Println("  (the computed placement was refused; --at overrides it — check the")
			fmt.Println("   authorization delta below especially carefully)")
		}
	case pl.Err != nil:
		fmt.Println()
		return fmt.Errorf("%w\n\nRe-run with --at <index> if you have decided where it belongs", pl.Err)
	default:
		fmt.Printf("\nPlacement: rule %d", index)
		if index == 0 && len(live.Rules) > 0 {
			fmt.Print(" (at the top)")
		} else if index >= len(live.Rules) {
			fmt.Print(" (at the end)")
		}
		fmt.Println()
		if len(pl.BlockedBy) > 0 {
			fmt.Printf("  above %s, which would otherwise decide these requests first\n", ruleWord(pl.BlockedBy))
		}
		if len(pl.WouldBlock) > 0 {
			fmt.Printf("  below %s, which it would otherwise leave unreachable\n", ruleWord(pl.WouldBlock))
		}
	}
	if pl.Redundant() {
		fmt.Printf("\nNOTE: rule %d already reaches the same outcome for everything this rule\n", pl.CoveredBy)
		fmt.Println("covers. Adding it changes no authorization — consider whether you meant")
		fmt.Println("something narrower, or whether the existing rule is broader than intended.")
	}

	candidate, err := live.InsertRule(rule, index)
	if err != nil {
		return err
	}

	fmt.Println("\nProposed rule:")
	fmt.Print(indentRule(rule, "  "))

	return runTransaction(transaction{
		livePath:   path,
		live:       live,
		liveOnDisk: exists,
		candidate:  candidate,
		expected:   policy.RuleProbes(rule),
		apply:      *apply,
		assumeYes:  *yes,
		newRule:    &rule,
	})
}

// --- policy apply ---------------------------------------------------------

func runPolicyApply(args []string) error {
	fs := flag.NewFlagSet("policy apply", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "install the candidate; without this it is only analysed against the live policy")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (for non-interactive use; requires --apply)")
	file := fs.String("file", "", "policy file to install over (default: the live policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: parzival policy apply [--apply] [--file PATH] <candidate.json>")
	}

	candidate, _, exists, err := loadPolicyFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no such candidate file: %s", fs.Arg(0))
	}

	live, path, liveExists, err := loadPolicyFile(*file)
	if err != nil {
		return err
	}
	if !liveExists {
		fmt.Printf("no policy at %s — this creates it\n", path)
		live = &policy.Policy{Schema: policy.SchemaVersion}
	}

	// Every probe is unexpected: `apply` takes a file, not an intent, so there is
	// nothing that says which changes were wanted. Everything the delta finds is
	// therefore reported for the operator to recognise or reject.
	return runTransaction(transaction{
		livePath:   path,
		live:       live,
		liveOnDisk: liveExists,
		candidate:  candidate,
		expected:   nil,
		apply:      *apply,
		assumeYes:  *yes,
	})
}

// --- the shared transaction ----------------------------------------------

type transaction struct {
	livePath   string
	live       *policy.Policy
	liveOnDisk bool
	candidate  *policy.Policy
	// expected are the probes the operator asked to change. Anything else the
	// delta finds is a side effect.
	expected []policy.Probe
	apply    bool
	// assumeYes skips the confirmation prompt. It is separate from apply so that
	// "install this" and "do not ask me" stay two decisions.
	assumeYes bool
	// newRule, when set, is shown in the representative what-if table.
	newRule *policy.Rule
}

func runTransaction(t transaction) error {
	now := time.Now()

	// --- write the candidate to its own file, and validate it from there ---
	//
	// Deliberately a real file re-read through the production parser, not an
	// in-memory check: the artifact that gets validated should be the artifact
	// that gets installed, and marshalling is a step where they could differ.
	candPath, err := policy.WriteCandidate(filepath.Dir(t.livePath), t.candidate)
	if err != nil {
		return err
	}
	reread, _, err := policy.LoadFile(candPath)
	if err != nil {
		os.Remove(candPath)
		return fmt.Errorf("the candidate does not load: %w", err)
	}
	fmt.Printf("\nCandidate: %s\n", candPath)
	fmt.Println("Parses, and every field and value is one this parzival understands.")

	// --- semantic analysis ---
	a := reread.Analyze()
	if errs := a.Errors(); len(errs) > 0 {
		fmt.Println("\nERRORS in the candidate — its text and its effect disagree:")
		for _, f := range errs {
			fmt.Printf("  [%s] %s\n", f.Kind, f.Message)
		}
		fmt.Printf("\nThe live policy at %s is untouched.\n", t.livePath)
		return fmt.Errorf("%d error(s) in the candidate; refusing to apply", len(errs))
	}
	if warns := a.Warnings(); len(warns) > 0 {
		fmt.Println("\nWarnings in the candidate:")
		for _, f := range warns {
			fmt.Printf("  [%s] %s\n", f.Kind, f.Message)
		}
	}

	// --- representative what-if decisions, from the real evaluator ---
	if t.newRule != nil {
		fmt.Println("\nExpected authorization (evaluated against the candidate):")
		for _, pr := range representativeProbes(*t.newRule) {
			allow, idx := reread.Explain(policy.Request{Ref: pr.Ref, Identity: pr.Identity, Mode: pr.Mode, Time: now})
			verdict, by := "DENY ", ""
			if allow {
				verdict = "ALLOW"
			}
			if idx >= 0 {
				by = fmt.Sprintf("  (rule %d)", idx)
			}
			fmt.Printf("  %-24s %-6s %-44s %s%s\n", displayIdentity(pr.Identity), pr.Mode, pr.Ref, verdict, by)
		}
	}

	// --- authorization delta ---
	var before *policy.Policy
	if t.liveOnDisk {
		before = t.live
	}
	probes := policy.ProbeSet([]*policy.Policy{t.live, reread}, t.expected)
	d := policy.DiffAuthorization(before, reread, probes, now)

	fmt.Printf("\nAuthorization delta (%d requests probed at %s):\n", d.Probed, now.Format("2006-01-02 15:04"))
	if d.Empty() {
		fmt.Println("  none — no probed request changes decision")
	}
	for _, c := range d.Changes {
		fmt.Printf("  %s\n", c.Describe())
	}
	if len(d.TimeConditional) > 0 {
		fmt.Printf("\n  Note: %s in the candidate %s limited by weekday, month day or hours.\n",
			ruleWord(d.TimeConditional), isAre(len(d.TimeConditional)))
		fmt.Println("  The delta above is a snapshot at one instant, not a schedule.")
	}

	unexpected := d.Unexpected(t.expected)
	if t.expected == nil {
		// apply has no stated intent, so "unexpected" is not a meaningful
		// category — everything is for the operator to recognise.
		unexpected = nil
	}
	if len(unexpected) > 0 {
		fmt.Println("\nUNEXPECTED authorization changes — these are outside what was requested:")
		for _, c := range unexpected {
			fmt.Printf("  %s\n", c.Describe())
		}
		fmt.Printf("\nThe live policy at %s is untouched.\n", t.livePath)
		fmt.Println("Narrow the grant so it changes only what you intended, or re-run with")
		fmt.Println("--at <index> if the placement is what produced these.")
		return fmt.Errorf("%d unexpected authorization change(s); refusing to apply", len(unexpected))
	}
	if t.expected != nil {
		fmt.Println("\nUnexpected authorization changes: none")
	}

	// --- file diff ---
	liveBytes := []byte("")
	if t.liveOnDisk {
		if liveBytes, err = policy.Marshal(t.live); err != nil {
			return err
		}
	}
	candBytes, err := policy.Marshal(reread)
	if err != nil {
		return err
	}
	diff := unifiedDiff(splitLines(liveBytes), splitLines(candBytes), t.livePath, candPath, 3)
	fmt.Println("\nFile diff:")
	if diff == "" {
		fmt.Println("  (none — the rendered policy is byte-identical)")
	} else {
		fmt.Print(diff)
	}

	// --- the generate/apply boundary ---
	if !t.apply {
		fmt.Printf("\nNothing was installed. The live policy at %s is unchanged.\n", t.livePath)
		fmt.Println("\nTo install this candidate:")
		fmt.Printf("  parzival policy apply --apply %s\n", candPath)
		return nil
	}

	// --- explicit confirmation ---
	//
	// --apply says an install is intended; it does not say the operator has read
	// the delta above. So --apply still prompts, and a caller that genuinely has
	// nobody to ask passes --yes as well.
	//
	// There is deliberately no "is stdin a terminal" heuristic here. Whether a
	// prompt can be answered is not something to infer — /dev/null is a character
	// device and would pass the obvious test — and the failure mode of guessing
	// wrong is either a script that hangs or a policy installed without anyone
	// agreeing to it. Two explicit flags cost one word and are always right.
	if !t.assumeYes {
		ok, err := confirm(os.Stdin, os.Stdout, fmt.Sprintf("\nInstall this policy over %s?", t.livePath))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("Not installed. The live policy at %s is unchanged.\n", t.livePath)
			fmt.Printf("The candidate is still at %s if you want it.\n", candPath)
			fmt.Println("(Pass --yes alongside --apply to install without this prompt.)")
			return errors.New("cancelled")
		}
	}

	// --- back up, install, verify ---
	backup, err := policy.Backup(t.livePath)
	if err != nil {
		return fmt.Errorf("refusing to install without a backup: %w", err)
	}
	if backup != "" {
		fmt.Printf("\nBackup: %s\n", backup)
	}

	if err := policy.WriteAtomic(t.livePath, reread); err != nil {
		return fmt.Errorf("install failed, live policy unchanged: %w", err)
	}

	if err := policy.VerifyInstalled(t.livePath, reread); err != nil {
		// The install reported success and the result is not what was approved.
		// Getting back to a known-good state matters more than preserving
		// evidence, so restore — and say loudly that it happened.
		fmt.Fprintf(os.Stderr, "\nFAILED: the installed policy is not what was approved: %v\n", err)
		if backup == "" {
			fmt.Fprintf(os.Stderr, "There was no previous policy to restore. %s must be repaired by hand.\n", t.livePath)
			return errors.New("installed policy failed verification and there is no backup")
		}
		if rerr := policy.Restore(backup, t.livePath); rerr != nil {
			fmt.Fprintf(os.Stderr, "The backup could not be restored either: %v\n", rerr)
			fmt.Fprintf(os.Stderr, "Restore %s by hand from %s.\n", t.livePath, backup)
			return errors.New("installed policy failed verification and could not be rolled back")
		}
		fmt.Fprintf(os.Stderr, "Rolled back to %s.\n", backup)
		return errors.New("installed policy failed verification; rolled back")
	}

	// The candidate has done its job and is now a second copy of the live policy
	// sitting in the config directory. Leaving it would be one more file that
	// looks authoritative and is not.
	os.Remove(candPath)

	fmt.Printf("\nInstalled %s (%d rules, mode 0600) and verified.\n", t.livePath, len(reread.Rules))
	fmt.Println("Re-run `parzival policy check` and `parzival policy validate` if you want")
	fmt.Println("the full reports against the installed file.")
	return nil
}

// --- interactive gathering ------------------------------------------------

// gatherInteractively fills in a GrantRequest by asking. Values already supplied
// as flags are offered as defaults rather than asked for again.
func gatherInteractively(in io.Reader, out io.Writer, req policy.GrantRequest) (policy.GrantRequest, error) {
	r := bufio.NewReader(in)

	fmt.Fprintln(out, "Describing the grant. Press Enter to accept a shown default.")

	ask := func(prompt, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(out, "%s [%s]: ", prompt, def)
		} else {
			fmt.Fprintf(out, "%s: ", prompt)
		}
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading %s: %w", prompt, err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		return line, nil
	}

	askList := func(prompt string, def []string) ([]string, error) {
		got, err := ask(prompt+" (space-separated)", strings.Join(def, " "))
		if err != nil {
			return nil, err
		}
		return strings.Fields(got), nil
	}

	var err error
	if req.Tool, err = ask("Tool or consumer needing access", req.Tool); err != nil {
		return req, err
	}
	if req.Goal, err = ask("What it needs to accomplish", req.Goal); err != nil {
		return req, err
	}
	if req.Secrets, err = askList("Secret reference(s)", req.Secrets); err != nil {
		return req, err
	}
	if req.Identities, err = askList("Identity label(s)", req.Identities); err != nil {
		return req, err
	}

	modeDefault := req.Modes
	if len(modeDefault) == 0 {
		modeDefault = policy.DefaultModes
	}
	fmt.Fprintln(out, "\nDelivery modes. exec and mount broker the value into a 0600 RAM file the")
	fmt.Fprintln(out, "consumer opens; get hands the raw value to the caller's stdout. Prefer")
	fmt.Fprintln(out, "exec,mount unless the consumer genuinely cannot use a file.")
	if req.Modes, err = askList("Modes", modeDefault); err != nil {
		return req, err
	}

	fmt.Fprintln(out, "\nOptional time limits — leave blank for none.")
	if req.Weekdays, err = askList("Weekdays", req.Weekdays); err != nil {
		return req, err
	}
	mdText, err := ask("Days of the month (comma-separated)", joinInts(req.Monthdays))
	if err != nil {
		return req, err
	}
	if req.Monthdays, err = parseMonthdays(mdText); err != nil {
		return req, err
	}
	if req.Hours, err = ask("Hours window HH:MM-HH:MM", req.Hours); err != nil {
		return req, err
	}
	return req, nil
}

// confirm asks a yes/no question, defaulting to no.
//
// Defaulting to no is the point: an empty line, a stray newline in a pipe, or an
// impatient Enter must never install a credential policy.
func confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprintf(out, "%s [y/N]: ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// --- small helpers --------------------------------------------------------

// representativeProbes builds the what-if table shown before an install: every
// mode for the rule's own refs and identities, plus a label the rule does not
// cover.
//
// The uncovered label is the useful row. It demonstrates that the grant is
// actually scoped — that some other caller does not get the same access — which
// is the claim an operator most wants evidence for and least wants to take on
// trust.
func representativeProbes(r policy.Rule) []policy.Probe {
	probes := policy.RuleProbes(policy.Rule{
		Allow: r.Allow, Secrets: r.Secrets, Identities: r.Identities,
		// Force all three modes, so the table shows get being refused rather
		// than omitting the row that proves it.
	})
	for _, ref := range firstOr(r.Secrets, "*") {
		probes = append(probes, policy.Probe{Ref: ref, Identity: uncoveredLabel, Mode: policy.ModeGet})
	}
	return probes
}

// uncoveredLabel is a synthetic identity used only in the what-if table, to show
// that a caller the rule does not name gets nothing from it.
const uncoveredLabel = "some-other-label"

func displayIdentity(id string) string {
	switch id {
	case "":
		return "(no --as)"
	case uncoveredLabel:
		return id + " *"
	}
	return id
}

func firstOr(vals []string, fallback string) []string {
	if len(vals) == 0 {
		return []string{fallback}
	}
	return vals
}

func splitCommas(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseMonthdays(s string) ([]int, error) {
	var out []int
	for _, p := range splitCommas(s) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("bad month day %q: want a number 1..31", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ",")
}

func ruleWord(idx []int) string {
	switch len(idx) {
	case 0:
		return "no rule"
	case 1:
		return "rule " + strconv.Itoa(idx[0])
	}
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = strconv.Itoa(n)
	}
	return "rules " + strings.Join(parts, ", ")
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
