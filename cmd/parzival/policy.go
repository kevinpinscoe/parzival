package main

// The `parzival policy` subcommands.
//
// These are presentation only. Every decision shown here comes from
// internal/policy — the same parser, the same evaluator, the same analysis that
// runs before a real fetch. Nothing in this file re-implements a policy rule,
// and nothing here should: a second opinion about what a policy means is how an
// editor ends up showing the operator one thing and installing another.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kevinpinscoe/parzival/internal/policy"
)

// policyUsage is printed when `policy` is given no subcommand or a bad one.
const policyUsage = `usage: parzival policy <command>

  check     [--file PATH]   report which refs can be read raw, and which mode
                            restrictions a different --as label would bypass
  validate  [--file PATH]   parse and validate a policy, then report ordering
                            problems: unreachable rules, shadowing, redundancy
  what-if   [--file PATH] --as ID --mode MODE --ref REF [--at TIME]
                            evaluate one request and name the rule that decides it
  grant     [--interactive] [--apply] --secret REF --identity ID [...]
                            build, place, analyse and optionally install one
                            allow-rule; brokered modes unless get is named
  apply     [--apply] <candidate.json>
                            analyse a candidate against the live policy and
                            optionally install it

With no --file, each command reads the live policy. Neither grant nor apply
changes anything without --apply.`

// runPolicy dispatches the `policy` subcommands.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New(policyUsage)
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	case "validate":
		return runPolicyValidate(args[1:])
	case "what-if", "whatif":
		return runPolicyWhatIf(args[1:])
	case "grant":
		return runPolicyGrant(args[1:])
	case "apply":
		return runPolicyApply(args[1:])
	default:
		return fmt.Errorf("unknown policy command %q\n\n%s", args[0], policyUsage)
	}
}

// loadPolicyFile reads the policy a command should operate on: the file named by
// --file, or the live policy when the flag is absent.
//
// Both go through policy.LoadFile, so a candidate is held to exactly the
// standard the live policy is held to. A command that validated a candidate
// leniently would approve something the binary then refuses to enforce.
func loadPolicyFile(file string) (p *policy.Policy, path string, exists bool, err error) {
	path = file
	if path == "" {
		path = policy.Path()
	}
	p, exists, err = policy.LoadFile(path)
	return p, path, exists, err
}

// --- policy check ---------------------------------------------------------

// runPolicyCheck reports where a policy's mode restrictions can be bypassed by
// asserting a different --as label, and exits non-zero if any can — so it can
// gate a rollout or run as a post-install verification.
//
// Its contract is deliberately unchanged from before the editing commands
// existed: it answers one question, and its exit status is wired into runbook
// steps as a deployment gate. The ordering findings added alongside it live in
// `policy validate`, so extending the analysis does not silently redefine what
// an existing gate fails on.
func runPolicyCheck(args []string) error {
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	file := fs.String("file", "", "policy file to check (default: the live policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy check takes no positional arguments (got %q)", fs.Arg(0))
	}

	p, path, exists, err := loadPolicyFile(*file)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Printf("no policy at %s — every fetch is denied (strict deny-by-default)\n", path)
		return nil
	}

	rep := p.Check()
	fmt.Printf("policy: %s (%d rules)\n", path, len(p.Rules))

	fmt.Println("\nRules permitting `get` — the raw value goes to a stream the caller controls:")
	if len(rep.GetOpen) == 0 {
		fmt.Println("  (none — no ref in this policy can be read as a raw value)")
	}
	for _, g := range rep.GetOpen {
		cond := ""
		if g.Conditional {
			cond = " [time-limited]"
		}
		fmt.Printf("  rule %d  secrets=%s  identities=%s%s\n",
			g.Rule, patterns(g.Secrets), patterns(g.Identities), cond)
	}

	if rep.OK() {
		fmt.Println("\nNo mode restriction is bypassable. OK.")
		fmt.Println("\nThis command checks mode bypasses only. For unreachable rules, shadowing")
		fmt.Println("and redundancy, run `parzival policy validate`.")
		return nil
	}

	fmt.Println("\nBYPASSABLE mode restrictions — identity labels are self-asserted, so these")
	fmt.Println("restrictions do not hold. Restrict the ref, not the identity:")
	for _, w := range rep.Weakened {
		fmt.Printf("  rule %d restricts identities=%s to brokered delivery on %s,\n",
			w.RestrictedRule, patterns(w.RestrictedIDs), patterns(w.Secrets))
		fmt.Printf("    but rule %d permits `get` on an overlapping ref for identities=%s.\n",
			w.OpenRule, patterns(w.OpenIDs))
		fmt.Printf("    A caller passes --as %s and reads the raw value.\n", exampleLabel(w.OpenIDs))
	}
	fmt.Println("\nFix: add \"modes\" (without \"get\") to EVERY allow-rule matching those refs.")
	return fmt.Errorf("%d bypassable mode restriction(s)", len(rep.Weakened))
}

// --- policy validate ------------------------------------------------------

// runPolicyValidate parses a policy and reports everything wrong with it: the
// syntax and value errors the parser raises, and the ordering problems only
// simulation can find.
//
// It is the command to run against a candidate before installing it. Loading is
// where JSON syntax, unknown fields, the schema version, trailing data, modes,
// weekdays, month days and hours are all decided — none of that is re-checked
// here, because a second implementation of those rules is a second thing to
// drift out of step with the one that actually gates fetches.
func runPolicyValidate(args []string) error {
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	file := fs.String("file", "", "policy file to validate (default: the live policy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// `parzival policy validate candidate.json` is the obvious thing to type, so
	// accept it as well as --file rather than refusing on a technicality.
	switch {
	case fs.NArg() == 1 && *file == "":
		*file = fs.Arg(0)
	case fs.NArg() > 1:
		return fmt.Errorf("policy validate takes at most one file (got %d)", fs.NArg())
	case fs.NArg() == 1:
		return errors.New("give the file either as --file or as a positional argument, not both")
	}

	p, path, exists, err := loadPolicyFile(*file)
	if err != nil {
		// The parse error is the finding. It already names the file and, for an
		// unknown field, explains that the binary is probably older than the
		// policy.
		fmt.Printf("policy: %s\n\nINVALID\n\n  %v\n", path, err)
		return errors.New("policy does not load")
	}
	if !exists {
		if *file != "" {
			return fmt.Errorf("no such policy file: %s", path)
		}
		fmt.Printf("no policy at %s — every fetch is denied (strict deny-by-default)\n", path)
		return nil
	}

	fmt.Printf("policy: %s (%d rules)\n", path, len(p.Rules))
	fmt.Println("\nParses, and every field and value is one this parzival understands.")

	a := p.Analyze()
	errs, warns := a.Errors(), a.Warnings()

	if len(errs) > 0 {
		fmt.Println("\nERRORS — the policy's text and its effect disagree. Fix these before")
		fmt.Println("relying on any rule involved:")
		for _, f := range errs {
			fmt.Printf("  [%s] %s\n", f.Kind, f.Message)
		}
	}
	if len(warns) > 0 {
		fmt.Println("\nWarnings — the policy means what it says, but these are worth seeing:")
		for _, f := range warns {
			fmt.Printf("  [%s] %s\n", f.Kind, f.Message)
		}
	}

	if len(errs) == 0 && len(warns) == 0 {
		fmt.Println("No ordering problems, no rules permitting raw `get`. OK.")
		return nil
	}
	if len(errs) == 0 {
		fmt.Printf("\n%d warning(s), no errors. OK.\n", len(warns))
		return nil
	}
	return fmt.Errorf("%d error(s) in %s", len(errs), path)
}

// --- policy what-if -------------------------------------------------------

// runPolicyWhatIf evaluates one request against a policy and reports the
// decision together with the rule that produced it.
//
// The point is the rule number. Valid JSON does not imply effective
// authorization, and when a request is refused the useful answer is not "denied"
// but "denied by rule 12, which matches before the rule you were expecting".
//
// Nothing is fetched and nothing is written to the audit log. This asks what
// *would* happen, and recording simulated requests beside real ones would make
// the audit log unable to answer what was actually retrieved.
func runPolicyWhatIf(args []string) error {
	fs := flag.NewFlagSet("policy what-if", flag.ContinueOnError)
	file := fs.String("file", "", "policy file to evaluate against (default: the live policy)")
	as := fs.String("as", "", "identity label to evaluate as (empty means a caller passing no --as)")
	mode := fs.String("mode", "", "delivery mode: get, exec or mount")
	ref := fs.String("ref", "", "the secret reference being requested")
	at := fs.String("at", "", "evaluation time as YYYY-MM-DDTHH:MM (default: now) — for rules limited by weekday, month day or hours")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy what-if takes no positional arguments (got %q)", fs.Arg(0))
	}
	if *ref == "" {
		return errors.New("policy what-if requires --ref")
	}
	if *mode == "" {
		return errors.New("policy what-if requires --mode (get, exec or mount)")
	}
	switch *mode {
	case policy.ModeGet, policy.ModeExec, policy.ModeMount:
	default:
		return fmt.Errorf("unknown mode %q (want %s, %s or %s)", *mode, policy.ModeGet, policy.ModeExec, policy.ModeMount)
	}

	when := time.Now()
	if *at != "" {
		parsed, err := time.ParseInLocation("2006-01-02T15:04", *at, time.Local)
		if err != nil {
			return fmt.Errorf("bad --at %q: want YYYY-MM-DDTHH:MM", *at)
		}
		when = parsed
	}

	p, path, exists, err := loadPolicyFile(*file)
	if err != nil {
		return err
	}

	req := policy.Request{Ref: *ref, Identity: *as, Mode: *mode, Time: when}
	fmt.Printf("policy: %s", path)
	if exists {
		fmt.Printf(" (%d rules)", len(p.Rules))
	}
	fmt.Println()

	if !exists {
		fmt.Println("\nDENY\n\nThere is no policy file, so every fetch is denied (strict deny-by-default).")
		return &exitError{code: 1}
	}

	allow, idx := p.Explain(req)
	writeWhatIf(os.Stdout, p, req, allow, idx, when)
	if !allow {
		// Non-zero so what-if can be used as a scripted assertion, the same way
		// `policy check` gates a rollout.
		return &exitError{code: 1}
	}
	return nil
}

// writeWhatIf renders one what-if result. It is separated from the command so
// tests can assert on the text without capturing os.Stdout.
func writeWhatIf(w io.Writer, p *policy.Policy, req policy.Request, allow bool, idx int, when time.Time) {
	verdict := "DENY"
	if allow {
		verdict = "ALLOW"
	}
	fmt.Fprintf(w, "\n%s\n\n", verdict)

	if idx >= 0 {
		fmt.Fprintf(w, "Matched rule: %d\n", idx)
	} else {
		fmt.Fprintf(w, "Matched rule: none — no rule matches, so the default deny applies\n")
	}
	identity := req.Identity
	if identity == "" {
		identity = "(none — caller passed no --as)"
	}
	fmt.Fprintf(w, "Identity:     %s\n", identity)
	fmt.Fprintf(w, "Mode:         %s\n", req.Mode)
	fmt.Fprintf(w, "Secret:       %s\n", req.Ref)
	fmt.Fprintf(w, "Evaluated at: %s\n", when.Format("2006-01-02 15:04 (Mon)"))

	if idx >= 0 {
		fmt.Fprintf(w, "\nRule %d:\n%s", idx, indentRule(p.Rules[idx], "  "))
	}

	// The first-match explanation. A refused request is usually not missing a
	// rule — it has one, sitting below a rule that matched first — and naming
	// that earlier rule is the difference between a useful answer and "denied".
	if !allow && idx >= 0 {
		fmt.Fprintf(w, "\nRule %d matches this request before any rule below it. If you expected a\n", idx)
		fmt.Fprintf(w, "later rule to allow this, that rule is unreachable for this request:\n")
		fmt.Fprintf(w, "narrow rule %d, or place the allowing rule above it.\n", idx)
	}
	if !allow && idx < 0 {
		fmt.Fprintf(w, "\nNo rule in this policy matches. Nothing is denying this request specifically —\n")
		fmt.Fprintf(w, "there is simply no allow-rule covering it, and the policy denies by default.\n")

		// The operator almost always had a rule in mind. Naming the ones that
		// cover this ref but failed on some other condition answers the question
		// they actually asked, which is "why didn't my rule fire?"
		if near := p.NearMisses(req); len(near) > 0 {
			fmt.Fprintf(w, "\nRules covering this ref that did not match:\n")
			for _, m := range near {
				fmt.Fprintf(w, "  rule %d — %s\n", m.Rule, p.Rules[m.Rule].Description)
				for _, why := range m.Explain(p.Rules[m.Rule], req) {
					fmt.Fprintf(w, "      %s\n", why)
				}
			}
		}
	}
	if allow && len(p.Rules) > idx+1 {
		fmt.Fprintf(w, "\nRules below %d were not consulted: the first match decides.\n", idx)
	}
}

// indentRule renders a rule the way it would read in policy.json, showing only
// the conditions it actually places. An omitted condition matches everything, so
// printing an empty list beside a real one would misrepresent both.
func indentRule(r policy.Rule, pad string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%sallow: %t\n", pad, r.Allow)
	if r.Description != "" {
		fmt.Fprintf(&b, "%sdescription: %s\n", pad, r.Description)
	}
	line := func(name string, vals []string) {
		if len(vals) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s%s: %s\n", pad, name, patterns(vals))
	}
	line("secrets", r.Secrets)
	line("identities", r.Identities)
	line("modes", r.Modes)
	line("weekdays", r.Weekdays)
	if len(r.Monthdays) > 0 {
		parts := make([]string, len(r.Monthdays))
		for i, d := range r.Monthdays {
			parts[i] = fmt.Sprint(d)
		}
		fmt.Fprintf(&b, "%smonthdays: [%s]\n", pad, strings.Join(parts, " "))
	}
	if r.Hours != "" {
		fmt.Fprintf(&b, "%shours: %s\n", pad, r.Hours)
	}

	// Say what is unconstrained, rather than leaving the reader to infer it from
	// a missing line. "No modes listed" is the single commonest way a rule turns
	// out to permit raw `get` — but only on an allow-rule. On a deny-rule the
	// same omission means it refuses every mode, which is the safe direction and
	// must not be flagged as though it granted something.
	var anyOf []string
	if len(r.Secrets) == 0 {
		anyOf = append(anyOf, "any ref")
	}
	if len(r.Identities) == 0 {
		anyOf = append(anyOf, "any identity")
	}
	if len(r.Modes) == 0 {
		if r.Allow {
			anyOf = append(anyOf, "any mode, including get")
		} else {
			anyOf = append(anyOf, "any mode")
		}
	}
	if len(anyOf) > 0 {
		fmt.Fprintf(&b, "%s(unrestricted: %s)\n", pad, strings.Join(anyOf, ", "))
	}
	return b.String()
}

// patterns renders a glob list for the report; an empty list means the rule
// placed no condition and so matches everything.
func patterns(ps []string) string {
	if len(ps) == 0 {
		return "<any>"
	}
	return "[" + strings.Join(ps, " ") + "]"
}

// exampleLabel picks a concrete label to show in the bypass example. A glob is
// shown as-is: it is the pattern the caller has to satisfy, not a literal.
func exampleLabel(ids []string) string {
	if len(ids) == 0 {
		return "<anything>"
	}
	return ids[0]
}
