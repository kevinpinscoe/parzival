// Command parzival is a runtime credential-delivery bridge: it fetches a secret
// from an encrypted store and hands it to a consuming tool through the most
// secure interface that tool supports.
//
//	parzival get   — delivery tier 2: stream a secret to stdout or a file descriptor.
//	parzival probe — no delivery at all: report whether a fetch would succeed.
//	parzival exec  — delivery tier 4: render secret(s) into a RAM-backed file, run a
//	                 command pointed at it, then wipe.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kevinpinscoe/parzival/internal/agent"
	"github.com/kevinpinscoe/parzival/internal/ephemeral"
	"github.com/kevinpinscoe/parzival/internal/mount"
	"github.com/kevinpinscoe/parzival/internal/policy"
	"github.com/kevinpinscoe/parzival/internal/profile"
	"github.com/kevinpinscoe/parzival/internal/secret"
	"github.com/kevinpinscoe/parzival/internal/store"
)

// version and commit are populated at release-build time via
// `-ldflags "-X main.version=... -X main.commit=..."` (see .goreleaser.yml).
// A plain `go build` leaves them at their zero-value defaults,
// which is how `version` distinguishes a local developer build from a
// released one — never guess a version string when these are unset.
var (
	version = "dev"
	commit  = "unknown"
)

// resolveIdentity returns the policy identity label: the --as flag if set, else
// $PARZIVAL_IDENTITY, else empty.
func resolveIdentity(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("PARZIVAL_IDENTITY")
}

// fetch authorizes a single reference against the policy, then retrieves it.
// mode is the delivery mode (policy.ModeGet / ModeExec), which policy rules can
// gate on — an identity may be permitted brokered delivery but refused the raw
// value. See THREAT-MODEL.md §4b.
func fetch(ctx context.Context, ref store.SecretRef, identity, mode string) ([]byte, error) {
	if err := policy.Authorize(policy.Request{Ref: ref.Raw, Identity: identity, Mode: mode, Time: time.Now()}); err != nil {
		return nil, err
	}
	backend, err := store.Resolve(ref)
	if err != nil {
		return nil, err
	}
	return backend.Get(ctx, ref)
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "get":
		err = runGet(args)
	case "probe":
		err = runProbe(args)
	case "exec":
		err = runExec(args)
	case "mount":
		err = runMount(args)
	case "service":
		err = runService(args)
	case "policy":
		err = runPolicy(args)
	case "doctor":
		err = runDoctor(args)
	case "version", "-v", "--version":
		runVersion()
		return
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "parzival: unknown command %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		// A command that ran but exited non-zero propagates its own status.
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "parzival:", err)
		os.Exit(1)
	}
}

// runVersion prints the release version and source commit and returns —
// never an error, since "what version is this" must succeed even against a
// broken policy/config that would fail every other command.
func runVersion() {
	fmt.Printf("parzival %s (commit %s)\n", version, commit)
}

func usage(w *os.File) {
	fmt.Fprint(w, `parzival — runtime credential-delivery bridge

Usage:
  parzival get   [--fd N] [--as ID] [--force] <ref>
  parzival probe [--as ID] <ref>
  parzival exec  [--as ID] <profile> -- <command> [args...]
  parzival mount [--as ID] <mountpoint>
  parzival service [--socket PATH] [--input name=value ...] <consumer>.<operation>
  parzival policy check    [--file PATH]
  parzival policy validate [--file PATH]
  parzival policy what-if  [--file PATH] --as ID --mode MODE --ref REF [--at TIME]
  parzival doctor [--allow-ambient-openbao]
  parzival version

Secret reference forms:
  bao:<mount>/<path>#<field>    OpenBao KV v2   (e.g. bao:app/gitea#token)
  op://<vault>/<item>/<field>   1Password       (e.g. op://Private/Gitea/token)
  gopass:<path>                 gopass          (not yet implemented)

Flags (must precede the reference/profile):
  --fd N   write the secret to inherited file descriptor N instead of stdout
  --as ID  identity label for the approval policy (or set $PARZIVAL_IDENTITY)
  --force  permit get to write the raw secret to a regular file (it refuses by
           default: a redirect leaves the value on disk permanently)

get refuses outright in an AI agent's tool shell:
  When an agent harness is detected from the environment (Claude Code, Cursor,
  Codex, or anything exporting $PARZIVAL_AGENT), get is refused before the fetch
  — an agent's captured output is a permanent transcript. There is no override
  flag and no override variable, by design. Use probe to check a ref, exec or
  mount to use a credential, or run the command yourself in a terminal that is
  not driving parzival.

probe:
  Answers "would this fetch succeed?" without ever returning the value. It runs
  the real policy check and a real fetch, then reports one of four verdicts and
  discards what it retrieved:

    OK      the fetch succeeded and returned a value  (exit 0)
    EMPTY   the fetch succeeded and returned nothing  (exit 3)
    DENIED  the policy refused it                     (exit 4)
    ERROR   the store refused or failed the fetch     (exit 5)

  Use it to confirm a store-side ACL grant landed. It takes no --mode: it tries
  get, exec and mount in that order and names the first the policy permits, so
  it needs no rule of its own and grants nothing a rule did not already grant.
  Unlike "policy what-if" it does fetch, so the decision is audited.

exec:
  Renders a profile's secret(s) into a RAM-backed file, runs the command with the
  file's path available as $PARZIVAL_CRED_FILE, as the profile's inject.env var,
  and substituted for any {{cred}} token in the command, then wipes the file.
  The RAM dir itself is exposed as $PARZIVAL_CRED_DIR, as the profile's
  inject.env_dir var, and for any {{creddir}} token — for tools that read a fixed
  filename inside a config dir (inject.filename may nest, e.g. "tea/config.yml").
  Profiles live in `+profile.Dir()+`/<profile>.json

mount:
  Serves one read-only virtual file per profile at <mountpoint>; each open()
  runs the policy, fetches fresh, renders, and serves from memory (nothing on
  disk). Blocks until Ctrl-C. Linux only (macOS: use exec).

service:
  Calls one named operation through a running parzival-broker over its
  AF_UNIX socket (default `+defaultServiceSocket+`, or --socket, or
  $PARZIVAL_BROKER_SOCKET) and prints the canonical result to stdout. Unlike
  get/exec/mount/probe above, this command authorizes nothing itself and
  never touches the store — the broker on the other end of the socket
  enforces the boundary; this is just a client of it. --input is repeatable:

    parzival service --input owner=acme tea.repos-list

  Exit codes: 0 OK, 3 DENIED, 4 INVALID, 5 ERROR, 6 UNAVAILABLE (the broker's
  closed status vocabulary), 1 for anything else (the broker was not
  reachable at all, or its response could not be understood).

Approval policy (strict deny-by-default):
  Every fetch is checked against `+policy.ConfigDir()+`/policy.json — with no policy
  file, all fetches are DENIED. Rules match on the secret ref, the --as identity,
  the delivery mode, and time. Decisions are logged. See examples/policy.json.

  A rule's "modes" list (get / exec / mount) is an allowlist; omit it to match any
  mode. Listing ["exec","mount"] grants brokered delivery while refusing the raw
  value — the recommended posture for AI agents and other non-human callers, which
  can then USE a credential without it ever entering a log or transcript.

  Restrict the REF, not the IDENTITY. Identity labels are self-asserted, so a
  mode restriction only holds when EVERY allow-rule matching that ref excludes
  get; otherwise the caller asserts a different --as label and reads the value.

policy check:
  Reports which refs can be read as a raw value, and which mode restrictions a
  different --as label would bypass. Exits non-zero if any is bypassable, so it
  can gate a rollout or run as a post-install check.

  A policy naming a field this binary does not know is REFUSED, not partially
  applied — an out-of-date binary fails loudly instead of silently enforcing a
  weaker rule than written. Rebuild after upgrading before trusting a new field.

policy validate:
  Parses a policy, then reports what only simulation can find: rules that can
  never fire because an earlier rule already matches everything they match,
  rules that shadow part of a later one, and redundant rules. Errors (the
  policy's text and its effect disagree) are separated from warnings. Exits
  non-zero on any error.

  Run it against a candidate before installing it. "policy check" answers only
  the mode-bypass question, deliberately, because its exit status gates rollouts.

policy what-if:
  Evaluates one request and names the rule that decides it. Because the first
  matching rule wins, a refused request usually has an allow-rule — sitting
  below a rule that matched first — and the rule number is the answer. --at
  evaluates at a chosen time, for rules limited by weekday, month day or hours.

  Nothing is fetched and nothing is written to the audit log. Exits non-zero
  when the request would be denied, so it can be used as a scripted assertion.

doctor:
  Checks deployment posture: no ambient BAO_TOKEN, no readable ~/.vault-token,
  strict policy loading, writable audit log, and backend capability reporting.
  Ambient OpenBao CLI auth is compatibility mode and fails doctor unless
  --allow-ambient-openbao is passed.
`)
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fd := fs.Int("fd", 1, "write the secret to this inherited file descriptor (1 = stdout)")
	as := fs.String("as", "", "identity label for the approval policy (or $PARZIVAL_IDENTITY)")
	force := fs.Bool("force", false, "permit writing the raw secret to a regular file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("get requires exactly one secret reference (got %d)", fs.NArg())
	}

	ref, err := store.ParseRef(fs.Arg(0))
	if err != nil {
		return err
	}

	// Both checks run before the fetch, so a refused destination never causes
	// one. The agent check is first because it is the broader refusal: it does
	// not care which descriptor the value was going to, only who was going to
	// receive it.
	if err := refuseAgentShell(); err != nil {
		return err
	}
	if *fd == 1 && !*force {
		if err := refuseRegularFile(os.Stdout); err != nil {
			return err
		}
	}

	buf, err := fetch(context.Background(), ref, resolveIdentity(*as), policy.ModeGet)
	if err != nil {
		return err
	}
	defer secret.Zero(buf)

	out := os.Stdout
	if *fd != 1 {
		out = secret.FileForFD(*fd)
	}
	return secret.WriteTo(out, buf)
}

// refuseAgentShell rejects `get` when the process is running under a recognised
// AI agent harness.
//
// It is the same shape as refuseRegularFile below — a destination that records,
// refused before the fetch — applied to the destination that records most
// durably. Whatever an agent's tool shell captures becomes part of a transcript
// held by the agent, by the model provider, and by whatever session log the
// launcher keeps, and none of those copies can be redacted afterwards.
//
// # There is deliberately no override
//
// No flag, no environment variable, no --force. This is deliberate, and it
// is the point of the control rather than an oversight: a bypass an AI can type
// is a bypass an AI will type, and the refusal only has value while it cannot
// be argued past by the process it is refusing. When a raw value is genuinely
// needed, a human runs the command in a terminal parzival is not being driven
// from, which is exactly the caller every `get`-mode rule in the policy already
// documents itself as being for.
//
// It refuses regardless of --fd. A specific descriptor is still a stream the
// agent chose and still lands in the agent's own process; --force is likewise
// no answer, because it addresses the file-on-disk hazard rather than this one.
//
// See internal/agent for what this keys on and why it is not a boundary.
func refuseAgentShell() error {
	m, ok := agent.Detect()
	if !ok {
		return nil
	}
	return fmt.Errorf("refusing to hand a raw secret to an AI agent's tool shell: "+
		"$%s identifies this process as running under %s, whose captured output becomes a "+
		"durable transcript that cannot be redacted afterwards\n"+
		"use `parzival probe <ref>` to confirm the fetch would succeed without disclosing the value, "+
		"or `parzival exec` / `parzival mount` to use the credential without seeing it\n"+
		"there is no override: if the raw value is genuinely needed, run this command yourself in a "+
		"terminal that is not driving parzival", m.Env, m.Agent)
}

// refuseRegularFile rejects a redirected stdout. `parzival get REF > cred.txt`
// writes the raw value to disk permanently, which is almost always a mistake and
// is the exact outcome the project exists to prevent. A pipe or a terminal is
// genuinely ambiguous and so is allowed; --fd is exempt because choosing a
// descriptor is already deliberate.
func refuseRegularFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return nil // cannot tell what stdout is; do not block on a stat failure
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	return errors.New("refusing to write a secret to a regular file: stdout is redirected to a file, " +
		"which leaves the raw value on disk\n" +
		"use `parzival exec` or `parzival mount` to broker it without a plaintext copy, " +
		"`--fd N` to hand it to a specific descriptor, or `--force` if you meant it")
}

func runMount(args []string) error {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	as := fs.String("as", "", "identity label for the approval policy (or $PARZIVAL_IDENTITY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("mount requires exactly one mountpoint")
	}
	return mount.Serve(fs.Arg(0), resolveIdentity(*as))
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	allowAmbient := fs.Bool("allow-ambient-openbao", false, "allow OpenBao ambient CLI auth compatibility mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("doctor takes no positional arguments (got %q)", fs.Arg(0))
	}

	var failures int
	check := func(name string, ok bool, detail string) {
		status := "OK"
		if !ok {
			status = "FAIL"
			failures++
		}
		if detail == "" {
			fmt.Printf("[%s] %s\n", status, name)
			return
		}
		fmt.Printf("[%s] %s: %s\n", status, name, detail)
	}
	note := func(name, detail string) {
		if detail == "" {
			fmt.Printf("[INFO] %s\n", name)
			return
		}
		fmt.Printf("[INFO] %s: %s\n", name, detail)
	}

	note("version", fmt.Sprintf("%s (commit %s)", version, commit))

	// Reported, never failed. Running under an agent harness is a normal and
	// expected way to invoke parzival — it is `get` specifically that is refused
	// there, and exec/mount/probe are the reason an agent has a broker at all.
	// Saying which marker matched is what makes the refusal diagnosable when it
	// fires somewhere unexpected.
	if m, ok := agent.Detect(); ok {
		note("AI agent shell detected", fmt.Sprintf("$%s — %s; `get` is refused here, use probe/exec/mount", m.Env, m.Agent))
	} else {
		note("AI agent shell detected", "no — `get` is permitted in this shell")
	}

	if os.Getenv("BAO_TOKEN") == "" {
		check("BAO_TOKEN not exported", true, "not set")
	} else {
		check("BAO_TOKEN not exported", false, "ambient store tokens let callers bypass parzival policy")
	}

	vaultToken := filepath.Join(userHomeDir(), ".vault-token")
	if st, err := os.Stat(vaultToken); errors.Is(err, os.ErrNotExist) {
		check("default OpenBao token file absent", true, vaultToken)
	} else if err != nil {
		check("default OpenBao token file absent", false, fmt.Sprintf("cannot inspect %s: %v", vaultToken, err))
	} else if st.Mode().IsRegular() {
		if f, err := os.Open(vaultToken); err == nil {
			f.Close()
			check("default OpenBao token file absent", false, vaultToken+" is readable by this caller")
		} else {
			check("default OpenBao token file absent", true, vaultToken+" exists but is not readable by this caller")
		}
	} else {
		check("default OpenBao token file absent", false, vaultToken+" exists and is not a regular file; verify bao cannot use it")
	}

	p, exists, err := policy.Load()
	switch {
	case err != nil:
		check("policy loads strictly", false, err.Error())
	case !exists:
		check("policy loads strictly", false, filepath.Join(policy.ConfigDir(), "policy.json")+" is missing")
	default:
		check("policy loads strictly", true, fmt.Sprintf("%d rule(s)", len(p.Rules)))
	}

	if err := checkAuditWritable(); err != nil {
		check("audit log writable", false, err.Error())
	} else {
		check("audit log writable", true, auditPath())
	}

	openbao, err := store.NewOpenBaoFromEnv()
	if err != nil {
		check("openbao backend configured", false, err.Error())
	} else {
		caps := openbao.Capabilities()
		note("openbao capabilities", capabilitySummary(caps))
		if caps.NonAmbientBrokerAuth {
			check("openbao non-ambient broker auth", true, "AppRole mode")
		} else {
			check("openbao non-ambient broker auth", *allowAmbient, "ambient CLI auth is compatibility mode; callers with the same token can invoke bao directly")
		}
	}

	note("onepassword capabilities", capabilitySummary(store.NewOnePassword().Capabilities()))
	note("gopass capabilities", capabilitySummary(store.NewGopass().Capabilities()))

	if failures > 0 {
		return fmt.Errorf("doctor found %d failed check(s)", failures)
	}
	return nil
}

func capabilitySummary(c store.Capabilities) string {
	var parts []string
	add := func(ok bool, name string) {
		if ok {
			parts = append(parts, name)
		}
	}
	add(c.EncryptedAtRest, "encrypted-at-rest")
	add(c.NonAmbientBrokerAuth, "non-ambient-broker-auth")
	add(c.ScopedStoreAuthorization, "scoped-store-authorization")
	add(c.ShortLivedCredential, "short-lived-credential")
	add(c.BackendAudit, "backend-audit")
	add(c.InteractiveUnlock, "interactive-unlock")
	add(c.UnattendedBootstrap, "unattended-bootstrap")
	if len(parts) == 0 {
		return "(none)"
	}
	if c.StrongUnattended() {
		parts = append(parts, "strong-unattended")
	}
	return strings.Join(parts, ", ")
}

func checkAuditWritable() error {
	if err := os.MkdirAll(filepath.Dir(auditPath()), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func auditPath() string {
	return filepath.Join(stateDir(), "audit.log")
}

func stateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "parzival")
	}
	return filepath.Join(userHomeDir(), ".local", "state", "parzival")
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// exitError carries a child command's non-zero exit status up to main so it can
// be propagated as parzival's own status without an error message.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func runExec(args []string) error {
	pre, cmdArgs, err := splitAtDashDash(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	as := fs.String("as", "", "identity label for the approval policy (or $PARZIVAL_IDENTITY)")
	if err := fs.Parse(pre); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("exec requires exactly one profile name before -- (got %d)", fs.NArg())
	}
	profileName := fs.Arg(0)
	identity := resolveIdentity(*as)

	prof, err := profile.Load(profileName)
	if err != nil {
		return err
	}

	// Authorize and fetch every secret the profile needs.
	ctx := context.Background()
	secrets := make(map[string][]byte, len(prof.Secrets))
	defer func() {
		for _, v := range secrets {
			secret.Zero(v)
		}
	}()
	for name, ref := range prof.Secrets {
		parsed, err := store.ParseRef(ref)
		if err != nil {
			return fmt.Errorf("profile %q secret %q: %w", profileName, name, err)
		}
		val, err := fetch(ctx, parsed, identity, policy.ModeExec)
		if err != nil {
			return err
		}
		secrets[name] = val
	}

	rendered, err := prof.Render(secrets)
	if err != nil {
		return err
	}
	defer secret.Zero(rendered)

	// Create the RAM-backed dir and wipe it on every exit path, including signals.
	dir, err := ephemeral.New()
	if err != nil {
		return err
	}
	defer dir.Cleanup()
	stop := cleanupOnSignal(dir)
	defer stop()

	credPath, err := dir.WriteFile(prof.Inject.FileName(), rendered)
	if err != nil {
		return err
	}

	// Build the child: substitute {{cred}}/{{creddir}} in argv, set the
	// injection env vars.
	childArgs := substituteCred(cmdArgs, credPath, dir.Path())
	child := exec.Command(childArgs[0], childArgs[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(),
		"PARZIVAL_CRED_FILE="+credPath,
		"PARZIVAL_CRED_DIR="+dir.Path(),
	)
	if prof.Inject.Env != "" {
		child.Env = append(child.Env, prof.Inject.Env+"="+credPath)
	}
	if prof.Inject.EnvDir != "" {
		child.Env = append(child.Env, prof.Inject.EnvDir+"="+dir.Path())
	}

	runErr := child.Run()
	dir.Cleanup() // wipe promptly, before returning
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return &exitError{code: ee.ExitCode()}
		}
		return fmt.Errorf("exec %q: %w", childArgs[0], runErr)
	}
	return nil
}

// splitAtDashDash splits exec's args into the pre-"--" part (flags + profile) and
// the post-"--" command. It requires "--" to be present with a command after it.
func splitAtDashDash(args []string) (pre, post []string, err error) {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, nil, errors.New("exec requires: parzival exec [--as ID] <profile> -- <command> [args...]")
	}
	pre, post = args[:sep], args[sep+1:]
	if len(post) == 0 {
		return nil, nil, errors.New("exec requires a command after --")
	}
	return pre, post, nil
}

// substituteCred replaces the literal {{cred}} token in each arg with credPath
// and {{creddir}} with credDir. Neither token is a prefix of the other, so the
// replacement order does not matter.
func substituteCred(args []string, credPath, credDir string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		a = strings.ReplaceAll(a, "{{cred}}", credPath)
		out[i] = strings.ReplaceAll(a, "{{creddir}}", credDir)
	}
	return out
}

// cleanupOnSignal wipes dir if the process receives SIGINT/SIGTERM. It returns a
// stop function that unregisters the handler once the child has finished.
func cleanupOnSignal(dir *ephemeral.Dir) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case s := <-ch:
			dir.Cleanup()
			if sig, ok := s.(syscall.Signal); ok {
				os.Exit(128 + int(sig))
			}
			os.Exit(1)
		case <-done:
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}
