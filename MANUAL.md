# Parzival Manual

> A practical guide for using secrets without leaving them behind.
>
> "What is the secret of the Grail? Who does it serve?"
>
> "You, my lord."
>
> "Who am I?"

In John Boorman's *Excalibur* (1981), Perceval then recognizes the wounded figure
as Arthur, his lord and king. Asked whether he has found the secret that was lost,
Perceval answers that Arthur and the land are one.

Parzival is a command-line secret broker. It fetches a credential from an encrypted
store only when a command needs it, gives that command the credential through the
safest interface the command supports, and then wipes the temporary copy.

This manual is written around user tasks, not around the source tree. For the full
design record, see [README.md](README.md) and [THREAT-MODEL.md](THREAT-MODEL.md); for
installing and deploying Parzival, see [INSTALL.md](INSTALL.md).

## Start Here

| If you need to... | Use this | Why |
| --- | --- | --- |
| Check whether the host is ready | `parzival doctor` | Finds bypasses and missing config before a real workflow depends on it |
| Check which build is installed | `parzival version` | Prints the release version and source commit (`dev`/`unknown` on a local `go build`) |
| Hand a secret to a command through a pipe or fd | `parzival get` | No plaintext file is created |
| Check whether a ref is readable, without reading it | `parzival probe` | Answers OK / EMPTY / DENIED / ERROR and never returns the value |
| Run a tool that insists on a credential file | `parzival exec` | Renders that file in RAM, runs the tool, then wipes it |
| Expose fixed-path credential files on Linux | `parzival mount` | Re-fetches on every `open()` and serves from memory |
| Verify a policy cannot be dodged by changing identity labels | `parzival policy check` | Catches rules that look restricted but still allow raw reads |
| Check a policy for rules that can never fire | `parzival policy validate` | Rule order decides everything, and a dead rule looks fine in JSON |
| Find out why a request was allowed or refused | `parzival policy what-if` | Names the rule that decided, and why a rule you expected did not |
| Add a rule without breaking the ones already there | `parzival policy grant` | Places it, shows what changes, backs up, installs atomically |
| Install a policy file you have reviewed | `parzival policy apply` | Same transaction, starting from a file instead of an intent |
| Do an emergency OpenBao operation outside policy | A human runs a separate break-glass tool, outside Parzival | Human-only override, never automation — see "Break Glass Without Making It a Back Door" below |

The safest everyday shape is:

```bash
parzival exec --as ai <profile> -- <tool> [args...]
```

That lets a caller use a secret without receiving the raw value in stdout, logs,
shell history, transcripts, or copied files.

## The Idea in One Minute

Most command-line tools need secrets in one of three ways:

1. A stream, such as stdin.
2. A file path, such as `~/.aws/credentials` or `KUBECONFIG`.
3. An environment variable.

Parzival prefers streams, then RAM-backed files, and treats environment variables as
the weakest option because child processes can inherit and expose them. The exact
delivery method is chosen by the command you need to run.

Parzival does not make plaintext impossible. No secret broker can. It makes plaintext
short-lived, deliberate, policy-checked, auditable, and limited to the one consumer
that actually needs it.

## Install the Supporting Software

See [INSTALL.md](INSTALL.md) for full installation instructions — packages, building from
source, and per-backend configuration. In short: install `bao` for an OpenBao backend, `op`
for 1Password, and, on Linux, `fuse3` if you want `parzival mount`. macOS uses `exec` only;
`mount` is not implemented there. `gopass` and KeePassXC backends are named in the design
but not implemented yet.

## Configure the First Policy

Parzival denies every fetch unless a policy allows it. Create:

```text
~/.config/parzival/policy.json
```

Start with a narrow rule that grants brokered delivery, not raw reads:

```json
{
  "schema": 1,
  "rules": [
    {
      "allow": true,
      "description": "Let automation use the Gitea token through exec or mount only.",
      "secrets": ["bao:app/gitea#*"],
      "identities": ["ai", "agent-*"],
      "modes": ["exec", "mount"]
    }
  ]
}
```

Then check it:

```bash
parzival policy check
parzival policy validate
parzival doctor
```

### Rule Order Decides Everything

The policy is a list, and **the first rule that matches a request decides it**. Every
rule below that one is never consulted for that request. This matters more than it
sounds like it should, because a rule can be perfectly correct JSON and still have no
effect at all.

Two ways that happens:

- **An unreachable rule.** An earlier rule already matches everything this one matches.
  You add an allow, the file changes, and the authorization does not.
- **A shadowed rule.** An earlier rule matches *some* of what a later one covers, so
  part of the later rule quietly stops applying.

Neither shows up in a diff of `policy.json`. `parzival policy validate` simulates the
ordering and reports both:

```bash
parzival policy validate                          # the live policy
parzival policy validate --file candidate.json    # a file you are about to install
```

It separates **errors** — where the policy's text and its effect disagree — from
**warnings**, which are things worth seeing but not wrong. It exits non-zero on any
error.

`policy check` answers a narrower question on purpose: only whether a mode restriction
can be bypassed by asserting a different identity label. Its exit status is meant to be
used as a deployment gate in your own install or upgrade scripts, so it does not fail on
the ordering findings above. Run both.

### Ask What Would Happen, Before It Does

`parzival policy what-if` evaluates one request and tells you **which rule decided it**:

```bash
parzival policy what-if --as agent-x --mode exec --ref 'bao:app/gitea#token'
```

```text
DENY

Matched rule: 1
Identity:     agent-x
Mode:         exec
Secret:       bao:app/gitea#token

Rule 1:
  allow: false
  description: agents get nothing under bao:app by default
  secrets: [bao:app/*]
  identities: [agent-*]
  (unrestricted: any mode)

Rule 1 matches this request before any rule below it. If you expected a
later rule to allow this, that rule is unreachable for this request:
narrow rule 1, or place the allowing rule above it.
```

The rule number is the useful part. "Denied" tells you nothing you did not already
know; "denied by rule 1, which matches before the rule you wrote" tells you what to fix.

When no rule matches at all, it names the rules that *nearly* matched and the condition
that stopped each one — usually the real answer to "why didn't my rule fire?":

```text
Rules covering this ref that did not match:
  rule 0 — brokered only, working hours
      mode get is not in [exec mount]
      the request is at 22:00, outside the rule's 08:00-18:00 window
```

Useful flags:

| Flag | What it does |
| --- | --- |
| `--file PATH` | Evaluate against a candidate file instead of the live policy |
| `--at YYYY-MM-DDTHH:MM` | Evaluate at a chosen time, for rules limited by weekday, month day or hours |
| `--as ID` | The identity label; omit it to ask what a caller passing no `--as` would get |

Nothing is fetched and nothing is written to the audit log — it answers a hypothetical.
It exits non-zero when the request would be denied, so it works as a scripted assertion.

### Add a Rule Without Hand-Editing the File

`parzival policy grant` builds one allow-rule, works out where it belongs, shows you
what it changes, and only then installs it:

```bash
parzival policy grant \
    --tool codex \
    --goal "file YouTrack issues" \
    --secret 'bao:app/YouTrack-Codex#token' \
    --identity codex
```

That command **changes nothing**. It analyses, writes a candidate file, and stops. Add
`--apply` to install, which asks for confirmation first; add `--yes` as well for a script
that has nobody to ask.

`--interactive` prompts for the same details instead of taking them from flags.

#### What it shows you before anything is installed

**Where the rule goes, and why.** Not the end of the file — the position at which it both
fires and disturbs nothing:

```text
Placement: rule 0 (at the top)
  above rule 1, which would otherwise decide these requests first
```

**What the rule will actually do**, evaluated by the real policy engine rather than
asserted:

```text
Expected authorization (evaluated against the candidate):
  codex               get    bao:app/YouTrack-Codex#token   DENY
  codex               exec   bao:app/YouTrack-Codex#token   ALLOW  (rule 0)
  codex               mount  bao:app/YouTrack-Codex#token   ALLOW  (rule 0)
  some-other-label *  get    bao:app/YouTrack-Codex#token   DENY
```

The last row is the useful one: it shows that a caller the rule does not name gets
nothing from it.

**Everything that changed, separated from everything you asked for:**

```text
Authorization delta (36 requests probed at 2026-09-08 07:10):
  NEW ALLOW   codex / exec / bao:app/YouTrack-Codex#token  (rule 0)
  NEW ALLOW   codex / mount / bao:app/YouTrack-Codex#token  (rule 0)

Unexpected authorization changes: none
```

If anything moved that you did not ask for, it is listed under **UNEXPECTED** and the
install is refused.

**The exact file change**, as a unified diff, so nothing is installed that you have not
seen in the form it will take on disk.

#### `get` is never granted by silence

Omit `--modes` and you get `exec,mount`. Raw retrieval is granted only when you name it,
and when you do, you are told what you are asking for:

```text
WARNING: this rule permits the caller to retrieve the raw secret value.

  Brokered exec or mount access may be sufficient and exposes less secret
  material to the caller...
```

It is not forbidden — sometimes a tool genuinely has no other interface — but it is never
something you discover afterwards.

#### When it refuses

`grant` stops rather than guessing in three cases:

| Refusal | What it means | What to do |
| --- | --- | --- |
| **Placement is ambiguous** | The rule partially overlaps an existing one with the opposite outcome, and neither contains the other. Both orders are legitimate policies. | It names both indices — pick one with `--at N`. Usually the more specific rule goes first. |
| **The candidate has errors** | An unreachable rule, or a mode restriction the new rule would defeat. | Narrow the grant, or fix the existing rule. |
| **Unexpected authorization changes** | The rule moved something you did not ask about — usually a glob that is broader than intended. | Narrow `--secret` or `--identity`. |

In every case the live policy is untouched — not partially written, not backed up, not
opened for writing.

#### How the install itself is done

Once you confirm:

1. The current policy is copied to `policy.json.bak.<timestamp>`. Existing backups are
   never overwritten.
2. The new policy is written to a temporary file in the same directory, set to `0600`,
   flushed, and **renamed over** `policy.json`. A reader at any instant sees the whole old
   policy or the whole new one — never half of either.
3. The installed file is read back and compared against what you approved, and its
   permissions are checked. If it does not match, the backup is restored automatically and
   the failure is reported.

### Install a Policy File You Already Have

`parzival policy apply` runs the same transaction starting from a file:

```bash
parzival policy apply candidate.json              # analyse only
parzival policy apply --apply candidate.json      # install, with confirmation
```

Because a file carries no statement of intent, every authorization change it makes is
reported for you to recognise — there is nothing to compare against "what was asked for".

Candidate files accumulate in the config directory when you run `grant` without
`--apply`. They are ordinary files and safe to delete; `parzival` only ever reads
`policy.json`.

### A Rule That Feels Safe Can Be Unsafe

Identity labels are self-asserted with `--as` or `$PARZIVAL_IDENTITY`. That means a
rule like "agents cannot use `get`" only works if no other rule allows `get` for the
same secret reference.

Use this rule of thumb:

> Restrict the secret reference, not just the identity.

If any allow-rule matching `bao:app/gitea#token` permits `get`, then a caller can use
that label and read the raw token. `parzival policy check` exists to catch this.

## Fetch a Secret Without Writing a File

Use `get` when the consumer accepts stdin or an inherited file descriptor.

```bash
parzival get --as kevin 'bao:app/gitea#token' | docker login git.example.com \
  -u myuser --password-stdin
```

OpenBao references use:

```text
bao:<mount>/<path>#<field>
```

1Password references use native `op://` syntax:

```bash
parzival get --as kevin 'op://Private/Gitea/token'
```

`get` refuses this by default:

```bash
parzival get 'bao:app/gitea#token' > token.txt
```

That redirect writes the raw secret to persistent disk. If you really mean to do that,
`--force` exists, but most workflows should use `exec` or `mount` instead.

### `get` refuses outright inside an AI agent's tool shell

If `parzival` detects that it is running under an AI coding agent — Claude Code, Cursor,
the Codex CLI, or anything exporting `PARZIVAL_AGENT` — `get` is refused before the fetch
happens:

```text
parzival: refusing to hand a raw secret to an AI agent's tool shell: $CLAUDECODE
identifies this process as running under Claude Code, whose captured output becomes a
durable transcript that cannot be redacted afterwards
```

**There is no override.** No flag, no environment variable, no `--force`. That is the
point of the control rather than a gap in it: a bypass an agent can type is a bypass an
agent will type, and a `get` inside an agent shell puts the value into the agent's
context, the model provider, the terminal, and any session log the launcher keeps — four
permanent copies from one command.

The three things to do instead, in the order you will usually want them:

| You want to | Do this |
| --- | --- |
| Confirm a ref is readable | `parzival probe <ref>` — no value is returned |
| Use the credential | `parzival exec` or `parzival mount` — brokered; Parzival does not write it to its stdout |
| Genuinely see the raw value | Run `get` yourself, in a terminal that is not driving `parzival` |

The refusal keys on environment variables, so it is a mistake-prevention control and not a
boundary — anything that can unset a variable defeats it. That is consistent with the rest
of the model: a same-uid process can bypass `parzival` altogether. It is aimed at the case
that actually happens, which is an honest, on-task agent reaching for `get` because `get`
was the only tool that answered its question.

`parzival doctor` tells you whether the current shell is detected as one:

```text
[INFO] AI agent shell detected: $CLAUDECODE — Claude Code; `get` is refused here, use probe/exec/mount
```

## Check a Ref Without Reading It

`probe` answers one question — *would this fetch succeed?* — and answers it without ever
returning the value. Use it to confirm that a store-side ACL grant actually landed, which
is the check that used to require running `get` and remembering to redirect the output.

```bash
parzival probe --as ansible 'bao:tailscale/api/oauth-client#client_id'
```

```text
Ref:      bao:tailscale/api/oauth-client#client_id
Identity: ansible

OK

Reached:  get (rule 16)
Value:    present — not shown, and probe never shows it
```

There are four verdicts, each with its own exit status so a script can tell them apart:

| Verdict | Exit | Means |
| --- | --- | --- |
| `OK` | 0 | The fetch succeeded and returned a value |
| `EMPTY` | 3 | The fetch succeeded and returned zero bytes |
| `DENIED` | 4 | The policy refused it |
| `ERROR` | 5 | The store refused or could not perform the fetch |

`DENIED` and `ERROR` being separate is the useful part: "your policy does not allow this"
and "OpenBao's ACL does not allow this" are different problems with different fixes, and
running `get` to find out which one you had is exactly the habit this verb replaces.

A `DENIED` names why each mode was refused:

```text
DENIED

Reached:  no mode — get, exec and mount are all denied
  get    no matching rule (default deny)
  exec   no matching rule (default deny)
  mount  no matching rule (default deny)
```

**`probe` takes no `--mode`.** The question is whether the identity can reach the ref at
all, so it tries `get`, `exec` and `mount` in that order and names the first the policy
permits. That means it needs no rule of its own, works against a policy written before it
existed, and grants nothing — an identity that can `exec` a ref could already learn whether
the fetch succeeds by running `exec`.

**`probe` is not `policy what-if`.** `what-if` simulates: it evaluates the rules, names the
deciding one, touches no store, and writes nothing to the audit log. `probe` performs a
real fetch against the real backend, which is the only way to see a store-side ACL, and it
is audited accordingly — its record carries `caller=probe` so a reader can tell a
reachability check from a delivery. Use `what-if` to ask why a rule did or did not match;
use `probe` to ask whether the credential is actually there.

## Run a Tool That Needs a Credential File

Use `exec` when a tool insists on a file path.

Profiles live in:

```text
~/.config/parzival/profiles/<name>.json
```

A profile says which secrets to fetch, how to render them, and how the child command
finds the rendered file. This AWS profile renders a credentials file in RAM:

```json
{
  "secrets": {
    "access_key": "bao:aws/myaccount#access_key_id",
    "secret_key": "bao:aws/myaccount#secret_access_key"
  },
  "template": "[default]\naws_access_key_id = {{ .access_key }}\naws_secret_access_key = {{ .secret_key }}\n",
  "inject": {
    "env": "AWS_SHARED_CREDENTIALS_FILE",
    "filename": "credentials"
  }
}
```

Run it:

```bash
parzival exec --as ai aws -- aws s3 ls
```

During the command:

| Path | How the child sees it |
| --- | --- |
| Rendered credential file | `$PARZIVAL_CRED_FILE` |
| RAM-backed credential directory | `$PARZIVAL_CRED_DIR` |
| Profile-specific file variable | The profile's `inject.env`, such as `AWS_SHARED_CREDENTIALS_FILE` |
| Profile-specific directory variable | The profile's `inject.env_dir`, such as `XDG_CONFIG_HOME` |
| Command argv substitution | `{{cred}}` for the file, `{{creddir}}` for the directory |

When the command exits, Parzival zeroes and removes the rendered file. Signal cleanup
is wired for Ctrl-C and termination paths.

## Use the Shipped Profiles

Copy an example and edit the references for your store:

```bash
mkdir -p ~/.config/parzival/profiles
cp examples/profiles/aws.json ~/.config/parzival/profiles/
```

| Profile | Best for | Example |
| --- | --- | --- |
| `aws` | AWS shared credentials file | `parzival exec aws -- aws s3 ls` |
| `kubectl` | `KUBECONFIG` | `parzival exec kubectl -- kubectl get pods` |
| `pgpass` | PostgreSQL password file | `parzival exec pgpass -- psql -h postgres.example.com -U dbuser` |
| `ssh-key` | Temporary SSH identity file | `parzival exec ssh-key -- ssh -i {{cred}} -o IdentitiesOnly=yes host uptime` |
| `curl-bearer` | Token in a curl config file | `parzival exec curl-bearer -- curl -K "$EXAMPLE_CURL_CONFIG" https://api.example.com` |
| `tea` | Gitea CLI config under `XDG_CONFIG_HOME` | `parzival exec tea -- env HOME=/nonexistent tea repos list` |
| `openbao-token` | Downstream `bao` command needing `.vault-token` | `parzival exec openbao-token -- env BAO_ADDR=https://bao.example.com bao token lookup` |
| `homebrew-token` | Homebrew token, weakest pattern | Reads the RAM file into `HOMEBREW_GITHUB_API_TOKEN` inside one child |

The Homebrew profile is included because some upstream tools only accept an
environment variable. Use a narrow, purpose-built token for that kind of profile.

## Mount Virtual Credential Files on Linux

Use `mount` when a tool reads a fixed path repeatedly and you want one virtual file
per profile.

```bash
mkdir -p ~/parzival-mnt
parzival mount --as ci ~/parzival-mnt
```

In another terminal:

```bash
ls ~/parzival-mnt
cat ~/parzival-mnt/gitea-token
```

Each `open()`:

1. Loads the profile.
2. Checks policy for `mode=mount`.
3. Fetches fresh secret material.
4. Renders in memory.
5. Wipes the rendered bytes when the file handle closes.

The mount is owner-only and uses direct I/O so content is not page-cached. On macOS,
use `exec`; `mount` is not implemented there.

## Call an Operation Through the Broker

`get`/`exec`/`mount`/`probe` above all authorize against *this* process's own
`policy.json` and fetch the value into *this* process. `service` is a different shape:
it's a client of a separate, long-running **broker daemon** (`parzival-broker`) that
lets a caller — especially an AI agent — *use* a credential without ever being able to
*read* it. The client never names a command, a file, a profile, or an environment
variable; it names an **operation** and typed inputs, and the broker decides everything
else.

| Role | Requirement | Notes |
| --- | --- | --- |
| The broker | `parzival-broker` running and enabled | Linux only — see [INSTALL.md](INSTALL.md)'s "Installing the broker service" section. Check with `systemctl status parzival-broker` first |
| The client | The regular `parzival` binary | Nothing extra to install — `service` is a subcommand of the same binary `get`/`exec` already live in |

```bash
parzival service tea.repos-list --input owner=acme
```

`--input name=value` is repeatable, for operations that take more than one input. On
success, the broker's canonicalized JSON result prints to stdout and the command exits
`0`. On anything else, a short, non-sensitive message prints to stderr and the exit
code names which of the broker's closed statuses happened:

```json
[
  {"owner": "acme", "name": "widget-service", "type": "source", "ssh": "ssh://git@..."}
]
```

| Exit code | Status | Meaning |
| --- | --- | --- |
| `0` | `OK` | Succeeded — the result above is on stdout |
| `3` | `DENIED` | Not authorized for this operation — never means "it doesn't exist"; the broker won't tell an unauthorized caller the difference |
| `4` | `INVALID` | The request was malformed, or an input failed its declared pattern |
| `5` | `ERROR` | The broker attempted the operation and it failed |
| `6` | `UNAVAILABLE` | The broker can't serve requests right now (e.g. it can't reach its own store) |
| `1` | — | Transport failure — the broker wasn't reachable at all, or its response couldn't be understood. Distinct from the codes above: this means the broker never got to render a verdict |

Only one operation exists today, `tea.repos-list`. What operations a given deployment
serves, and who's authorized for each, are decisions the broker's administrator makes —
see `SERVICE-PROTOCOL.md` for the wire protocol and `internal/consumer`/`internal/
broker`'s package docs for the consumer-definition and authorization-file formats. This
command never grants anything by itself; it can only ask for what the broker already
allows.

## Use OpenBao in the Strong Mode

Ambient OpenBao mode shells out to `bao` and inherits whatever auth the caller has.
That is useful for compatibility, but it cannot be the strongest unattended boundary
because the caller may also be able to run `bao` directly.

For unattended use, configure AppRole broker auth:

```bash
export PARZIVAL_OPENBAO_AUTH=approle
export BAO_ADDR=https://openbao.example
export PARZIVAL_OPENBAO_ROLE_ID=<role-id>
export PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential
```

For interactive user-session storage, see [INSTALL.md](INSTALL.md)'s "Creating the CLI's
own AppRole" section, which documents `systemd-creds encrypt --user`. The important
property is that Parzival can authenticate to OpenBao without a caller-readable
`BAO_TOKEN` or `~/.vault-token`.

Use `parzival doctor` as the gate before you wire real unattended consumers.

## Break Glass Without Making It a Back Door

Parzival deliberately has no bypass built in — no flag, no environment variable, no
override that lets automation or an AI agent read something policy denies.

That leaves one situation policy can't solve by itself:

> a manual OpenBao operation is genuinely needed, and Parzival policy does not grant it
> to automation.

The correct action is one of exactly two things:

1. Identify the Parzival policy change needed and get a human to approve it.
2. Print the exact command for a human to run manually, in a break-glass mechanism kept
   entirely outside Parzival's own request path, then stop.

A real break-glass mechanism — whatever tool a given deployment uses for it — should
enforce a human-only path independent of Parzival:

| Gate | What it protects |
| --- | --- |
| Real (not merely effective) human user id | Break-glass authority belongs to a specific human, not to root or a service account |
| An actually open controlling terminal | Detached/piped jobs cannot run it |
| An out-of-band human-presence check (a live sign-in, not just a TTY check) | A recording pty can satisfy a naive TTY-only check without a human actually present |
| Exact confirmation phrase on the controlling terminal | Piped stdin cannot confirm the bypass |
| Pinned endpoint for whatever it authenticates against | A caller cannot redirect the login flow to steal the credential |
| Absolute helper paths | `PATH` shadowing cannot capture the credential |
| Policy file validation | Bad policy writes are refused before the store is touched |

See [THREAT-MODEL.md](THREAT-MODEL.md) for the full reasoning behind each property.

Agents and automation must never invoke a break-glass mechanism. Do not wrap it, call it
from a script, make it a fallback, or use it as a credential broker. The answer for
automation is always a Parzival policy rule.

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `denied by policy` | No rule matched, or the mode is not allowed | Read the error; add or adjust a rule in `policy.json` |
| `get` works but `exec` fails | Policy allows `get` but not `exec`, or the profile reference is wrong | Add `exec` to the rule or fix the profile |
| `exec` creates no durable file | That is expected | The file exists only while the child command runs |
| `mount` fails on Linux | Missing FUSE support | Install `fuse3`, check `/dev/fuse`, or use `exec` |
| `mount` is requested on macOS | Not implemented | Use `exec` |
| `doctor` fails on `BAO_TOKEN` | Ambient token is exported | Unset it and use AppRole broker auth for unattended use |
| A new policy field is refused | Installed binary is older than the policy | Rebuild Parzival before trusting the new field |
| OpenBao fetches fail | OpenBao is sealed, unreachable, or auth is missing | Check OpenBao status and broker auth configuration |
| `refusing to hand a raw secret to an AI agent's tool shell` | You are running inside Claude Code, Cursor, Codex, or another detected harness | Use `probe` to check a ref or `exec`/`mount` to use one. There is no override — run `get` yourself in an ordinary terminal if you truly need the value |
| `probe` says `DENIED` | The **policy** refused it | `parzival policy what-if` names the rule that decided |
| `probe` says `ERROR` | The **store** refused or failed the fetch | The policy is fine; check the OpenBao ACL, the path, and whether the field exists |
| `probe` says `EMPTY` | The ref resolves but holds zero bytes | The secret was created without a value, or the field name is wrong |

## Keep This Manual Useful

This manual follows the guidance from Amarel's
[User Manuals That People Actually Read](https://www.amarel.net/en/all-resources/blog/user-manuals-that-people-actually-read-crafting-effective-guides/):
plain language, clear task paths, searchable headings, short procedures, real examples,
and problem-solving sections.

Before adding a new section, ask:

1. What task is the reader trying to finish?
2. What should they run first?
3. What mistake would leak a secret or weaken the policy?
4. Where should deep operator detail live instead?

Use this manual for the first useful answer. Use INSTALL.md and THREAT-MODEL.md for the
full explanation.
