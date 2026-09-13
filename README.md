# What is Parzival

Parzival is a credential broker system that delivers four things:

1. A guarantee that only authorized programs and tools can access a given secret through
   policy statements.
2. Prevention of credential leaks into AI-agent sessions.
3. Secrets kept encrypted and off local disk storage, regardless of the tool that
   consumes the secret.
4. Audit logging of which credentials were accessed and by what tool.

- **Authorization — only approved tools may use approved secrets.** Policy determines
  which identity or tool may use a particular credential and by which mode or broker
  operation. The default is deny.
- **AI credential containment — secrets must not leak into AI-agent context.** Agents
  can use credentials through `exec`, `mount`, or broker operations without receiving
  the raw value in stdout, transcripts, prompts, logs, or tool results. Raw `get` is
  specifically blocked in detected AI-agent shells.
- **No persistent plaintext credentials — keep secrets encrypted and off local persistent
  storage.** Credentials remain in OpenBao, 1Password, or another encrypted store and
  are fetched only when needed. Parzival uses streams, RAM-backed files, encrypted
  systemd credentials, or other ephemeral mechanisms rather than ordinary plaintext
  credential files. Parzival can guarantee what it itself does with a secret; it cannot
  prevent a deliberately malicious consumer from taking a credential it legitimately
  receives and writing it to disk.
- **Accountability — audit which credentials were used, by whom, and for what.** Secret
  access and use are auditable, including the requesting identity, tool or operation,
  credential reference, authorization result, and outcome — without logging the secret
  itself.

## Why is it named Parzival

> "What is the secret of the Grail? Who does it serve?"
>
> "You, my lord."
>
> "Who am I?"

In John Boorman's *Excalibur* (1981), Perceval then recognizes the wounded figure as
Arthur, his lord and king. Asked whether he has found the secret that was lost,
Perceval answers that Arthur and the land are one.

## Summary

Parzival retrieves credentials from OpenBao only after its deny-by-default policy
authorizes the request. 1Password is the human gate for access to the system, rather
than a peer credential store in this deployment. `get` writes a raw value to stdout or
an inherited file descriptor, while refusing in detected AI-agent shells; `exec` renders
profile credentials to a short-lived RAM-backed file for one command; and Linux `mount`
presents profile credentials as read-only virtual files that are fetched again on every
open. The broker service exposes a fixed set of local consumer operations over a Unix
socket for clients that must use a credential without reading it. Temporary credential
buffers and files are zeroed or removed when Parzival finishes with them.

## Status

**Pre-1.0 public prerelease. No tagged release has been cut yet.** The CLI and the broker
service are both implemented and exercised against real deployments, not just designed:

- `parzival get` streams a secret from OpenBao or 1Password to stdout or a file
  descriptor; `parzival exec` renders secret(s) into a RAM-backed file, runs a command
  pointed at it, then wipes it; `parzival mount` serves the same thing as a read-only
  virtual filesystem. An approval policy gates every fetch, strict deny-by-default,
  with every decision written to an audit log.
- `parzival-broker` is a packaged (RPM/DEB) systemd service: an `AF_UNIX` socket server
  exposing a small, fixed set of consumer operations (currently `tea.repos-list`) to
  local callers. Access to the socket itself and authorization to invoke an operation
  are two independent, OS-enforced layers — see [`SERVICE-PROTOCOL.md`](SERVICE-PROTOCOL.md)
  and `packaging/README.md` for the trust model and installation contract.
- Linux packaging (RPM and DEB) is built and tested via GoReleaser; macOS ships the CLI
  only, as a Homebrew cask — there is no macOS broker/service package.

The full design and phased roadmap live in the project's planning documents.

## Installation

See [INSTALL.md](INSTALL.md) for installing the `parzival` CLI (RPM, DEB, Homebrew, or from
source) and, on Linux, the `parzival-broker` service. Use **CLI mode** if you or a trusted
script need to fetch or broker a secret directly under your own approval policy; use
**broker service mode** if an untrusted client — an AI agent, in particular — needs to *use*
a credential without ever being able to *read* it. INSTALL.md covers both, plus configuring
an OpenBao/1Password backend, the broker's trust boundary, and validating the install. Once
installed, see [MANUAL.md](MANUAL.md) for how to actually use it.

## Purpose

There are four problems this project addresses:

- Secrets are often stored as plaintext in files, config directories, and scripts,
  which makes them easy for malware or overly broad local access to discover and reuse.
  macOS and Linux reduce some risk, but they do not prevent credential theft by
  processes already running as the user.
- After login, secrets may also exist in plaintext in process memory or be exposed
  through environment variables inherited by child processes.
- Automated workflows such as AI tools, scheduled jobs, background services, and
  non-interactive scripts also need access to credentials.
- In most current setups, too many applications within the same user context can access
  the same credentials through the home directory, process memory, or inherited shell
  environment.

### Why this exists outside the cloud

Parzival was designed to operate **outside** an AWS or cloud environment. The thought
experiment that gave rise to this project was: *how would it function with these design
goals in mind?* AWS, Azure, and the other cloud providers have already solved all of these
problems. But for those running on-prem, or a homelab on physical non-cloud hosts, this is
the gap Parzival is trying to fill.

I want AI tasks and automation with **zero** credential leaks (goal 2). And I want a policy
that enforces that only tool, program, or command *xyz* can reach credential *abc* — if I
allow it, at the time of day I allow it, and by the method I allow — as decided by Parzival
policy (goal 3).

Finally, on goal 2: there are three decades of genuinely bad practice behind us. Secrets
stored in plaintext, on local disk, with no access protection beyond the access controls of
the OS itself. Worse still, a wide variety of CLI and in-shell programs use poorly designed
secret-input methods — reading a plaintext file and nothing else, or requiring an
environment variable to be set (ugh). These are severely outdated and harmful practices.
Parzival intends to wrap them securely, without the ability — or the desire — to fix the
upstream code.

## Operational Context

| Item | Detail |
| --- | --- |
| Status | Pre-1.0 public prerelease. CLI and broker are both implemented and deployed in real installs; no tagged release has been cut yet. |
| Secrets location | Encrypted stores: OpenBao, 1Password, gopass (planned), KeePassXC (planned). No plaintext secrets in this repo. |
| Data classification | This repo contains source, packaging, and documentation only — never credentials. |
| Production impact | Real, where deployed — parzival-broker runs as an unattended systemd service handling live credential requests once installed. |

## How It Works

The design rests on one unavoidable truth: a secret **must** become plaintext at the
point of use, because the consuming tool needs the cleartext bytes in its own memory
to do its job. So the goal is not "never plaintext" — it is **plaintext for the
shortest time, in the fewest copies, on volatile memory only, wiped immediately
after.**

Four design goals follow from that. **This list is canonical** — everything else in this
repository refers to these goals by number rather than restating them.

### Goal 1 — Encrypted at rest

No secret exists as plaintext at rest anywhere Parzival is responsible for: not in a
dotfile, not in an app's config directory, not in a script, not in a token file.
Credentials live encrypted in a store — OpenBao, 1Password — and are decrypted only in
memory, only at the moment of use.

### Goal 2 — Delivered only at runtime, through the safest interface the tool supports

Secrets reach a consumer at execution time and leave nothing behind. Parzival prefers a
stream — stdin, a file descriptor, a named pipe — falls back to a FUSE-backed virtual
file, and uses a short-lived RAM-backed file only when a tool insists on a path.
**Environment-variable injection is a last resort, scoped to a single child process.**

Because three decades of CLI and in-shell programs accept credentials only through a
plaintext file or an environment variable, this goal is as much about **safely wrapping
bad upstream interfaces** as about Parzival's own behaviour. Parzival has neither the
ability nor the desire to fix that upstream code.

Two callers are refused the raw stream outright rather than merely discouraged from it: a
stdout redirected to a regular file, and an AI agent's tool shell. Both are destinations
that *record*, and the value cannot be recalled once it lands there. `parzival probe`
exists so the commonest legitimate reason to reach for a raw value — checking whether a
ref is readable at all — no longer requires receiving one.

### Goal 3 — Authorized per request, by identity and by context

Every fetch is authorized before it happens, strict deny-by-default. It is **one
decision** evaluated over both halves:

- **Who is asking** — each human, script, timer, service, and AI agent has its own
  identity, with access only to the secrets it needs.
- **Under what conditions** — the calling script or command, the workflow, the delivery
  method allowed, the day of week, the day of month, and the time of day.

Every decision, allow and deny alike, is written to an audit log.

**The identity half is self-asserted, and that is a documented limit rather than a
boundary.** A rule saying an identity is human-run and unattended records an intention the
policy cannot enforce: any caller can type the same label. `parzival policy validate`
reports the whole set of labels that reach raw `get` for exactly this reason, and the
`get` refusal in an agent shell is what turns one class of that intention into something
actually enforced at runtime.

### Goal 4 — Presented to one consumer, once

Each request is fulfilled for exactly one verified caller. A secret is not broadcast, not
cached for reuse, and not left available after the call that needed it — which is why
`mount` re-runs policy and re-fetches on every `open()` rather than materialising a file
once.

### What is deliberately not a goal

| Not a goal | Why |
| --- | --- |
| Machine binding / theft resistance | Declined 2026-08-14. The mitigation for a stolen credential is rotation, not prevention. |
| Secret zero being a brokered secret | It is a **precondition** serving goals 1–3, not a goal. Parzival never hands secret zero to a caller — it is how Parzival reaches the store. See [THREAT-MODEL.md](THREAT-MODEL.md) §6b. |
| Defence against root, or a same-uid attacker | [THREAT-MODEL.md](THREAT-MODEL.md) §4 and §5 scope. The goals do not carry their own caveats; the threat model does. |

#### A note on physical theft — read this before deploying

Parzival is **not** intentionally trying to protect against physical theft by means such as
a TPM. In the Unix universe — the non-cloud universe — those mechanisms are not always
available, and a design that depends on them excludes the very hosts this project exists to
serve.

That places two responsibilities on the operator rather than on Parzival:

- **Rotate access to your secret store on a regular basis.** Rotation, not hardware, is the
  mitigation for a stolen credential — and it only works if it is routine.
- **Back up your secret store in a consistent and secure manner.** Parzival brokers access
  to a store; it is not a store, and it keeps no copy of anything it hands out.

`parzival` chooses the highest-tier delivery mechanism the target tool supports — native
keyring, stdin/fd/process-substitution, a FUSE virtual file, a RAM-backed ephemeral
file, or a named pipe. See [THREAT-MODEL.md](THREAT-MODEL.md) for the security model behind
that ordering.

## Store agnosticism and guarantees

Parzival is intended to stay **store-agnostic at the user interface**. A caller should use
the same broker commands — `get`, `exec`, `mount`, policy checks, and audit review — whether
the backing store is OpenBao, 1Password, gopass, KeePassXC, or another encrypted store.

The security guarantees are not identical across stores. Goal 1 and goal 2 can be met by
many encrypted stores: they can hold secrets encrypted at rest, and Parzival can still
deliver those secrets only at runtime through safer interfaces. Goal 3 is stricter. If the
caller can reach the backing store directly with the same authority Parzival uses, then
Parzival policy can be bypassed and the bypass is unaudited.

For that reason, OpenBao is the **reference backend for enforceable unattended use**, not
because Parzival must be OpenBao-only, but because OpenBao supports the properties the
strongest mode needs: a broker-specific identity, scoped store-side policy, short-lived
tokens, auditable access, and routine rotation of bootstrap credentials.

Other stores remain useful where their guarantees match the risk. 1Password, OS keychains,
gopass, and KeePassXC can be good fits for interactive workflows and leak-prevention
delivery, especially when a human unlocks the store. They should not be treated as
equivalent to an unattended OpenBao/AppRole or JWT-style setup unless they can also prevent
or detect direct store access by the caller.

## Technology

Preference order for the encrypted store backing the broker:

- **Best overall:** OpenBao + Agent — open-source HashiCorp Vault fork with agent-based
  secret injection; strongest fit for both interactive and automated use.
- **Easiest cross-platform "one app" answer:** 1Password + CLI.
- **Best open-source local CLI:** gopass.
- **Best local GUI/CLI encrypted vault:** KeePassXC.

## Usage

```bash
# Build
go build -o parzival ./cmd/parzival

# Fetch a secret to stdout (delivery tier 2 — stream, no disk)
parzival get 'bao:app/gitea#token'          # OpenBao KV v2
parzival get 'op://Private/Gitea/token'     # 1Password

# Or to an inherited file descriptor instead of stdout
parzival get --fd 3 'bao:app/gitea#token' 3>/some/consumer/fd

# Ask whether a fetch WOULD succeed, without receiving the value
parzival probe --as ansible 'bao:app/gitea#token'

# Check deployment posture before wiring real unattended consumers
parzival doctor
```

`get` **refuses a stdout redirected to a regular file** — `parzival get REF > cred.txt`
leaves the raw value on disk permanently, which is the outcome this project exists to
prevent. A pipe or a terminal is genuinely ambiguous and stays allowed, `--fd` is exempt
(choosing a descriptor is deliberate), and `--force` overrides if you meant it.

`get` also **refuses outright inside an AI agent's tool shell** (Claude Code, Cursor, the
Codex CLI, or anything exporting `PARZIVAL_AGENT`), before the fetch and regardless of
`--fd`. An agent's captured output becomes a transcript held by the agent, the model
provider, the terminal and the launcher's session log — four permanent copies from one
command, none of them redactable afterwards. **There is deliberately no override**: no
flag, no environment variable. A bypass an agent can type is a bypass an agent will type.
Use `probe` to check a ref, `exec`/`mount` to use one, or run `get` yourself in a terminal
that is not driving `parzival`. See [THREAT-MODEL.md](THREAT-MODEL.md) §4b.

### `parzival probe` — ask whether a fetch would succeed (no delivery)

`probe` exists because its absence caused a leak. Confirming that a store-side ACL grant
landed is ordinary work, and until it existed the only tool that could answer was `get` —
which answers by handing back the plaintext. The workflow itself pushed the operator toward
the one command that can put a credential in a transcript.

It runs the real policy check and a real backend fetch, discards what it retrieved, and
reports one of four verdicts with a distinct exit status:

| Verdict | Exit | Means |
| --- | --- | --- |
| `OK` | 0 | The fetch succeeded and returned a value |
| `EMPTY` | 3 | The fetch succeeded and returned zero bytes |
| `DENIED` | 4 | The policy refused it |
| `ERROR` | 5 | The store refused or could not perform the fetch |

`DENIED` and `ERROR` are separate because "your policy does not allow this" and "OpenBao's
ACL does not allow this" have different fixes, and running `get` to find out which you had
is the habit this replaces. Nothing about the value is reported — not its length, not a
prefix, not a hash.

It takes no `--mode`: it tries `get`, `exec` and `mount` in that order and names the first
the policy permits. So it introduces no new mode value, needs no rule of its own, works
against a policy written before it existed, and grants nothing — an identity that can
`exec` a ref could already learn whether the fetch succeeds by running `exec`.

Unlike `policy what-if`, which simulates and deliberately writes nothing, `probe` performs
a real fetch and is audited as one, with `caller=probe` marking it as a reachability check
rather than a delivery.

Reference forms: `bao:<mount>/<path>#<field>`, `op://<vault>/<item>/<field>`,
`gopass:<path>` (not yet implemented). 1Password uses `op read`; OpenBao supports
both ambient `bao` CLI-auth compatibility mode and AppRole broker-auth mode for
unattended use. See [theory-of-operation-and-rationale.md](theory-of-operation-and-rationale.md).

For OpenBao AppRole broker-auth mode:

```bash
export PARZIVAL_OPENBAO_AUTH=approle
export BAO_ADDR=https://openbao.example
export PARZIVAL_OPENBAO_ROLE_ID=<role-id>
export PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential
```

The default systemd credential name is `openbao-secret-id`; override it with
`PARZIVAL_OPENBAO_SECRET_ID_NAME`. Development-only providers are available for tests and
migration: `env` reads `PARZIVAL_OPENBAO_SECRET_ID`, and `file` reads
`PARZIVAL_OPENBAO_SECRET_ID_FILE`. They are not production secret-zero protection.

### `parzival exec` — render to a RAM file, run, wipe (tier 4)

For tools that insist on reading a credential from a file path. A **profile**
(`~/.config/parzival/profiles/<name>.json`) declares which secrets to fetch, a
template to render them into, and how the command is pointed at the file.

```bash
mkdir -p ~/.config/parzival/profiles
cp examples/profiles/aws.json ~/.config/parzival/profiles/

# Renders creds to a tmpfs file, sets AWS_SHARED_CREDENTIALS_FILE, runs, wipes.
parzival exec aws -- aws s3 ls

# Arg injection: {{cred}} is replaced with the RAM-file path.
parzival exec gitea-token -- sh -c 'wc -c < {{cred}}'
```

The path is exposed three ways: as `$PARZIVAL_CRED_FILE`, as the profile's
`inject.env` variable, and substituted for any `{{cred}}` token in the command. The
file lives on tmpfs (`$XDG_RUNTIME_DIR`), is mode `0600`, and is zeroed and removed
when the command exits — including on Ctrl-C. See
[examples/profiles/](examples/profiles/).

### `parzival mount` — FUSE virtual credential files (tier 3, Linux)

For tools that read a credential from a fixed path and can't be redirected. Mounts a
FUSE filesystem exposing **one read-only virtual file per profile**; each `open()`
runs the policy, fetches fresh, renders, and serves from memory — nothing on disk, and
every open re-fetches (no caching).

```bash
parzival mount --as ci ~/parzival-mnt     # foreground; Ctrl-C to unmount
cat ~/parzival-mnt/gitea-token            # fetched + rendered live
```

The mount is owner-only (`0700`, no `allow_other`). Every `open()` is policy-checked
against the mount's `--as` identity, and the audit log additionally records the calling
process (`uid`/`pid`/`exe`) as provenance — the "which binary is asking" signal a pipe
can't see (advisory, not enforced; see [THREAT-MODEL.md](THREAT-MODEL.md)). **Linux
only**; on macOS use `parzival exec`.

## Approval policy (strict deny-by-default)

Every fetch — for both `get` and `exec` — is checked against
`~/.config/parzival/policy.json` **before** the store is queried. The posture is
**strict deny-by-default**: with no policy file, every fetch is denied. A request is
allowed only if a rule matches it.

```json
{
  "schema": 1,
  "rules": [
    { "allow": true, "secrets": ["bao:app/gitea#*"], "identities": ["tea","docker"],
      "modes": ["exec","mount"],
      "weekdays": ["Mon","Tue","Wed","Thu","Fri"], "hours": "08:00-18:00" },
    { "allow": true, "secrets": ["op://Private/*"], "identities": ["me"] }
  ]
}
```

Rules are evaluated in order; the first whose conditions all match decides. Conditions
(any omitted one is a wildcard): `secrets` and `identities` (globs with `*`/`?`),
`modes` (`get`/`exec`/`mount`), `weekdays`, `monthdays` (1–31), and an `hours` window
`HH:MM-HH:MM` (local, wraps past midnight). Identity is **self-asserted** via
`--as <id>` or `$PARZIVAL_IDENTITY`. `description` is free text for the operator.

```bash
parzival get  --as tea  'bao:app/gitea#token'
parzival exec --as ci   aws -- aws s3 ls
```

### Restrict the ref, not the identity

`modes` is an allowlist: a rule listing `["exec","mount"]` grants brokered delivery while
refusing the raw `get` path. That is the recommended posture for AI agents, timers, and other
non-human callers because it prevents the broker from writing the value to their tool stream.
It is not, by itself, a binding to a particular consumer command: `exec` accepts a caller-chosen
child, and same-uid processes are not isolated from one another. See `THREAT-MODEL.md` §4b for the
additional OS isolation required to guarantee non-disclosure to an agent.

It has one sharp edge, and getting it wrong makes the control decorative. Because identity
is self-asserted and the first matching rule wins, restricting *one identity* to
`exec`/`mount` achieves nothing if some *other* rule permits `get` on the same ref — the
caller simply passes the other label. The restriction only holds when **every** allow-rule
matching that ref excludes `get`; then no label reaches the raw value and identity does not
have to be trustworthy for the guarantee to stand.

```bash
parzival policy check     # reports which refs are readable and which
                          # restrictions a different --as label would bypass
```

`policy check` exits non-zero when it finds a bypassable restriction, so it can gate a
rollout or run as a post-install verification.

### Rule order is part of the policy, and a diff does not show it

The first matching rule decides, so a rule can be valid JSON and still have no effect —
an earlier rule already matched everything it matches. Adding it changes the file and
not the authorization. `policy validate` simulates the ordering and reports the rules
that can never fire, the ones that shadow part of a later rule, and the redundant ones,
separating errors (text and effect disagree) from warnings:

```bash
parzival policy validate                          # the live policy
parzival policy validate --file candidate.json    # before installing one
```

`policy what-if` answers the same question for a single request, and names the rule
responsible — which is the part worth knowing, since "denied" is rarely the useful half
of the answer:

```bash
parzival policy what-if --as agent-x --mode exec --ref 'bao:app/gitea#token'
```

When nothing matches, it names the rules that came closest and the condition that
stopped each — the wrong mode, the wrong day, an hours window. Nothing is fetched and
nothing is written to the audit log.

The two commands are deliberately separate from `policy check`, whose narrower
contract — mode bypasses only — is relied on as a deployment gate.

### Editing the policy is a transaction, not a file write

`policy grant` builds one allow-rule and owns the whole change:

```bash
parzival policy grant --tool documentation-bot --goal "publish documentation" \
    --secret 'bao:app/docs#token' --identity documentation-bot
```

It computes where the rule belongs rather than appending it, shows the resulting
authorization from the real evaluator, reports every change the edit causes and separates
the ones that were asked for from the ones that were not, and prints the file diff. That
much changes nothing: `--apply` installs, and installing means backup → same-directory
temp file at `0600` → `rename(2)` → read back and verify, restoring the backup if the
installed file is not what was approved.

Omitting `--modes` grants `exec,mount`. Raw `get` is granted only when named, and warns
when it is. Placement that cannot be determined safely is refused with both candidate
positions named, rather than guessed.

`policy apply` runs the same transaction from a file you already have.

### An out-of-date binary refuses the policy

A policy naming a field the binary does not know is **refused outright**, not partially
applied. Without this, a `policy.json` written for a newer parzival degrades in silence —
an unread `modes` field turns a brokered-delivery-only rule into an unrestricted allow,
with no warning. Refusing to run beats quietly enforcing less than the operator wrote. The
optional `schema` field is the same guarantee for a field whose *meaning* changes without
its name changing. **Rebuild after upgrading, before trusting a new policy field.**

Every decision (allow and deny) is appended to `$XDG_STATE_HOME/parzival/audit.log` —
recording the reference, identity, time, and reason, **never the secret value**. This is
advisory provenance, audit, and mistake-prevention — **not** a same-uid security boundary
(see [THREAT-MODEL.md](THREAT-MODEL.md)). Set `PARZIVAL_CONFIG_HOME` to point parzival at
a different config dir without disturbing other tools. See [examples/policy.json](examples/policy.json).

## Repository Layout

```text
parzival/
├── .gitignore
├── .markdownlint-cli2.jsonc  # repo-local mdlint rules (MD024/MD034/MD025)
├── LICENSE                   # Apache-2.0
├── NOTICE
├── README.md                 # this file
├── INSTALL.md                # installing and deploying parzival and parzival-broker
├── MANUAL.md                 # user-facing operational guide (get/exec/mount/service, policy)
├── THREAT-MODEL.md           # security model and consumer-attestation limits
├── SERVICE-PROTOCOL.md       # broker service protocol (implemented on Linux)
├── theory-of-operation-and-rationale.md   # how `get` works and why backends shell out
├── go.mod                    # Go module: github.com/kevinpinscoe/parzival
├── mise.toml                 # pinned toolchain (Go, markdownlint-cli2)
├── cmd/parzival/             # CLI entry point (get, probe, exec, mount, policy, doctor)
├── cmd/parzival-broker/      # broker daemon entry point
├── examples/                 # example exec profiles, consumer definitions + policy.json
├── packaging/                # systemd units, sysusers.d, install scripts for parzival-broker
├── scripts/release/          # release-notes and leak-scan scripts used by CI
└── internal/
    ├── agent/                # AI-agent-shell detection; `get` refuses when one is found
    ├── store/                # store-backend interface + OpenBao / 1Password / gopass
    ├── secret/               # raw-secret handling: write to fd, zero after use
    ├── ephemeral/            # RAM-backed dir for exec; zero + unlink on cleanup
    ├── profile/              # exec profile format (JSON): secrets, template, inject
    ├── policy/               # approval policy: strict deny-by-default + audit log;
    │                         #   check.go analyses a policy for bypassable restrictions
    ├── consumer/             # consumer definitions: fixed executable + operation allowlist
    │                         #   for the broker service mode in SERVICE-PROTOCOL.md
    ├── broker/                # broker daemon implementing SERVICE-PROTOCOL.md
    └── mount/                # FUSE virtual credential files (Linux)
```

## Security

No secret — token, password, private key, or credential — is ever stored unencrypted
on persistent disk, in a dotfile, in shell history, or in this repository. Plaintext
exists only transiently in volatile memory (a pipe buffer or RAM-backed file) for the
duration of a single command, and is wiped immediately afterward. See
[THREAT-MODEL.md](THREAT-MODEL.md) for the full security model, and
[INSTALL.md](INSTALL.md) for per-host setup.

## Further Reading

Background on operating-system mechanisms for enforcing approval policies and
binary/credential protection:

- [Smack (Simplified Mandatory Access Control Kernel)](https://en.wikipedia.org/wiki/Smack_(software))
- [TOMOYO Linux](https://en.wikipedia.org/wiki/Tomoyo_Linux)
- [AppArmor](https://en.wikipedia.org/wiki/AppArmor)
- [pakkero (binary packer/protector)](https://github.com/89luca89/pakkero)

## Integration Patterns

Four credential types traced end to end — where `parzival` is inserted, the policy
decision it makes, how the secret is delivered, and what is still exposed afterwards:

| Pattern | Delivery | Replaces |
| --- | --- | --- |
| **SSH private keys** | `exec` + `ssh -i`, or `get` → `ssh-add -t` | durable keys under `~/.ssh/` |
| **AWS credentials** | `exec` → `AWS_SHARED_CREDENTIALS_FILE` | `~/.aws/credentials` + exported `AWS_SECRET_ACCESS_KEY` |
| **Gitea token** (`tea`) | `exec` → `XDG_CONFIG_HOME` dir | a shell wrapper's tmpfs config that lives for the whole boot |
| **OpenBao tokens** | `exec` → `$HOME/.vault-token` | `export BAO_TOKEN=$(cat …)` in every script |

Each pattern states its own limitations, including where a credential still has to exist
on tmpfs while the command runs, and which patterns are not yet adopted on any host. The
full worked integrations (SSH keys, AWS, Gitea, OpenBao) are kept in the project's private
documentation; the table above is the public summary.

## Related Documentation

- [INSTALL.md](INSTALL.md) — installing and deploying `parzival` and `parzival-broker`
- [MANUAL.md](MANUAL.md) — the user-facing operational guide: `get`/`exec`/`mount`/`service`, policy
- [THREAT-MODEL.md](THREAT-MODEL.md) — the full security model and what it does and does not defend against
- [SERVICE-PROTOCOL.md](SERVICE-PROTOCOL.md) — the broker service protocol, for a client that
  must use a credential without being able to read it

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Created by Kevin P. Inscoe (kevin.inscoe@gmail.com).
Copyright 2026 Kevin P. Inscoe.
