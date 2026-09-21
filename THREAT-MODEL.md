# THREAT-MODEL.md — Parzival (`parzival`)

> `parzival` is a runtime
> credential-delivery bridge: it fetches a secret from an encrypted store only at
> execution time and hands it to a consuming tool through the most secure interface that
> tool supports. This document states what that design does and does not defend against,
> so the guarantees are on record rather than re-discovered.

## The core truth (why this is bounded)

A secret **must** become plaintext at the point of use — the consuming tool needs the
cleartext bytes in its own memory to do its job (e.g. `tea` sends
`Authorization: token <PLAINTEXT>` over TLS). No scheme avoids this. The design goal is
therefore **not** "never plaintext" — it is:

> plaintext for the shortest time, in the fewest copies, on volatile memory only,
> wiped immediately after.

Every claim below is bounded by that truth. `parzival` shrinks the exposure window and the
number of copies; it cannot make a secret usable without also making it stealable by
anyone who already controls the point of use.

## Assets

| Asset | Where it lives | Why it matters |
| ------- | ---------------- | ---------------- |
| Consumer secrets | store backend at rest; volatile RAM at use | the credentials being brokered |
| Secret-zero / store auth token | broker process memory (ideally a separate uid) | unlocks the whole store if stolen |
| Approval policy | config on disk | defines who may fetch what, when |
| Audit log | disk | after-the-fact accountability |

## Trust boundaries

```text
[store backend] --auth--> [parzival broker] --policy check--> [delivery adapter] --RAM/pipe/fd--> [consuming tool]
   at rest                separate uid?                   tier 1..5                          plaintext in use
```

- **Store ↔ broker** — authenticated by the store (OpenBao token / AppRole / JWT, `op`
  session, gopass GPG). The broker holds a live store credential; protecting it is
  paramount (run as a separate uid — see below).
- **Broker ↔ consumer** — the delivery adapter. This is where caller identity is checked
  and where plaintext crosses into a process the broker does not control.
- **Host boundary** — root and the kernel are trusted. `parzival` does not defend against a
  compromised host; see out-of-scope.

## Adversaries and what `parzival` does about each

### 1. Secret at rest on persistent storage — ✅ defended

Plaintext credentials in dotfiles, config dirs, scripts, backups, git commits, file-sync,
Time Machine. This is the primary threat `parzival` exists to kill.

- **Mitigation:** secrets live encrypted in the store; `parzival` fetches only at runtime and
  delivers to volatile RAM (tmpfs / `$XDG_RUNTIME_DIR` / `/dev/shm`, macOS RAM disk) or a
  stream (stdin / fd / pipe). No long-lived plaintext ever touches persistent storage.
- **Residual:** requires swap to not page RAM plaintext to disk — see per-host hardening.

### 2. Other non-root local users — ✅ defended

- **Mitigation:** delivery directories `0700`, files `0600`; secrets in per-user
  `$XDG_RUNTIME_DIR` / RAM disk. A different uid cannot read them by filesystem permission.

### 3. Secret lingering after use / broadcast to children — ✅ defended

- **Mitigation:** single-consumer model — one fetch, one delivery, then wiped (`parzival exec`
  cleanup trap; FUSE serves on demand and never persists). No caching. Environment-variable
  injection, when unavoidable, is scoped to a single child process, never exported broadly.

### 4. Same-uid process during the exposure window — ⚠️ partial, needs OS hardening

Any process running as the **same uid** as the consumer can read the consumer's memory
(`ptrace`, `/proc/<pid>/mem`, debugger) or the RAM-backed file during the window. This is
the fundamental limit of same-privilege delivery: once the secret is in the consumer's
address space, verifying *how it got there* does not stop a co-resident same-uid process
from taking it.

- **Mitigations (defense-in-depth, not a guarantee):**
  - `kernel.yama.ptrace_scope = 1` (or higher) — restrict `ptrace` to parent→child.
  - Run the **broker as a separate uid** so its long-lived store token is not in a process
    the normal account can `ptrace`.
  - Shrink the window — streaming (tier 2) and FUSE lazy-fetch (tier 3) beat a resident
    RAM file (tier 4); wipe immediately.
  - Real isolation (separate uid / namespace / container per consumer identity) closes it;
    see *Consumer attestation* below.
- **Residual:** a same-uid RAT on a host without this hardening can capture a secret in
  flight. Accepted and documented, not silently ignored.

### 4b. Accidental disclosure to a recording sink — ⚠️ partly defended, tier-dependent

Not an adversary at all — the ordinary operator, or an automated agent, causing the value to
be **written somewhere durable that nobody thinks of as a secret store**: a log file, a CI
job's captured output, terminal scrollback, an error message, a crash dump, or an **AI
agent's context and session transcript**. This is distinct from every threat above: it needs
no attacker, it is the most probable leak in practice, and unlike an in-flight capture the
copy is *permanent* and readable by whoever later reads the log.

The AI case is the sharpest and is not hypothetical. An agent that runs a raw fetch puts the
value into its own context, then the model provider, then the terminal, then any on-disk
session log the launcher keeps — several durable copies from a single command, none of them
on the host's threat radar.

**What is defended:**

- **Never logged by `parzival` itself.** The audit trail records ref, identity, decision and
  reason — never a value. Verified by piping a real secret into `grep -F` against the log.
- **No error path embeds command output.** The backends never use `CombinedOutput`, so a
  failing `bao`/`op` cannot splatter the value into an error string.
- **Never on argv** — so it cannot be harvested from `ps` or `/proc/<pid>/cmdline`, both of
  which routinely end up in diagnostics and process logs.
- **Tiers 3 and 4 avoid a broker-created stream disclosure.** `mount` and `exec` place the value
  in a `0600` RAM file rather than writing it to `parzival`'s stdout. This reduces accidental
  transcript capture when the intended consumer cooperates; it does not bind the credential to
  that consumer or confine another same-uid process that can read its file or memory.

- **`get` is refused outright in a detected AI agent shell.** When the
  environment carries a known agent marker — `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
  `CURSOR_AGENT`, `CODEX_SANDBOX`, `AI_AGENT`, or the explicit `PARZIVAL_AGENT` — `get`
  refuses before the fetch, regardless of `--fd`, with no override flag and no override
  variable. See *The honest agent* below for why this needed enforcing rather than
  documenting, and `internal/agent` for what it keys on.

**What is not:**

- **Tier 2 (`get`) hands the raw value to stdout or a caller-supplied fd — by construction.**
  `parzival` cannot distinguish "piped into the consumer that needs it" from "piped into a
  log," and today does not try. `get X > cred.txt` and `get X | tee -a build.log` are
  indistinguishable to the broker. The third case that used to sit in this list — an agent
  running `get` in a recorded session — is now refused rather than undetectable, but only
  where the harness is recognised.
- **Backend stderr is passed through** (`internal/store/exec.go`). `bao`/`op` do not print
  secrets there in normal operation, but a verbose mode or an unexpected error format would
  reach the terminal and any capturing log.
- **The consumer's own logging is out of scope.** Once `curl -v`, a debug flag, or a stack
  trace has the credential, no broker can recall it.

**Direction (Phase 2b), now shipped as the rule-level `modes` field:** make the safer raw-read
path enforced rather than advised — a rule may permit `exec`/`mount` but deny raw `get`. This
prevents the common accidental transcript leak in a recognised agent shell; it does not itself
bind delivery to a trusted consumer or make a credential structurally unreadable by a same-uid
agent.

#### The honest agent — why a documented intention was not enough

A policy that only *describes* who is trusted with a raw value, without enforcing it, fails
against exactly the caller who needs no attacker: an automation identity with a real,
on-task reason to ask "would this fetch succeed?" that has no way to ask except by actually
fetching and seeing the plaintext. `--as` is self-asserted, so a policy rule scoped to "this
identity never runs where a transcript is captured" describes an intention, not a boundary
— any caller that can legitimately assert that identity for an unrelated reason inherits the
same access, transcript included.

**This is not the adversary the self-assertion note above describes.** That note is about a
same-uid attacker forging a label, and it is correctly accepted as out of scope. This is an
*honest* caller asserting a *real* identity for a *good* reason, and it is much more
probable: it needs nobody to be malicious and no boundary to fail.

Two properties make this failure mode near-inevitable rather than merely possible:

1. **If the only tool that answers a question also discloses the answer**, any operator who
   needs to confirm a fetch would succeed is forced to run the disclosing form to find out.
2. **A control that depends on the caller remembering to redirect output is a habit, not a
   mechanism**, and disciplines fail under repetition — a redirect that must be typed
   correctly every single time eventually isn't.

The fix had to address both, and either half alone would have failed:

- `parzival probe` answers the question without returning the value, so the legitimate need
  has a non-disclosing tool. Refusing `get` without this would have removed the leak and
  left the need, which is how a control gets worked around.
- `get` refuses in a detected agent shell, so the safe path is the enforced one rather than
  the remembered one. There is no override — no flag, no environment variable — because a
  bypass an agent can type is a bypass an agent will type, and the refusal only has value
  while the process being refused cannot argue past it.
- `policy validate` reports the union of labels that reach raw `get` anywhere in the
  policy, so the exposure is visible before it is discovered by leaking something.

**The refusal is a mistake-prevention control, not a boundary, and the distinction is
load-bearing.** It keys on environment variables, so anything that can unset one defeats
it — which is consistent with the rest of this document, where a same-uid process bypasses
`parzival` entirely. It is aimed squarely at the case that actually happened. The marker
list is also not claimed to be exhaustive: a harness that sets none of them is not
detected, which is why `PARZIVAL_AGENT` exists as a self-declaration and why `policy
validate`'s finding matters independently.

**Two limits on that control, both learned in practice and neither obvious:**

1. **A `modes` restriction is only as strong as the loosest rule matching the same secret.**
   Rules are first-match-wins over the whole list, and `--as` is **self-asserted** (above). If
   `bao:app/gitea#*` has a restricted `ai` rule *and* an unrestricted `tea` rule, a caller
   simply passes `--as tea` and takes the raw value — the restriction is decorative. This is
   structural to any policy where a restricted identity coexists with an unrestricted one on
   the same ref, not a bug in a particular rule. **When adding a `modes` rule, audit every
   other rule that matches that ref.** Accepted as a known limit under the non-hostile-local
   assumption; it is a mistake-prevention control, not a boundary.
2. **It fails open when the binary lags the policy file.** A `parzival` binary built before a
   given policy field existed drops that field silently, so the rule degrades to matching on
   ref and identity alone and permits `get`. Nothing warns. This is the reverse of the
   deny-by-default posture the rest of this document assumes, and it is invisible unless you
   test the call you expect to be refused. The binary guards against this going forward — an
   unknown field, or a policy schema newer than the one it understands, is refused outright
   rather than silently ignored — but that protection is only as good as the binary actually
   running: rebuild after every upgrade, before trusting a new policy field.

### 4c. App-internal secrets the consumer persists itself — ❌ outside the broker model

A distinct class, worth naming because it looks like `parzival`'s problem and is not.

- **Category A — brokered credentials.** The secret exists *before* the consumer, lives in a
  store, and is handed over at runtime. There is a delivery event, and `parzival` sits in
  front of it. Everything else in this document assumes Category A.
- **Category B — app-internal secrets.** The application **generates** the secret, **persists**
  it, and reads it continuously thereafter: session-signing keys, DB encryption keys, OAuth
  client secrets it issues to itself. **There is no delivery event for `parzival` to sit in
  front of.** The broker cannot intercept a value the consumer creates for itself and writes
  to its own storage.

`parzival` has no mitigation for Category B in place, and should not pretend otherwise.
Worked example on this fleet: the `reader` service (`ghcr.io/babarot/oksskolten`) stores
`settings.system.jwt_secret` as plaintext in its SQLite DB. Anyone who reads that file can
forge a session token for any user. `parzival` cannot help, because the app never asks anyone
for that value.

**What actually works, in order of completeness:**

1. **Eliminate the persistence (complete, needs upstream).** If the app accepts the secret
   from an environment variable or a file at startup, the secret becomes Category A and
   `parzival` handles it normally — delivered at start, never written to disk. **Converting B
   into A is the only fix that removes the exposure**; everything below merely narrows it.
2. **Encrypt the volume, broker the unlock key (available now — see PLAN Phase 8).** The
   service's data directory lives on an encrypted volume; `parzival` supplies the passphrase
   at unlock. This fully protects the *offline* surface — backups, snapshots, disk images,
   stolen media — which is usually the larger one.
3. **File permissions.** Weakest, and easy to overrate. They do not survive an account with
   equivalent privilege: on a host where the primary user is in the `docker` group, a
   container mount reads any path as uid 0 regardless of DAC (verified empirically on a real deployment).
   They also routinely miss derived copies — the same fleet's `reader` backups stayed
   world-readable for six days after the data directory was hardened.

**The limit of encryption at rest, stated plainly.** A service that runs continuously holds
its data decrypted and mounted continuously. Encryption defeats the offline reader; it does
not defeat a live local reader with sufficient privilege. That is threat 4 again, and the
core truth at the top of this document: a secret cannot be made usable without being made
stealable by whoever controls the point of use. Encryption at rest and access control cover
*different* halves — neither alone is sufficient, and for Category B neither is complete.

**Detection is the realistic standing control.** Since Category B recurs whenever a new
self-hosted service is adopted, the durable practice is periodically auditing service data
directories and their backups for plaintext secrets, rather than expecting the broker to
prevent them.

### 4d. A client that must *use* a credential without being able to *read* it — ⚠️ defended on Linux, under stated assumptions

Threat 4 asks what a same-uid process can take during the exposure window. This asks
something narrower and more common: an AI coding agent, or any other untrusted local client,
legitimately needs an operation performed *with* a credential — list the repositories under a
Gitea owner — and must not be able to obtain the credential itself.

**The shipped CLI does not provide this, and must not be described as though it did.**

| Surface | Why it does not bound a client that wants the plaintext |
| --- | --- |
| `exec PROFILE -- COMMAND` | The **caller** chooses the command that receives the credential. A caller who can pick `tea` can pick `cat`, `env`, or a shell. |
| `mount MOUNTPOINT` | The rendered value is readable by whoever can `open()` the file, and the client is who opens it. |
| `get` refused in an agent shell (§4b) | Keyed on environment markers the client controls, and explicitly not exhaustive. Mistake prevention, never a boundary. |
| `policy.json` denying `get` | Advisory over a self-asserted `--as` label, on the same uid, with the store still directly reachable if the client has its own path (§6b). |

Each of those is a real control against an honest client making a mistake. None survives a
client that is trying.

**The broker service mode is the answer, and it works by moving the uid boundary rather than
by adding another check.** A broker daemon (`parzival-broker`) runs under its own dedicated
account; the client runs as itself; the client names an *operation*, never a command, and
receives only the operation's declared non-secret result. `SERVICE-PROTOCOL.md` specifies the
interface and `internal/consumer` defines the root-owned consumer definitions that say which
invocations exist at all. The broker is Linux-only — there is no macOS build yet.

**The boundary it claims:**

> A client that can reach the broker socket can request only approved, non-secret operations.
> It cannot read the broker's OpenBao authentication material, the rendered consumer
> configuration, the consumer process environment, or the consumer process memory.

**Which holds only under all four of these assumptions:**

1. The broker runs in a different uid, container, or MAC security domain from the client.
2. The client has no independent store credential and no direct read path to the store — §6b
   voids this the same way it voids every policy guarantee, and for the same reason.
3. The policy, profiles, consumer definitions, and consumer binaries are administrator-owned
   and not writable by the client identity. `consumer.VerifyTrustRoot` checks this, including
   every ancestor directory, and the broker refuses to start when it does not hold.
4. The approved consumer does not itself disclose the credential — in output, logs,
   configuration dumps, debug output, plugins, hooks, or a request to an attacker-controlled
   endpoint.

**What it still does not cover.** Root (§5). A compromised or careless trusted consumer —
assumption 4 is an assumption about *other people's code*, and it is the weakest of the four.
Another process sharing the consumer's security domain, which is threat 4 again, moved to the
broker's side of the boundary rather than removed. A legacy consumer that takes its credential
in an environment variable can be run inside the broker's domain, but nothing prevents code
that already possesses plaintext from disclosing it — no named pipe, file descriptor, profile,
or policy changes that, which is why such a consumer is treated as trusted code rather than as
a contained one.

**Status: implemented on Linux.** The broker daemon, its consumer-definition schema, and the
client (`parzival service`) all exist, are packaged for real installation, and are exercised
by automated tests. The honest answer to "can an agent be allowed to use the Gitea token
without reading it?" is **yes, on Linux, under the four assumptions above** — and **no**
anywhere the broker is not installed and configured, including macOS, where no build exists
yet.

### 5. Root on the host — ❌ out of scope

Root reads any memory, tmpfs, `/proc`, or swap. No userspace bridge defends against this.

- **Boundary:** if you need to defend against local root, the secret must never be
  plaintext in host RAM at all — that requires hardware (TPM-sealed, secure enclave,
  confidential-compute) and is outside `parzival`'s scope.

### 6. Compromised store backend / stolen store token — ❌ out of scope for `parzival`

If the OpenBao/1Password/gopass backend is compromised, or the broker's store credential
is stolen, the attacker has whatever that identity is authorized for. `parzival` reduces this
blast radius via least-privilege policy and a separate-uid broker, but backend integrity
is the backend's responsibility.

### 6b. A caller that can reach the store directly — ❌ every policy guarantee is void

**This is the most easily overlooked hole in the model, and it defeats the feature the
policy exists for.**

`parzival`'s intended control is that an identity restricted to `"modes": ["exec","mount"]`
can use a credential without the broker writing it to a raw stream. That reduction in accidental
disclosure has two preconditions:

- **The caller must not be able to reach the store on its own.**
- **The caller must not be able to replace, inspect, or cause the credential-consuming process to
  disclose the value.**

In compatibility mode, `parzival` shells out to `bao`/`op` and inherits their
authentication. That makes it a *gate in front of* the store, not a *gatekeeper of* the
store. Anything that can run `bao kv get` itself walks around the gate entirely. No policy
rule, no `modes` restriction, and no `parzival policy check` result has any bearing on it
— and nothing is written to `audit.log`, so the bypass is also invisible.

The stronger unattended OpenBao mode avoids that shape: `parzival` reads an AppRole
SecretID from a bootstrap provider, logs in to OpenBao itself, and uses the resulting
short-lived token only internally. The rule is backend-independent:

> **Callers must not share Parzival's store credential.**

The usual way this precondition silently fails is an **ambient store credential**: a
`BAO_TOKEN` exported into the login environment, or a readable token file the caller can
`cat`. Every descendant process then holds full store authority.

**Confirmed in practice, twice, on real deployments, in two different shapes of the same
underlying failure.** First: an exported store token in a login environment let an
automation caller retrieve a secret directly, bypassing every policy rule that restricted
`parzival`'s own delivery of that same reference — and the caller separately leaked the
token itself into its own output by expanding the environment variable. Second, after that
exported-token vector was closed on a different host by switching to the store CLI's own
default on-disk token cache: an automation caller ran the store CLI's own "verify my token"
command directly (not through `parzival`) to confirm the fix, and that command's own output
printed the token value into the caller's transcript. Removing the ambient-environment leak
path is necessary but not sufficient, because nothing stops an identity with an independent
path to the store from choosing a command whose own output includes the secret.

**What actually holds the line:**

| Control | Effect |
| --- | --- |
| **Use non-ambient broker auth where available.** OpenBao AppRole/JWT/OIDC mode gives Parzival a credential callers do not have. | Makes Parzival the only ordinary path to the store for that workflow |
| **Do not export the store credential.** `BAO_TOKEN` in a login shell gives every child direct store access. | Removes the ambient grant from every descendant process |
| **Do not leave a usable default token file.** A readable `~/.vault-token` lets raw `bao` bypass Parzival. | Closes the common default CLI helper bypass |
| **Scope the store credential itself.** An OpenBao policy that cannot read `app/gitea` makes the parzival rule redundant rather than decorative | The only control that survives a hostile caller |
| **Separate uid / namespace / container per identity** | The agent's own store credential differs from yours; see *Consumer attestation* below |

`parzival doctor` checks the common configuration failures, including `BAO_TOKEN`, a
readable `~/.vault-token`, policy load strictness, audit log writability, and whether the
OpenBao backend is still in ambient compatibility mode. **Treat a `modes` restriction as
meaningful only after confirming the caller has no independent path to the store.** Where
it does, the restriction documents intent — it does not enforce it.

## Consumer attestation — can a secret be bound to a recognized tool?

**Question:** can `parzival` guarantee a secret is delivered only to a recognized tool,
identified by executable path + SHA (or similar), on Linux/macOS?

**Answer: no — there is no portable, userspace, *guaranteed* mechanism.** Path + SHA is
useful **provenance, audit signal, and a speed bump**, never a guarantee, and `parzival` must
not present it as one. Three holes keep the hash advisory:

1. **Same-uid is the wall.** Once the secret is in the recognized consumer's memory, any
   same-uid process can extract it regardless of how perfectly the consumer was verified.
   Verifying the image gates *delivery*; it does not stop theft *after* delivery (threat 4).
2. **Interpreters make the hash meaningless.** For `python` / `node` / `bash` / `java` the
   interpreter's SHA proves nothing — it runs arbitrary scripts. This defeats path+SHA for
   `parzival`'s primary consumers (AI agents = python/node).
3. **TOCTOU.** PIDs are reused; there is a window between reading the caller pid and hashing
   its image. Mitigable (verify + deliver on the same connection, no re-exec between check
   and delivery) but never zero in pure userspace.

### Where a real guarantee can come from — only by leaving userspace

| Mechanism | Platform | Strength | Caveat |
| ----------- | ---------- | ---------- | -------- |
| `SO_PEERCRED` → hash `/proc/<pid>/exe` | Linux | kernel-authoritative uid/pid; the legitimate way to *do* the path+SHA check | stays advisory (holes 1–3) |
| **SELinux / AppArmor (MAC)** | Linux | enforces "only *this domain*, entered via *this labeled binary*, may read the secret"; blocks cross-domain `ptrace` (closes hole 1) | doesn't solve interpreters — a confined `python_t` runs any script |
| **Separate uid / namespace / container per identity** | Linux/macOS | robust, portable structural fix; a *container image* SHA becomes meaningful; isolation is real, not advisory | operational overhead per identity |
| **XPC + audit token + `SecCodeCheckValidity`** | macOS | kernel-backed cryptographic *dynamic* code identity; hardened runtime blocks debugger/injection (mitigates hole 1) | only for signed hardened Mach-O apps; unsigned scripts get weak identity; signed `python` still runs any script |

### Consequences for `parzival`

- The caller-identity check (`SO_PEERCRED` → `/proc/<pid>/exe` path+SHA, cmdline) is
  **provenance + audit + a speed bump**. Log it, gate on it, never rely on it as a guarantee.
- Real enforcement lives in an OS isolation primitive: SELinux/AppArmor domains (Linux),
  code-signing requirements (macOS), or — cleanest and most portable — a **separate uid /
  namespace / container per identity**.
- OpenBao itself does **not** do binary attestation — it authenticates token / AppRole / JWT
  *identities*. Any "which binary is asking" logic is something `parzival` layers on top and
  inherits every limit above.
- For interpreted consumers (AI agents), image identity is **unattestable**; isolation,
  not hashing, is the only control.

## Approval policy — what it is and isn't

`parzival` gates every fetch behind a strict deny-by-default policy (`policy.json`) keyed
to the secret reference, a self-asserted identity label (`--as` / `$PARZIVAL_IDENTITY`),
and time, and it appends every decision to an audit log.

**What it genuinely provides:**

- **Mistake-prevention** — a fat-fingered or mis-scoped request for a secret no rule
  allows is refused rather than silently served.
- **Blast-radius scoping** — a given workflow/agent label is granted only the references
  its rules name, on the days/hours they name.
- **Provenance + audit** — an append-only record of which reference was requested, under
  which label, when, and whether it was allowed. Values are never logged.

**What it explicitly does NOT provide:**

- **It is not an authentication boundary.** The identity is *self-asserted* — any caller
  can pass `--as anything`. It scopes honest callers and records claims; it does not
  verify them (consistent with *Consumer attestation* above — self-assertion, not proof).
- **It does not stop a same-uid attacker.** A co-resident same-uid process can ignore
  `parzival` entirely (call `bao`/`op` directly) or read a secret out of the consumer's
  memory after delivery (threat 4). The policy governs requests made *through* parzival,
  not access to the underlying store or to delivered plaintext.
- **It is advisory, enforced in userspace.** Real confinement still comes from the OS
  isolation primitives in *Consumer attestation* (separate uid / MAC / code-signing).

Treat the policy as a scoping-and-audit layer over honest automation, not as a control
that withstands a local adversary.

## Per-host hardening requirements

`parzival` should check and document these on every host it runs on:

- **Swap must not leak plaintext.** Require zram (e.g. `/dev/zram0`), encrypted swap,
  or no swap; **disable hibernation**. Plain disk swap can page a tmpfs token to disk,
  defeating threat 1.
- **`kernel.yama.ptrace_scope = 1`** (or higher) — restrict `ptrace` to parent→child
  (threat 4). Persist it in a `sysctl.d` drop-in rather than setting it only for the
  current boot.
- **Run the broker/Agent as a separate uid** — keep its long-lived store token out of any
  process the normal account can `ptrace` (threats 4, 6).
- **SELinux enforcing** (Linux) where available — enables MAC-based delivery confinement.

## Secret-zero bootstrap

The broker's own credential to the store is the root of trust; if it is a plaintext file on
disk, threat 1 reappears one level up.

Secret zero is not a brokered secret. Parzival never returns it to a caller, never logs it,
never renders it into a profile, and never exposes it through `get`, `exec`, or `mount`.
It is only used internally to authenticate Parzival to its backing store.

Chosen direction:

- **No machine-binding requirement.** Rotation, audit, and least privilege are the accepted
  mitigation for stolen bootstrap material.
- **OpenBao is the reference unattended backend.** AppRole/JWT/OIDC-style broker identity
  gives Parzival non-ambient store auth, scoped store-side policy, short-lived tokens, and
  backend audit.
- **Other stores remain valid by capability.** Interactive stores can still satisfy runtime
  delivery and encrypted-at-rest goals where their weaker direct-access guarantees are
  acceptable.

**Reference implementation.** A deployment's bootstrap credential should never be a
plaintext, non-expiring token sitting on disk (or, worse, ever committed to a repository's
history) — that reintroduces threat 1 one level up from the secrets Parzival is meant to
protect. The reference deployment instead authenticates via a scoped AppRole, with the
SecretID protected at rest via an OS-level encrypted-credential mechanism and decrypted only
on demand, never exported into an environment. A deployment-side config fallback (rather
than requiring every caller to source the same interactive shell startup file) ensures
non-interactive callers — cron, a systemd unit, an AI agent's own tool shell — authenticate
the same way an interactive session does, rather than silently falling back to a weaker
ambient mode when they don't happen to inherit shell rc state.

**Break-glass is a human-only override, structurally outside the broker's own request
path.** The invariant is that *Parzival defines the maximum OpenBao authority available to
automation and AI, and a break-glass mechanism is a human's own override of that boundary* —
never invoked by Parzival itself, never callable as a backend or fallback by any program,
and independent of any other privilege (e.g., an agent holding sudo/root for OS
administration does not thereby hold break-glass authority). For a break-glass path to be a
real boundary rather than an advisory one, it must verify an actual human is present at
the moment of use — not merely that some process asserts a human identity. Properties worth
enforcing in any such mechanism: the real (not merely effective) human user id, an actually
open controlling terminal (piped/redirected stdio elsewhere should not defeat this — a
recording pty can satisfy a naive TTY-only check without a human actually present, so an
independent liveness signal such as a live out-of-band sign-in is stronger), and an explicit
confirmation with no unattended/non-interactive override. A credential minted for such a
tool should never be passed as a literal command-line argument (argv is visible host-wide via
the process table for the credential's entire lifetime) and any endpoint/address it
authenticates against should be pinned rather than environment-overridable, so a caller
cannot redirect the flow to a host they control and harvest the credential in transit.

**Terminal disclosure is a separate control from authorization, and needs its own allowlist.**
Verifying a human is present decides whether a privileged operation may *execute*; it says
nothing about whether that operation's *output* may be shown. A break-glass wrapper typically
passes an arbitrary subcommand through to the underlying secrets CLI and inherits its stdout, so
whatever that CLI prints — a policy body, or a freshly minted credential — reaches the terminal
and the scrollback identically. The wrapper cannot tell them apart by inspection.

The defensible shape is an **allowlist that fails closed**: only operations explicitly classified
as producing non-secret output print their stdout; everything else still executes but has its
output withheld. Two properties matter more than the list itself. First, classify by **exact
command shape, not by top-level noun** — a subcommand added later under an otherwise-safe verb
must default to blocked rather than inheriting its parent's classification. Second, provide **no
escape hatch**: a flag or environment variable that restores raw output for an unclassified
operation defeats the control precisely when it matters. A newly unsupported administrative
command is an inconvenience; a newly introduced credential-returning command printing plaintext
is a security failure.

Note that several operations that *look* administrative return credential material: minting a
SecretID for a role, creating a token, and initialising or unsealing a store all return live
credentials, and looking up a token typically prints the token's own id.

**Credential material must not be supplied on argv either**, and this is an independent exposure
rather than a consequence of anything being printed: an argv element is visible host-wide through
the process table for the life of the process, and is written to shell history. A wrapper that
accepts `key=value` pairs should refuse a literal value wherever the value could be secret, and
direct the caller to the CLI's stdin form instead.

**Residual risk: plaintext in volatile process memory at the point of use.** A break-glass
wrapper implemented as a shell script necessarily holds three values in ordinary, unexported
shell variables — the AppRole SecretID it authenticates with, the login response, and the
resulting token. They are never intentionally printed, tracing is disabled before any of them
exists, and they are unset promptly after use. Being shell variables, the SecretID and the login
response are **not** exposed through `/proc/<pid>/environ`; the token is deliberately placed in
the environment of the single child process that needs it, and that child environment is the
accepted residual exposure.

Rewriting this portion in a compiled or interpreted language would move the plaintext from
shell-managed memory to that runtime's managed memory. **It would not eliminate the fundamental
fact that authentication requires the credential to exist in plaintext in volatile process memory
at the point of use.** The requirement is therefore stated as: secrets must not be placed in
argv, logs, terminal output, trace output, persistent files, or unnecessary environments;
temporary plaintext in volatile process memory at the point of use is accepted.

## Summary of guarantees

| Threat | Status |
| -------- | -------- |
| Secret at rest on persistent disk / backups / sync | ✅ defended |
| Other non-root local users | ✅ defended |
| Secret lingering after use / child broadcast | ✅ defended |
| Same-uid process during the window | ⚠️ partial — needs ptrace/separate-uid/isolation hardening |
| Binding delivery to a specific recognized binary | ⚠️ advisory only — real teeth require OS isolation |
| Approval policy (scoping + audit of requests) | ⚠️ advisory — self-asserted identity; scopes honest callers, not a same-uid adversary |
| Raw `get` reaching an AI agent's transcript | ⚠️ partial — refused in a *detected* agent shell with no override; an unrecognised harness is not detected (§4b) |
| **Client that must use a credential without reading it** | ⚠️ **defended on Linux** — the broker service mode of §4d, under its four stated assumptions; no macOS build yet |
| Break-glass printing credential material to a terminal | ✅ defended — allowlisted, fail-closed terminal output; classify by exact command shape, no escape hatch |
| Credential supplied on argv (process table, shell history) | ✅ defended — literal values refused where they could be secret; CLI stdin form instead |
| Plaintext in volatile process memory at the point of use | ⚠️ accepted residual — inherent to authentication; a language change relocates it rather than removing it |
| Root on the host | ❌ out of scope (needs hardware) |
| Compromised store backend / stolen store token | ❌ out of scope (backend's responsibility) |
| **Caller with its own path to the store** (ambient `BAO_TOKEN`, readable token file) | ❌ **every policy guarantee is void, and the bypass is unaudited** — see §6b |

## Related documentation

- [`README.md`](README.md) — project overview and rationale.
- [`INSTALL.md`](INSTALL.md) — installation, deployment, and per-host setup.
- [`SERVICE-PROTOCOL.md`](SERVICE-PROTOCOL.md) — the broker service protocol (§4d), and the
  interface the no-plaintext-to-the-client boundary rests on.
