# Theory of Operation and Rationale — Parzival (`parzival`)

> Companion to [THREAT-MODEL.md](THREAT-MODEL.md) (what the design does and does
> not defend against). This document explains *how* `parzival` fetches a secret and *why* it
> is built the way it is — in particular why the store backends **shell out** to
> the existing CLIs (`bao`, `op`) instead of talking to their APIs directly.

## What `parzival` does

`parzival` is a runtime credential-delivery bridge. It fetches a secret from an
encrypted store **only at the moment of use** and hands it to the consuming tool
through the most secure interface that tool supports (see the delivery-mechanism
tiers in THREAT-MODEL.md). The primitive every other command builds on is
`parzival get <ref>`, which streams the secret to stdout or an inherited
file descriptor (delivery **tier 2**).

## Secret reference syntax

A secret is addressed by a self-describing reference; the scheme prefix selects
the backend. No config file is required for `get` — the reference is complete.

| Backend | Reference form | Example | Executes |
| --------- | ---------------- | --------- | ---------- |
| OpenBao (KV v2) | `bao:<mount>/<path>#<field>` | `bao:app/gitea#token` | `bao kv get -field=token -mount=app gitea` |
| 1Password | `op://<vault>/<item>/<field>` | `op://Private/Gitea/token` | `op read --no-newline op://Private/Gitea/token` |
| gopass | `gopass:<path>` | `gopass:web/gitea` | *(not yet implemented)* |

Reusing 1Password's own `op://` reference means `op read` consumes it verbatim —
no translation layer.

## The `Store` seam

All backends implement one interface (`internal/store`):

```go
type Store interface {
    Name() string
    Capabilities() Capabilities
    Get(ctx context.Context, ref SecretRef) ([]byte, error)
}
```

The CLI parses a reference (`ParseRef`), resolves it to a `Store` (`Resolve`),
calls `Get`, writes the raw bytes to the chosen output, then zeroes the buffer.
Because every backend hides behind this interface, the decision below (shell out,
broker-auth HTTP, or another native mechanism) is an implementation detail of each backend,
not a property the rest of the program depends on. `Capabilities` makes the important
security difference visible: an ambient CLI-auth backend is useful, but not equivalent to
non-ambient broker auth with scoped backend policy and audit.

## Backend authentication modes

Parzival supports two shapes.

**Ambient CLI-auth compatibility mode** launches the existing backend CLI and reads the
secret from stdout. The 1Password backend launches `op read`. OpenBao can launch `bao kv
get`. Parzival orchestrates tools you have already configured, which is convenient for
interactive use and keeps dependencies small.

**OpenBao AppRole broker-auth mode** is the reference unattended mode. Parzival reads an
AppRole SecretID from a bootstrap provider, logs in to OpenBao over the HTTP API, receives a
short-lived token, and uses that token internally for KV reads. The caller does not receive
or share that store credential.

Set:

```bash
PARZIVAL_OPENBAO_AUTH=approle
BAO_ADDR=https://bao.example
PARZIVAL_OPENBAO_ROLE_ID=...
PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential
```

Development/test providers also exist: `env` reads `PARZIVAL_OPENBAO_SECRET_ID`, and `file`
reads `PARZIVAL_OPENBAO_SECRET_ID_FILE`. They are not production protection mechanisms.

"Shell out" here does **not** mean invoking a shell (`/bin/sh -c "…"`). The
binary is `exec`'d directly with an argv array (Go's `exec.Command`), so no shell
interprets the reference — the classic shell-injection class simply does not
exist. Only the field name, mount, and path go on the argv; the secret value
never does (neither `bao` nor `op` takes the secret on argv for a read).

### The data path

Ambient OpenBao compatibility mode:

```text
OpenBao server ──TLS──> `bao` child ──stdout──> OS pipe ──> parzival []byte ──> stdout/fd ──> consumer
                        (child memory)          (kernel RAM)                    (zeroed after write)
```

AppRole broker-auth mode:

```text
bootstrap provider ──> SecretID ──> parzival HTTP login ──> short-lived token ──> OpenBao KV ──> parzival []byte
                         (zeroed)                         (zeroed after read)
```

In both cases the fetched secret is returned as `[]byte` and zeroed after delivery. AppRole
mode removes the caller's ambient `bao` token from the path; that is what closes the direct
store bypass described in THREAT-MODEL.md §6b.

### Why keep CLI mode at all?

1. **Interactive auth is still hard, and the CLIs already solved it.** For 1Password and
   interactive OpenBao use, the CLI may already handle session state, unlock, namespaces,
   and user prompts.
2. **It matches the prior art.** The existing `tea`/OpenBao wrapper and the
   `dlogin` migration already do exactly `bao kv get -field=… | …`. `parzival
   get` is that pattern generalized and made testable — a faithful
   reimplementation, not a new mechanism to validate.
3. **Fewer dependencies, smaller trust surface.** No OpenBao/Vault or 1Password SDK is
   vendored. The OpenBao AppRole path uses the standard library HTTP client.
4. **The interface hides the choice.** Changing how a backend authenticates touches the
   backend, not every caller, because `Store.Get` is the seam.

### The real trade-offs

- **Ambient CLI mode requires the CLI on `PATH`.** `parzival` cannot fetch through that mode
  on a host without the backend CLI. AppRole mode does not require `bao`.
- **Ambient CLI mode spawns a process per fetch.** Negligible for interactive and `exec` use;
  AppRole mode avoids this for OpenBao.
- **Coarser error typing.** We get the child's exit code plus its stderr, not a
  typed API error in CLI mode. `parzival` captures the CLI's stderr, surfaces it only on
  failure, and wraps a non-zero exit in a clean `parzival:` error.
  Verified in practice: a `bao` 403 surfaces `bao`'s own "permission denied" text,
  then `parzival: openbao: fetch "…" via bao: exit status 2`.
- **You trust the child not to leak.** `bao`/`op` could in principle log or cache;
  they are the tools you already chose to hold these secrets, so this adds no new
  trust.

**Net:** CLI mode remains useful compatibility behavior. OpenBao AppRole mode is the
stronger unattended path because Parzival authenticates with a broker-owned identity callers
do not share.

## Output hygiene

- The secret is kept as `[]byte`, never a `string` (strings are immutable and
  cannot be wiped), and the buffer is zeroed after the write (best effort — see
  THREAT-MODEL.md on why in-process erasure is not a guarantee).
- Exactly the store's bytes are written, with **no added newline**. `bao -field`
  appends one trailing newline to a pipe, which the OpenBao backend trims;
  `op read --no-newline` never adds one.
- `--fd N` writes to an inherited file descriptor instead of stdout, for callers
  that want the secret out-of-band from normal output.

## `parzival exec` — RAM-file delivery (tier 4)

Many tools cannot read a credential from stdin or an fd; they insist on a file at a
path. `exec` serves them without ever writing plaintext to persistent disk:

1. **Fetch** — each secret named in the profile is retrieved through the same
   `store.Get` used by `get` (so `exec` inherits the shell-out backends and their
   auth for free).
2. **Render** — the profile's `text/template` is filled with the secret values
   (`missingkey=error`, so a typo fails loudly rather than emitting a blank).
3. **Stage on tmpfs** — the output is written to a `0600` file inside a private
   `0700` directory under `$XDG_RUNTIME_DIR/parzival` (fallback
   `/dev/shm/parzival-<uid>`). Both are RAM-backed; nothing touches persistent disk.
4. **Point the tool at it** — the file's path is exposed three ways so the profile
   author can match whatever the tool expects: as `$PARZIVAL_CRED_FILE`, as the
   profile's `inject.env` variable, and substituted for any `{{cred}}` token in the
   command's argv.
5. **Run and wipe** — the child runs with inherited stdio; on exit the file is
   zeroed and the directory removed. Cleanup also runs on `SIGINT`/`SIGTERM` (a
   signal handler), because a `defer` alone would be skipped if the process is
   killed — and a leftover plaintext credential is exactly what the tool exists to
   prevent. The child's exit status is propagated as parzival's own.

**Why JSON profiles.** The profile format is JSON (`encoding/json`, stdlib) rather
than TOML/YAML, keeping the dependency tree empty — the same "small trust surface"
value that motivates shelling out. The cost is a less friendly multi-line-template
syntax, judged acceptable for a handful of short profiles.

**One honest caveat.** `text/template` requires the secret as a `string` during
rendering, and Go strings are immutable and cannot be zeroed. The source `[]byte`
and the rendered output buffer are both zeroed after use, but the transient string
copies made inside template execution are left to the garbage collector. This is a
small, bounded relaxation of the "keep secrets as `[]byte`" rule, localized to
rendering.

## How to build and verify

```bash
# From the repo root
go build ./...      # compile everything
go vet ./...        # static checks
go test ./...       # unit tests (hermetic; no live bao/op needed)

# Try the CLI
go run ./cmd/parzival --help

# Live fetch (needs an authenticated `bao` token). Byte count only — never
# print the secret value to a terminal:
go run ./cmd/parzival get 'bao:app/gitea#token' | wc -c
```

The unit tests substitute a fake command runner (`runner` interface in
`internal/store/exec.go`), so backend behaviour — argv construction and
newline trimming — is verified without spawning `bao` or `op`.
