## v0.1.0-pre.2 — first public prerelease

This is Parzival's first public prerelease: **pre-1.0**, and the interfaces, policy
format, and configuration layout may still change before a stable `v1.0.0`. The CLI and
the broker service are both implemented and exercised against real deployments, not
just designed — this tag is about making that work installable, not about declaring it
finished.

Parzival is a credential broker: it fetches a secret from an encrypted store only when
a command needs it, hands it to that command through the safest interface it supports,
and wipes the temporary copy afterward. Four goals drive the design:

1. **Authorization** — every fetch is checked against a deny-by-default policy before
   the store is queried. Only approved callers, tools, and operations may use approved
   secrets, and every decision is written to an audit log.
2. **AI credential containment** — an AI agent can use a credential through `exec`,
   `mount`, or a broker operation without ever receiving the raw value in its own
   stdout, transcript, or tool output. Raw `get` is refused outright inside a detected
   AI-agent shell, with no override.
3. **No persistent plaintext** — credentials are retrieved at runtime and delivered
   through a stream, a RAM-backed file, or another ephemeral mechanism, never written to
   an ordinary plaintext credential file.
4. **Auditability** — every authorization decision and broker operation is logged
   (identity, reference, result) without ever logging the secret value itself.

### What's included

- **`parzival get`** — streams a secret to stdout or an inherited file descriptor.
- **`parzival probe`** — confirms a fetch would succeed without ever returning the value.
- **`parzival exec`** — renders secrets into a RAM-backed file for one command, then
  wipes it.
- **`parzival mount`** (Linux) — serves profile credentials as read-only virtual files,
  re-fetched on every open.
- **`parzival service`** — a client for the broker daemon, for callers that must *use* a
  credential without ever being able to *read* it.
- **`parzival-broker`** (Linux only) — a packaged systemd service exposing a small, fixed
  set of consumer operations over a Unix socket.
- **Policy tooling** — `policy check`, `policy validate`, `policy what-if`, `policy
  grant`, and `policy apply` for inspecting and safely editing the approval policy.
- **OpenBao** is the reference backend for unattended use (ambient `bao` CLI mode or
  AppRole broker-auth mode); 1Password is supported for interactive workflows.

### Packages

- **RPM** and **DEB** packages for the CLI and, on Linux, the broker service.
- **Homebrew cask** for macOS (Apple Silicon).
- **SBOMs** (SPDX, via Syft) for every published binary.
- Release checksums are signed keylessly with **Sigstore/cosign** through GitHub Actions
  OIDC, providing verifiable integrity for the published artifacts without maintaining a
  signing key — verify offline with `cosign verify-blob --bundle=`.

### Known limits at this stage

- macOS ships the CLI only — there is no macOS build of `parzival-broker`.
- `gopass` and KeePassXC backends are named in the design but not implemented yet.
- This is a prerelease: expect interface and configuration changes before `v1.0.0`.

See [README.md](README.md), [INSTALL.md](INSTALL.md), [MANUAL.md](MANUAL.md), and
[THREAT-MODEL.md](THREAT-MODEL.md) for the full design, installation, usage, and
security model.
