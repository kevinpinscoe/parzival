# packaging/

Source for installing the `parzival-broker` daemon as a real systemd service via the RPM/DEB
packages `.goreleaser.yml`'s `nfpms:` block produces. **Nothing in this directory is applied
automatically by being in the repo** — it only takes effect once installed, whether by hand
or via the packaged install. See the repo root's [`INSTALL.md`](../INSTALL.md) for the full
procedure.

## Contents

- `systemd/parzival-broker.service` — the daemon's own unit: dedicated service account,
  root-owned trust-root files via `ConfigurationDirectory=`/`StateDirectory=`/
  `RuntimeDirectory=`, the `systemd-credential`-provider OpenBao AppRole bootstrap, and a
  from-scratch hardening baseline. Packaged install path:
  `/usr/lib/systemd/system/parzival-broker.service`.
- `systemd/check-parzival-broker.service` + `.timer` — a periodic health check (every 10
  minutes) that makes a real `tea.repos-list` request through the socket — the deadman and
  silent-fail detections. Runs as the `parzival-broker` service account itself (not a human
  operator's account) — it's just a client of an already-authenticated broker, needs no
  credential of its own, and this keeps the packaged unit free of any specific person's
  username. Packaged install paths: `/usr/lib/systemd/system/check-parzival-broker.service`
  and `.timer`.
- `systemd/check-parzival-broker.sh` — the checker script itself. Reports success/failure
  entirely through its exit status and ordinary `journalctl`-visible logging — no
  push-monitor beat, no chat alert; see its header comment. It also does **not** implement
  an audit-log error-rate check, since that would require either weakening `audit.log`'s
  intentional `0600` permissions or a new broker-side summary operation. Packaged install
  path: `/usr/libexec/parzival-broker/check-parzival-broker.sh`.
- `sysusers.d/parzival-broker.conf` — declarative service-account creation
  (`systemd-sysusers`). Packaged install path: `/usr/lib/sysusers.d/parzival-broker.conf`,
  applied automatically by the package's postinstall script.

## The administrator trust-root ownership contract

The security invariant this package and the broker's own verifier
(`internal/consumer.VerifyTrustRoot`) both enforce: **root owns every trusted
broker input; `parzival-broker` may read and traverse it, and never write
it.** The broker's own uid is a privilege-reduction measure, not a trust
boundary — it is never an acceptable substitute for root ownership on
either side of that check.

| Path | Owner:group | Mode | Who creates it |
| --- | --- | --- | --- |
| `/etc/parzival-broker` | `root:parzival-broker` | `0750` | package (postinstall, after `systemd-sysusers` creates the group) |
| `/etc/parzival-broker/consumers` | `root:parzival-broker` | `0750` | package, same as above |
| `/etc/parzival-broker/profiles` | `root:parzival-broker` | `0750` | package, same as above |
| A consumer definition (e.g. `consumers/tea.json`) | `root:parzival-broker` | `0640` | administrator |
| A profile (e.g. `profiles/tea.json`) | `root:parzival-broker` | `0640` | administrator |
| `authz.json` | `root:parzival-broker` | `0640` | administrator |
| A named executable a consumer definition points at (e.g. `/usr/bin/tea`) | ordinary distro package ownership (typically `root:root`) | ordinary distro mode | the executable's own package |
| A credential file the service receives via a systemd credential mechanism (e.g. `openbao-secret-id.cred`) | `root:root` | `0600` | administrator, decrypted by systemd itself before the service starts — never group-readable, since the broker never reads it directly |
| `audit.log` | `parzival-broker:parzival-broker` | `0600` | the broker itself, at runtime — an output, not a trusted input, so it is never part of this contract |
| `/run/parzival/broker.sock` | `parzival-broker:parzival-clients` | `0660` | the broker itself, at runtime, immediately after binding it — see "The socket-client group" below. Also not a trusted input |

**The package only owns the three directory rows.** It creates and fixes
their group ownership on every install and upgrade (idempotently, and
never recursively — see `scripts/postinstall.sh`), because it is the one
that shipped them. Every administrator-created file above is created,
and re-permissioned after any edit, by the administrator — the package
never chowns, chmods, or otherwise mutates content it did not ship, and an
upgrade never widens or narrows a permission an administrator already set
on a file of their own.

## The socket-client group

The broker's listening socket has **two independent authorization layers**, and it's
important not to confuse what each one does:

1. **Filesystem permissions on the socket itself** — a coarse local admission gate. They
   decide who can `connect()` at all.
2. **`SO_PEERCRED` plus `authz.json`** — the actual per-request authority decision, made
   *after* a connection is accepted, based on the connecting process's real uid. This is
   unchanged by anything below and remains the only thing that decides whether a given
   caller may invoke a given operation.

Before this fix, the socket was created `0700`, owned solely by the `parzival-broker`
service account — layer 1 admitted *nobody but the broker's own uid*, which made layer 2's
whole uid-based model unreachable for every other caller `authz.json` might authorize.
`internal/broker`'s `setSocketGroupAndMode` now chowns the socket to a dedicated
**`parzival-clients`** group and sets its mode to `0660` immediately after binding — before
`Accept` is ever called, so no connection can race the change.

`parzival-clients` is deliberately **not** the same group as `parzival-broker` above. That
group's entire purpose is read/traverse access to the trusted config
`internal/consumer.VerifyTrustRoot` checks (`authz.json`, `consumers/`, `profiles/`);
`parzival-clients` grants nothing but the ability to reach the socket. **Membership in
`parzival-clients` authorizes zero broker operations by itself** — a member whose uid
`authz.json` doesn't list still gets the same generic `DENIED` any other unauthorized caller
gets, with no operation resolved and no secret ever fetched.

**Administrator action required, per intended local caller:**

```bash
sudo usermod -aG parzival-clients <local-username>
```

The package creates the `parzival-clients` group (via `sysusers.d`) but never adds any
account to it automatically — not even the account you're installing as. Every local user or
service account that should be able to reach the broker is your explicit choice.

The broker process itself needs `parzival-clients` as a *supplementary* group (see
`parzival-broker.service`'s `SupplementaryGroups=`) — not because it needs to read anything
through it, but because `chown(2)` requires either `CAP_CHOWN` (this unit's
`CapabilityBoundingSet=` is empty) or membership in the target group to change a file's group,
even as that file's own owner.

## Site-specific configuration — `/etc/parzival-broker/environment`

**Not shipped by the package, and there is no default.** Both units read this one file via
`EnvironmentFile=`; it holds every value that's genuinely specific to one OpenBao instance
and one Gitea account, none of which a generic package can guess:

```bash
# /etc/parzival-broker/environment  (create by hand, mode 0640, owner root:parzival-broker)
BAO_ADDR=https://openbao.example.com
PARZIVAL_OPENBAO_ROLE_ID=<role-id-from-your-AppRole>
OWNER=<the-gitea-account-or-org-the-tea-consumer-definition-is-configured-for>
```

`PARZIVAL_OPENBAO_AUTH=approle` and `PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential`
stay inline in `parzival-broker.service` — they describe how this packaged unit
authenticates by design, not a per-install value. Without this file, `parzival-broker.service`
fails to start and `check-parzival-broker.service` refuses to run (both loudly, not
silently) rather than falling back to any deployment-specific default — the shipped units
carry none, and `scripts/release/scan-release-artifacts.sh` exists to catch exactly that
kind of leakage before a release goes out.

## Generic by design, no bundled alerting

Neither unit carries an `OnFailure=`, and the checker script has no dependency on any
specific push-monitor or chat-alert infrastructure — this package ships to anyone, and it
must not assume any one site's monitoring stack. Each unit's own exit status and journald
output are the generic signal; a site wires that into its own alerting (a systemd drop-in
via `systemctl edit`, or a wrapper around the checker script) rather than this package
calling out to a specific alert mechanism. Integrate the health-check service with the
monitoring or alerting system used by the deployment.
