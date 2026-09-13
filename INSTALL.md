# INSTALL.md — Installing and Deploying Parzival

This is the installation and deployment guide for `parzival` (the CLI) and
`parzival-broker` (the optional broker service). See [README.md](README.md) for what
Parzival is and why it exists, [THREAT-MODEL.md](THREAT-MODEL.md) for what its guarantees
do and do not cover, and [SERVICE-PROTOCOL.md](SERVICE-PROTOCOL.md) for the broker's wire
protocol. This guide covers only installation, configuration, and validation.

## Two modes — pick one to start with

Parzival ships two independent things. Decide which one you need before installing.

| | CLI mode | Broker service mode |
| --- | --- | --- |
| What it is | The `parzival` binary, run directly by a human, script, or process | `parzival-broker`, a long-running systemd service, plus `parzival service` as its client |
| Who authorizes each request | Your own `~/.config/parzival/policy.json`, under whatever identity the caller asserts with `--as` | The broker's root-owned `authz.json`, keyed on the connecting process's real, kernel-verified uid |
| What the caller can name | A secret reference and a delivery mode (`get`/`exec`/`mount`) | A fixed operation name and typed inputs — never a command, a file, a profile, or a secret reference |
| Right for | A human, a trusted script, a service that can be trusted with `exec`/`mount` delivery | An **untrusted** client — an AI coding agent, in particular — that must be able to *use* a credential without ever being able to *read* it |
| Platforms | Linux, macOS | Linux only |

If you are not sure which you need: start with **CLI mode**. It is simpler to install and
covers most cases — a human or a trusted script fetching or brokering a secret under its
own approval policy. Reach for **broker service mode** only when the caller itself must not
be trusted with the plaintext at all. The two are independent and can be installed
together; the broker's own health check and `tea.repos-list` operation are themselves just
a `parzival service` client call.

## Requirements

| Role | Needs |
| --- | --- |
| Run the CLI | Nothing beyond the binary itself and a `policy.json` |
| Build from source | Go 1.26 (pinned via `mise.toml`), or any Go 1.26+ toolchain |
| OpenBao backend | The `bao` CLI (ambient mode), or nothing extra (AppRole broker-auth mode — the CLI talks to OpenBao's HTTP API directly) |
| 1Password backend | The `op` CLI, signed in |
| `parzival mount` | Linux only: `fuse3`, `/dev/fuse`, `fusermount3` |
| `parzival-broker` | Linux with systemd (`systemd-sysusers`, `LoadCredentialEncrypted=`); a dedicated OpenBao AppRole; a Gitea account for the shipped `tea.repos-list` operation |

`gopass` and KeePassXC backends are named in the design but not implemented yet — a
`gopass:` reference parses but nothing serves it.

## Installing the CLI

Three package managers, plus a source build for anything else. Pick one.

### RPM (Fedora, RHEL, and derivatives — x86_64, aarch64)

```bash
sudo dnf config-manager --add-repo https://kevinpinscoe.github.io/rpm/kevinpinscoe.repo
sudo dnf install parzival
```

Or without `dnf config-manager`:

```bash
curl -sLO https://kevinpinscoe.github.io/rpm/kevinpinscoe.repo
sudo mv kevinpinscoe.repo /etc/yum.repos.d/
sudo dnf install parzival
```

Packages are signed; the repository's GPG key is documented at
<https://github.com/kevinpinscoe/rpm>.

> **Release/cutover placeholder.** The `dnf config-manager`/`add-repo` step above is a real,
> already-live repository serving other `kevinpinscoe` tools today. `sudo dnf install
> parzival` will not resolve to anything until Parzival's own first tagged release has been
> built and dispatched into that repository — a separate, later, explicitly-approved step
> (see [README.md](README.md) → Status). Until then, use the source build below.

The RPM installs both `/usr/bin/parzival` and `/usr/bin/parzival-broker`, the
`parzival-broker`/`parzival-clients` systemd assets described under
[Installing the broker service](#installing-the-broker-service) below, and does **not**
enable or start the broker — installing the package never brings an unconfigured service
online.

### DEB (Debian, Ubuntu, and derivatives — amd64, arm64)

```bash
curl -sL https://kevinpinscoe.github.io/apt/gpg.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kevinpinscoe.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/kevinpinscoe.gpg] \
  https://kevinpinscoe.github.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/kevinpinscoe.list

sudo apt update
sudo apt install parzival
```

> **Release/cutover placeholder**, same as the RPM path above: the APT repository is real
> and already live for other tools, but `parzival` will not appear in it until the first
> tagged release is published. Use the source build below until then.

The DEB package ships the identical set of files and systemd assets as the RPM above.

### Homebrew (macOS, Apple Silicon only — CLI only)

```bash
brew install --cask kevinpinscoe/tap/parzival
```

or, if you have already tapped it:

```bash
brew tap kevinpinscoe/tap
brew install --cask parzival
```

This installs the `parzival` CLI only. There is **no macOS build of `parzival-broker`** —
the broker is a systemd service with no macOS/launchd equivalent yet, so broker service mode
is Linux-only regardless of which platform installed the CLI. Homebrew also does not build
for Intel Macs; only Apple Silicon (`arm64`) is published.

> **Release/cutover placeholder**, same reasoning as above: the tap exists and serves other
> tools already, but the `parzival` cask will not resolve until the first tagged release.

### From source (any platform Go supports)

```bash
git clone https://github.com/kevinpinscoe/parzival.git
cd parzival
go build -o parzival ./cmd/parzival
go build -o parzival-broker ./cmd/parzival-broker   # Linux only; builds but is unused elsewhere
go test ./...
./parzival version
```

With [`mise`](https://mise.jdx.dev/) installed, `mise install` pins the exact Go toolchain
(`go 1.26`) this project is built and tested against, without it, any Go 1.26+ toolchain
works. There is no separate install step from source — put the resulting binaries on `PATH`
yourself, e.g. `install -m 0755 parzival ~/.local/bin/`.

## Configuring a secret backend

Parzival is store-agnostic at the CLI: the same `get`/`exec`/`mount`/`probe`/`service`
commands work regardless of which encrypted store backs a given secret reference. Configure
whichever backend(s) you actually use.

### OpenBao — the reference backend for unattended use

Two modes:

- **Ambient mode** (default, compatibility). Parzival shells out to the `bao` CLI and
  inherits whatever authentication that CLI already has (`BAO_TOKEN`, `~/.vault-token`,
  or an interactive login). This is the easiest way to get started, but it means anything
  that can also run `bao` directly can bypass Parzival's own approval policy entirely — see
  [THREAT-MODEL.md](THREAT-MODEL.md) §6b before relying on `policy.json` for anything that
  matters.
- **AppRole broker-auth mode** — the strongest unattended shape. Parzival authenticates to
  OpenBao itself, using a dedicated AppRole scoped to only the paths it needs, and the
  caller never has a readable copy of the resulting token:

  ```bash
  export PARZIVAL_OPENBAO_AUTH=approle
  export BAO_ADDR=https://openbao.example.com
  export PARZIVAL_OPENBAO_ROLE_ID=<role-id-from-your-approle>
  export PARZIVAL_OPENBAO_SECRET_ID_PROVIDER=systemd-credential   # or systemd-creds-user, env, file
  ```

  See [Creating the CLI's own AppRole](#creating-the-clis-own-approle) below for the exact
  `bao` commands to create the role and its policy, and
  [Configuring the broker's OpenBao AppRole](#configuring-the-brokers-openbao-approle) for
  the broker daemon's own, separate AppRole.

Run `parzival doctor` after configuring either mode — it reports whether OpenBao is still in
ambient compatibility mode, whether an ambient `BAO_TOKEN` or a readable `~/.vault-token`
exists (both of which void the approval-policy guarantee described above), and whether the
detected shell is an AI agent harness.

### 1Password

Install and sign in to the `op` CLI, then use `op://<vault>/<item>/<field>` references
directly — no separate Parzival-side configuration is needed:

```bash
parzival get 'op://Private/Gitea/token'
```

### Creating the CLI's own AppRole

One AppRole per host (or per identity that needs its own accountable credential), scoped to
exactly the KV paths that identity needs — this is the blast-radius ceiling if the SecretID
is ever stolen, independent of `policy.json`:

```bash
cat <<'EOF' | bao policy write parzival-<host> -
path "app/data/<mount1>" { capabilities = ["read"] }
path "app/data/<mount2>" { capabilities = ["read"] }
EOF

bao write auth/approle/role/parzival-<host> \
  token_policies="parzival-<host>" \
  token_ttl=5m token_max_ttl=15m \
  secret_id_ttl=0            # non-expiring SecretID; rotation is the mitigation, not a TTL

bao read -field=role_id auth/approle/role/parzival-<host>/role-id     # non-secret, goes in config
bao write -f -field=secret_id auth/approle/role/parzival-<host>/secret-id \
  | systemd-creds encrypt --user --name=openbao-secret-id - \
      ~/.config/parzival/openbao-secret-id.cred
```

The SecretID never touches a stream or a file in plaintext — pipe `bao write` straight into
`systemd-creds encrypt --user`. On a non-Linux host, or without `systemd-creds`, use the
`env`/`file` SecretID providers instead (development/interactive use only — see
[README.md](README.md) for their limits).

Rotation is the accepted mitigation for a stolen bootstrap credential (Parzival does not do
machine binding — see [THREAT-MODEL.md](THREAT-MODEL.md)):

```bash
bao write -f -field=secret_id auth/approle/role/parzival-<host>/secret-id \
  | systemd-creds encrypt --user --name=openbao-secret-id - \
      ~/.config/parzival/openbao-secret-id.cred.new
mv ~/.config/parzival/openbao-secret-id.cred.new ~/.config/parzival/openbao-secret-id.cred
parzival doctor && parzival exec --as ai <any-known-profile> -- true   # re-verify before trusting it
bao list auth/approle/role/parzival-<host>/secret-id                  # old accessor still listed
bao delete auth/approle/role/parzival-<host>/secret-id/<old-accessor> # revoke the old one once proven
```

`role_id` never changes on rotation — only the SecretID.

## Configuring policy and profiles (CLI mode)

Parzival denies every fetch unless a policy allows it. Create `~/.config/parzival/policy.json`,
starting with a narrow rule that grants brokered delivery rather than a raw read:

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

Then validate it:

```bash
parzival policy check      # can a bypassable mode restriction be dodged by a different --as label?
parzival policy validate   # unreachable/shadowed/redundant rules, evaluated by real rule order
parzival doctor            # host-level posture: ambient OpenBao, AI-agent-shell detection, and more
```

**The first rule that matches a request decides it — order the file accordingly.** Use
`parzival policy what-if --as <id> --mode <mode> --ref '<ref>'` to see which rule would decide
a specific request before it happens, and `parzival policy grant`/`parzival policy apply` to
add a rule as a reviewed transaction (backup → atomic install → read-back verification)
rather than a hand edit — see [README.md](README.md) for worked examples of each.

For a tool that needs a credential in a file rather than a stream, write a profile at
`~/.config/parzival/profiles/<name>.json`:

```json
{
  "secrets": {
    "access_key": "bao:aws/myaccount#access_key_id",
    "secret_key": "bao:aws/myaccount#secret_access_key"
  },
  "template": "[default]\naws_access_key_id = {{ .access_key }}\naws_secret_access_key = {{ .secret_key }}\n",
  "inject": { "env": "AWS_SHARED_CREDENTIALS_FILE", "filename": "credentials" }
}
```

```bash
parzival exec --as ai aws -- aws s3 ls
```

Copy a starting point from [`examples/profiles/`](examples/profiles/) rather than writing one
from scratch — it covers AWS, `kubectl`, PostgreSQL (`pgpass`), SSH keys, a bearer-token curl
config, the Gitea CLI (`tea`), a downstream `bao` token file, and Homebrew's
environment-variable-only interface.

## Installing the broker service

Everything above authorizes against **your own** `policy.json` and delivers the secret into
**your own** process. `parzival-broker` is different: a dedicated systemd service, under its
own uid, that lets an untrusted client — an AI agent, a script it doesn't fully trust — invoke
one of a small, fixed set of named operations without ever holding the credential itself. See
[SERVICE-PROTOCOL.md](SERVICE-PROTOCOL.md) for the wire protocol this is built on.

### What the package installs

Installing the RPM or DEB package (or the equivalent manual placement, if building from
source) puts these in place, but does **not** enable, start, or configure anything — a
broker with no trust-root configuration would have nothing safe to serve:

| File | Path |
| --- | --- |
| `parzival-broker.service` | `/usr/lib/systemd/system/parzival-broker.service` |
| `check-parzival-broker.service` + `.timer` | `/usr/lib/systemd/system/` |
| `check-parzival-broker.sh` | `/usr/libexec/parzival-broker/check-parzival-broker.sh` |
| `parzival-broker.conf` (`sysusers.d`) | `/usr/lib/sysusers.d/parzival-broker.conf` |
| `/etc/parzival-broker/`, `consumers/`, `profiles/` (empty directories) | created `root:parzival-broker 0750` |

The package's postinstall step also runs `systemd-sysusers`, which creates two accounts you
will use in the steps below:

- **`parzival-broker`** — the service's own dedicated system account (uid < 1000, no login
  shell). It owns nothing under `/etc/parzival-broker` — it only reads and traverses what an
  administrator places there.
- **`parzival-clients`** — a group that grants only the ability to *connect* to the broker's
  socket. **Membership in this group authorizes zero operations by itself** — it is a coarse
  filesystem-level admission gate, entirely separate from the per-operation authorization
  decision described below. The package creates this group but adds no one to it
  automatically, not even the account you installed as.

### The trust boundary: what root owns, what the broker may only read

The security invariant the package and the broker's own startup verifier both enforce:
**root owns every trusted broker input; `parzival-broker` may read and traverse it, and never
write it.** The broker's own uid is a privilege-reduction measure, not a trust boundary in
itself — root ownership on both sides of this check is what makes it real.

| Path | Owner:group | Mode | Who creates/writes it |
| --- | --- | --- | --- |
| `/etc/parzival-broker` | `root:parzival-broker` | `0750` | the package |
| `/etc/parzival-broker/consumers` | `root:parzival-broker` | `0750` | the package |
| `/etc/parzival-broker/profiles` | `root:parzival-broker` | `0750` | the package |
| A consumer definition, e.g. `consumers/tea.json` | `root:parzival-broker` | `0640` | the administrator, by hand |
| A profile, e.g. `profiles/tea.json` | `root:parzival-broker` | `0640` | the administrator, by hand |
| `authz.json` | `root:parzival-broker` | `0640` | the administrator, by hand |
| The OpenBao SecretID credential (e.g. `openbao-secret-id.cred`) | `root:root` | `0600` | the administrator; decrypted by systemd itself at start, never read directly by the broker |
| `audit.log` | `parzival-broker:parzival-broker` | `0600` | the broker itself, at runtime — an output, not a trusted input |
| `/run/parzival/broker.sock` | `parzival-broker:parzival-clients` | `0660` | the broker itself, immediately after binding it |

The package only ever touches the three directory rows, and only their ownership/mode —
never anything an administrator has placed inside them, and never recursively.

**The socket has two independent authorization layers, and it matters that you don't confuse
them:**

1. **Filesystem permissions on the socket** — a coarse, local admission gate. This is what
   `parzival-clients` membership grants: the ability to `connect()` at all, nothing more.
2. **`SO_PEERCRED` plus `authz.json`** — the actual per-request decision, made after a
   connection is accepted, based on the connecting process's real, kernel-verified uid. This
   is the only thing that decides whether a given caller may invoke a given operation, and it
   is unaffected by socket-group membership.

### Installation, step by step

1. **Install the package** (or build the binaries from source and place them at
   `/usr/bin/parzival` and `/usr/bin/parzival-broker`, `root:root 0755`, per
   [Installing the CLI](#installing-the-cli) above).

2. **Add every local account that should be able to reach the broker's socket** to
   `parzival-clients` — the package never does this automatically:

   ```bash
   sudo usermod -aG parzival-clients <local-username>
   ```

3. **Create a dedicated Gitea service identity for the broker.** See
   [Configuring the Gitea consumer](#configuring-the-gitea-consumer) below for exactly how —
   the non-admin account, the three token scopes it needs, and a gotcha worth knowing before
   you start.

4. **Configure the broker's own OpenBao AppRole.** See
   [Configuring the broker's OpenBao AppRole](#configuring-the-brokers-openbao-approle) below.

5. **Populate `/etc/parzival-broker`.** The consumer and profile definitions:

   ```bash
   sudo install -m 0640 -o root -g parzival-broker \
     examples/consumers/tea.json /etc/parzival-broker/consumers/tea.json
   sudo install -m 0640 -o root -g parzival-broker \
     examples/profiles/tea.json /etc/parzival-broker/profiles/tea.json
   ```

   Then write `/etc/parzival-broker/authz.json` by hand — it names real local uids, so there
   is no shipped example to copy. The schema:

   ```json
   {
     "schema": 1,
     "entries": [
       {
         "uid": 1000,
         "description": "Example: an AI agent's tool-wrapper process",
         "operations": ["tea.repos-list"]
       }
     ]
   }
   ```

   Each entry only grants — a uid with no matching entry is denied by omission. Set its
   ownership and mode the same as every other trust-root file:

   ```bash
   sudo chown root:parzival-broker /etc/parzival-broker/authz.json
   sudo chmod 0640 /etc/parzival-broker/authz.json
   ```

6. **Create `/etc/parzival-broker/environment`** — the one file the package deliberately does
   not ship, because every value in it is specific to your OpenBao instance and your Gitea
   account:

   ```bash
   # /etc/parzival-broker/environment  (mode 0640, owner root:parzival-broker)
   BAO_ADDR=https://openbao.example.com
   PARZIVAL_OPENBAO_ROLE_ID=<the-broker-approle-role-id-from-step-4>
   OWNER=<the-gitea-account-or-org-the-tea-consumer-definition-is-configured-for>
   ```

   Without this file, `parzival-broker.service` refuses to start rather than falling back to
   any default — there is no default a generic package could safely ship.

7. **Enable and start it:**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now parzival-broker.service
   sudo systemctl enable --now check-parzival-broker.timer
   ```

`authz.json` and every consumer/profile definition are read once, at startup — a
`systemctl restart parzival-broker.service` is required after editing any of them.

### Configuring the broker's OpenBao AppRole

A separate, dedicated AppRole from the CLI's own (from
[Creating the CLI's own AppRole](#creating-the-clis-own-approle) above) — the broker's
unattended, always-running access is kept independently accountable from any interactive CLI
use, and a stolen broker SecretID carries no CLI authority and vice versa. Scope it to read
only the one Gitea secret the broker's consumer definition needs:

```bash
bao policy write parzival-broker - <<'EOF'
path "app/data/parzival-broker/gitea" { capabilities = ["read"] }
EOF
bao write auth/approle/role/parzival-broker \
  token_policies="parzival-broker" token_ttl=5m token_max_ttl=15m secret_id_ttl=0
ROLE_ID=$(bao read -field=role_id auth/approle/role/parzival-broker/role-id)
echo "Role ID (non-secret, goes in /etc/parzival-broker/environment): $ROLE_ID"
```

Encrypt the SecretID for the **service** — host-key mode, not the desktop's
`systemd-creds-user`, since this is a system unit rather than an interactive session:

```bash
bao write -f -field=secret_id auth/approle/role/parzival-broker/secret-id \
  | sudo systemd-creds encrypt --name=openbao-secret-id - \
      /etc/parzival-broker/openbao-secret-id.cred
sudo chown root:root /etc/parzival-broker/openbao-secret-id.cred
sudo chmod 0600 /etc/parzival-broker/openbao-secret-id.cred
```

Rotate it the same way, at any time, without restarting the service until you're ready to
swap in the new one — `systemctl restart parzival-broker.service` picks it up.

### Configuring the Gitea consumer

The shipped `tea.repos-list` operation needs a Gitea account and a scoped Personal Access
Token, stored at a path dedicated to the broker — **never** whatever path an interactive
`tea` CLI wrapper might already use for a personal account:

1. Create a **new**, non-admin Gitea user account, dedicated to the broker — not shared with
   any human's personal account. The account name itself is not load-bearing; any dedicated
   name works.

2. **Leave login allowed.** Do not set the account to login-prohibited. Gitea's
   `prohibit_login` blocks a token issued to that account from authenticating at *all*, not
   only password/web login — there is no "token-only, login-prohibited" mode in Gitea's
   account model. Whatever least-privilege posture this identity needs comes from it being
   dedicated, non-admin, and narrowly token-scoped — not from disabling its own login.

3. Generate a Personal Access Token scoped to **exactly**: `read:repository`,
   `read:organization`, `read:user`. All three are required for `tea repos list --owner
   <name>` to work at all — `tea` resolves the named owner by checking identity, then
   organization membership, then repository access, in sequence, and refuses outright (never
   silently degrades) if any one of the three is missing. Grant nothing broader — no write,
   no admin, no repo create/delete.

4. Store it in OpenBao at the dedicated path this consumer's shipped profile
   (`examples/profiles/tea.json`) already expects:

   ```bash
   bao kv put app/parzival-broker/gitea \
     url=https://git.example.com \
     user=<the-dedicated-account-name> \
     token=<the-three-scope-token>
   ```

### Verifying the broker

```bash
parzival service tea.repos-list --input owner=<a-gitea-owner>
```

run as a uid that is both a member of `parzival-clients` (reachability) **and** granted
`tea.repos-list` in `authz.json` (authority) — both are independently required. `OK` and a
canonical `[{"owner":...,"name":...,"type":...,"ssh":...}, ...]` result mean the whole
path — socket, authorization, OpenBao, Gitea, response canonicalization — is working. This is
exactly what `check-parzival-broker.timer` runs, unattended, every 10 minutes.

## Validating the installation

Run these after any install or configuration change, in this order:

```bash
parzival version                      # confirms the installed build (release version + commit)
parzival doctor                       # host posture: ambient OpenBao mode, AI-agent-shell
                                       # detection, readable token files, policy load errors
parzival policy check                 # can a bypassable mode restriction be dodged by a
                                       # different --as label? exits non-zero if so
parzival policy validate              # unreachable, shadowed, or redundant rules
parzival probe --as <id> '<ref>'      # does a real fetch succeed, WITHOUT returning the value
```

`probe` is the right check for "did the store-side ACL grant land?" — it performs a real
fetch and reports one of four verdicts (`OK`/`EMPTY`/`DENIED`/`ERROR`), each with a distinct
exit code, and never returns the value itself. It is also the only reachability check
available from inside an AI agent's own shell, where `parzival get` refuses outright by
design (see [README.md](README.md) for why, and why there is deliberately no override).

If a broker is installed, also run its own health check:

```bash
parzival service tea.repos-list --input owner=<a-gitea-owner>
```

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `denied by policy` | No rule matched, or the mode is not allowed | `parzival policy what-if` names the deciding (or nearest) rule |
| `refusing to hand a raw secret to an AI agent's tool shell` | Running `get` inside a detected AI coding agent's shell | Use `probe` to check a ref, or `exec`/`mount` to use one. There is no override — run `get` yourself in an ordinary terminal if you need the raw value |
| `mount` fails on Linux | Missing FUSE support | Install `fuse3`, confirm `/dev/fuse` exists, or use `exec` instead |
| `mount` requested on macOS | Not implemented | Use `exec` |
| `doctor` flags `BAO_TOKEN` or a readable `~/.vault-token` | Ambient OpenBao credential is exported/present | Unset it; configure AppRole broker-auth mode instead |
| A new policy field is refused outright | The installed binary is older than the policy file | Rebuild/upgrade Parzival before trusting the new field — refusing is deliberate, not a bug |
| `systemctl status parzival-broker` loops in `activating (auto-restart)` | Trust-root verification is failing at startup — bad ownership/mode on a consumer/profile/authz file, or a missing profile | `journalctl -u parzival-broker -n 50` — the broker logs the specific path and reason before refusing to start |
| `parzival service` reports "could not reach the broker" (`permission denied`) | The caller's uid is not a member of `parzival-clients` | `id <caller>`; `sudo usermod -aG parzival-clients <caller>`, then re-login/re-exec so the new group takes effect |
| `parzival service` reports "could not reach the broker" (anything else) | Socket doesn't exist yet, wrong socket path, or the unit isn't running | `systemctl status parzival-broker`; confirm the socket path matches on both sides |
| `DENIED` for a caller you expect to be authorized | `authz.json` doesn't grant that uid the operation, or wasn't reloaded after an edit | Check `authz.json`'s uid entries; `systemctl restart parzival-broker` after any edit |
| `UNAVAILABLE` on every broker request | OpenBao unreachable, the AppRole SecretID failed to decrypt, or the AppRole/policy doesn't grant the Gitea secret path | `journalctl -u parzival-broker`; confirm `BAO_ADDR` reachability and that the role ID matches the unit's configuration |
| `consumer_failed` even though authorization succeeded | The Gitea token is missing one of its three required scopes, or the account has `prohibit_login` set | Re-check the token's scopes and the account's login setting directly in Gitea — the broker never surfaces the underlying error to the client, by design |

## Related documentation

- [README.md](README.md) — what Parzival is, its design goals, and what is and isn't a goal
- [MANUAL.md](MANUAL.md) — the user-facing operational guide: what to run next, once installed
- [THREAT-MODEL.md](THREAT-MODEL.md) — the security model, what each control does and does
  not defend against, and the assumptions the broker's boundary depends on
- [SERVICE-PROTOCOL.md](SERVICE-PROTOCOL.md) — the broker's wire protocol
- [`examples/`](examples/) — starting-point profiles, consumer definitions, and a `policy.json`
