## v0.2.0

Parzival is still **pre-1.0**: the policy format, interfaces, and configuration layout
may change before a stable `v1.0.0`. This release adds a per-rule guard against AI
agent contexts, closes an ordering gap in `exec` and `mount`, and tightens what the
broker will accept back from its helper scripts.

### New: keep a rule's grant away from AI agents (`deny_agents`)

A policy rule can now carry `"deny_agents": true`. When Parzival detects that it is
running inside an AI agent harness — the same detection that already refuses raw
`get` there — the rule still matches but refuses the request. Because the first
matching rule decides, no broader rule further down the list can grant the same
request to the agent instead. Requests made outside an agent context, and rules
without the field, behave exactly as before.

- It applies to every mode the rule matches: `get`, `exec`, and `mount`.
- It is a guard against the normal agent harness, **not** a proof that a human is
  present. See THREAT-MODEL.md for what it does and does not establish.
- First match still wins. An *earlier* matching allow is not affected, so to keep an
  agent off a secret whatever `--as` label it asserts, the denying rule must cover
  every identity and every mode that later rules grant on that secret, and sit above
  those rules. MANUAL.md has a worked example.
- `policy validate` and `policy check` now judge reachability, shadowing, and
  redundancy for both agent and non-agent requests. An earlier allow that makes an
  agent denial unreachable is an error; overlaps that only matter for agents are
  warnings, as are `deny_agents` on a rule that already denies and an
  agent-denying rule limited to specific identities.
- `policy what-if --agent` asks the question for an agent context. Without the flag,
  `what-if` answers for a request with no agent, whatever shell it is run from.
- The audit log records the detected agent marker on decisions made in an agent
  context.
- Authorization deltas (`policy grant` / `policy apply`) also probe the agent context
  when either policy uses `deny_agents`.

An older Parzival refuses a policy file that uses `deny_agents`, rather than ignoring
the field. Upgrade every host that reads a policy before adding the field to it.

### Changed: `exec` and `mount` authorize every secret before fetching any

A profile renders all-or-nothing, but previously a profile whose second secret was
refused had already fetched the first one from the store. `exec` and `mount` now check
every secret in the profile against the policy first, and only then fetch. A refusal
now means no store access, no rendering, no credential file, and no child process.

### Broker

- Consumer operations can register a **response validator**, so the broker checks a
  helper script's output against an exact, closed contract before returning it.
  Validators ship for the Uptime Kuma push-monitor and Woodpecker repository-secret
  example operations; anything the contract does not allow is refused, not passed
  through.
- Operations gain an optional `response_config`: administrator-owned settings for a
  validator, read only from the root-owned operation definition and never from a
  request. The broker refuses to start on a missing, unknown, or invalid key.
- The push-monitor validator now requires the returned push URL to match the
  configured origin and token format exactly.

### Documentation

- THREAT-MODEL.md states the disclosure invariant, and covers terminal disclosure,
  argument-vector exposure, the in-memory residual, and the new `deny_agents` guard.
- `parzival service` examples put `--input` before the operation name.

See [README.md](README.md), [INSTALL.md](INSTALL.md), [MANUAL.md](MANUAL.md), and
[THREAT-MODEL.md](THREAT-MODEL.md) for the full design, installation, usage, and
security model.
