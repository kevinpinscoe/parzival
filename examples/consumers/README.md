# Example consumer definitions

> **This is the interface `parzival-broker` reads its consumer definitions from.** Consumer
> definitions are consumed by the broker service specified in
> [`../../SERVICE-PROTOCOL.md`](../../SERVICE-PROTOCOL.md). `internal/broker` and
> `cmd/parzival-broker` implement it for exactly the operation [`tea.json`](tea.json)
> declares. The broker is Linux-only, packaged as a systemd service under its own dedicated
> account, and reads consumer definitions from its own root-owned configuration directory
> (`PARZIVAL_CONFIG_HOME`, pinned by `cmd/parzival-broker`'s own flags/environment) — never
> from a user's `~/.config/parzival`. The shipped `parzival` CLI binary neither reads this
> directory nor runs a daemon; copying a file from here into `~/.config/parzival` does
> nothing. See [`../../INSTALL.md`](../../INSTALL.md) for where a real deployment's consumer
> definitions actually live.

A **profile** (`../profiles/`) says how to prepare a consumer's credential. A **consumer
definition** says which invocations of that consumer a client may cause to run. They are
separate files because they are separate decisions with different owners: a profile is a
rendering recipe, and a definition is a trust-root statement.

## What a definition may say

| Field | Meaning |
| --- | --- |
| `schema` | Definition format version. A version newer than the binary understands is refused, never partially applied. |
| `name` | The consumer's name, and the first half of a qualified operation (`tea` in `tea.repos-list`). |
| `executable` | The absolute path of the binary the broker runs. Never chosen, named, or influenced by a client. |
| `profile` | A bare profile name, resolved against the broker's own root-owned profile directory. |
| `operations` | The closed set of invocations a client may request. An empty set is refused. |

Each operation declares an `argv` vector with `${name}` placeholders, the `inputs` those
placeholders may be filled from, and the `response` shape (`json` or `text`) its stdout is
validated against.

An operation may also carry `response_config`: a small map of trusted, deployment-specific
strings its response validator needs, such as the exact origin a returned URL must have.
These are facts about your deployment, not the product, so they live in this root-owned
file instead of being compiled into `parzival-broker`. A client can never supply or change
them. Each validator declares the exact keys it requires and checks their values. The broker
refuses to start on a missing, unknown or invalid key, and on `response_config` given to an
operation whose validator takes none. For example, `kuma.push-mint` requires:

```json
"response_config": { "push_origin": "https://uptime.example.test" }
```

That is a bare HTTPS origin in canonical form: lowercase, an optional explicit port, and no
path, slash, query or fragment. A returned `push_url` must then be exactly
`<push_origin>/api/push/<32 lowercase hex>`.

Each input declares a `pattern`, and optionally `max_length`, `optional`, and
`allow_leading_dash`. Three things about inputs are worth knowing before writing one:

- **The pattern is anchored by parzival, not by you.** `[a-z]+` is treated as
  `\A(?:[a-z]+)\z`. An unanchored pattern that matches a substring is validation that looks
  present and is not.
- **A value beginning with `-` is refused** unless the input sets `allow_leading_dash`. An
  argv element starting with a dash is read as an option by essentially every consumer, which
  would let a client change what your fixed argv means without ever naming a flag.
- **An input nothing substitutes is an error.** A declared-but-unreferenced input means you
  believe a value is constrained and reaching the consumer, and it is not.

## Where they live, and who must own them

In a deployed service mode a definition lives in a root-owned directory that the client
identity cannot write — `consumer.VerifyTrustRoot` checks the file, the executable, and every
ancestor directory of both, and the broker refuses to start when the check fails.

That ancestor walk is the part worth understanding. A `0600` root-owned definition inside a
directory the client can write is not protected: the client cannot edit the file, but it can
rename it away and put its own there. Checking the file alone gives a confident answer to the
wrong question — which is why a definition under `/tmp` is refused however it is owned.

## The worked example

[`tea.json`](tea.json) is the worked example: a client may ask for the repositories under
one owner, and receives JSON. It cannot ask for a
different `tea` subcommand, add a flag, change the output format, point `tea` at a different
config, or read the token that made the call work.
