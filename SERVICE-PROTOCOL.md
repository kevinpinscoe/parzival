# SERVICE-PROTOCOL.md — the parzival broker service protocol

> **Status: implemented on Linux, for one operation.** `parzival-broker` is the Linux broker
> daemon that implements this document: a packaged systemd service running under its own
> dedicated account, with root-owned trust-root configuration and per-request authorization
> based on the connecting process's real, kernel-verified uid. `internal/broker`'s client
> (`Dial`/`Call`) and `cmd/parzival service` are the agent-facing client this document
> describes. As of this writing the broker serves exactly one operation, `tea.repos-list` —
> not the full protocol surface this document specifies. There is no macOS build yet. The
> shipped `parzival` CLI's `get`/`exec`/`mount`/`probe`/`policy` behavior is unchanged by any
> of this.

## Why a second interface exists

`parzival exec` hands a credential to a command the **caller** chose. That is the right
shape for a human at a terminal, and it is the wrong shape for an untrusted client: a
caller who picks the command can pick `cat`, `env`, or a shell. `parzival mount` has the
same property from the other direction — whoever can `open()` the mounted file reads the
value. Both are honest-mistake prevention, and neither is a boundary against a client that
wants the plaintext.

The service protocol is the interface for a client that must be able to *use* a credential
without being able to *read* it. The client names an operation; it never names a command,
an executable, a profile, a file, an environment variable, or a path.

> The credential still becomes plaintext — inside the broker's security domain, in the
> approved consumer's memory. That is unavoidable: a secret must exist in cleartext
> somewhere for the consuming tool to use it. What changes is who is on the far side of
> the uid boundary when it happens.

## The boundary this protocol is part of

A client that can reach this socket can request only approved, non-secret operations. It
cannot read the broker's OpenBao authentication material, the rendered consumer
configuration, the consumer process environment, or the consumer process memory.

That holds only under the assumptions recorded in `THREAT-MODEL.md` §4d — a separate uid,
an administrator-owned trust root, no independent client path to the store, and an approved
consumer that does not itself disclose the credential. **The protocol is one component of
that boundary and does not create it on its own.** A correct implementation of this
document running as the same uid as its client enforces nothing.

## Transport

| Property | Value |
| --- | --- |
| Socket family | `AF_UNIX`, `SOCK_STREAM` |
| Default path | `/run/parzival/broker.sock` (Linux); a broker-owned runtime directory on macOS |
| Socket mode | `0660`, owned `parzival-broker:parzival-clients` |
| Directory mode | `0755` on the socket's parent, `0700` on the broker's runtime directory |
| Client identity | `SO_PEERCRED` on Linux; XPC peer identity on macOS where available |

**Peer credentials are read from the kernel, never from the request.** There is no field in
which a client states who it is, and there is no equivalent of `--as`. A self-asserted
identity is exactly the control this interface exists to remove: an identity a client can
type is an identity a client can choose.

The socket's group membership is the coarse gate — who may connect at all. Authorization of
a specific operation is a separate decision made per request, after the peer's uid is known.

## Framing

One request and one response per connection. The connection is closed by the broker after
the response is written; a client that wants a second operation opens a second connection.

Each message is a 4-byte big-endian unsigned length followed by that many bytes of UTF-8
JSON. No trailing newline, no delimiter, no chunking, no streaming.

```text
+--------+------------------+
| uint32 | JSON body        |
| length | (length bytes)   |
+--------+------------------+
```

| Bound | Value | On breach |
| --- | --- | --- |
| Maximum request body | 64 KiB | Connection closed, no response written |
| Maximum response body | 1 MiB | `ERROR` with code `result_too_large` |
| Read timeout for the request | 5s | Connection closed |
| Total operation deadline | Per operation, default 30s | `ERROR` with code `timeout` |

A single request/response per connection is deliberate. It gives every operation its own
kernel-verified peer credentials, removes any notion of a session an attacker could
inherit, and makes the broker's cleanup path unconditional — the runtime directory for an
operation is created after the request is authorized and removed before the response is
written.

## Request

```json
{
  "protocol": 1,
  "operation": "tea.repos-list",
  "inputs": { "owner": "acme" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `protocol` | integer | yes | Protocol version. A version the broker does not implement is refused, never guessed at. |
| `operation` | string | yes | `<consumer>.<operation>`, both names as declared in the consumer definition. |
| `inputs` | object of string | no | Values for the operation's declared inputs. Absent is equivalent to `{}`. |

**Unknown fields are refused, not ignored** — the same rule `policy.Parse` follows, for the
same reason. A client that sends a field this broker does not understand is asking for
something it will not get, and silently dropping the field is how a control degrades without
anyone noticing.

**`inputs` values are data and only data.** They are matched against the operation's
declared pattern, substituted into an argv vector, and passed to `execve`. They are never
concatenated into a command line, never interpreted by a shell, and never used to select a
file, a profile, an executable, or an environment variable.

There is deliberately **no** field for: an executable, a profile name, a configuration path,
an environment variable, a file descriptor, an output destination, a delivery mode, a
timeout, an identity, or a raw flag to pass through to the consumer. Adding any of them
would hand the client back the thing this interface took away.

## Response

```json
{
  "protocol": 1,
  "status": "OK",
  "result": { "repositories": [] }
}
```

```json
{
  "protocol": 1,
  "status": "DENIED",
  "error": { "code": "not_authorized", "message": "operation not permitted for this client" }
}
```

| Field | Type | Present when | Meaning |
| --- | --- | --- | --- |
| `protocol` | integer | always | Echoes the protocol version the broker answered in. |
| `status` | string | always | One of the five values below. |
| `result` | object | `status` is `OK` | The operation's declared response shape. |
| `error` | object | `status` is not `OK` | A bounded `code` and a human-readable `message`. |

### The status vocabulary is closed

| Status | Meaning |
| --- | --- |
| `OK` | The operation ran and produced its declared result. |
| `DENIED` | The peer is not authorized for this operation. |
| `INVALID` | The request was malformed, named an unknown operation, or failed input validation. |
| `ERROR` | The operation was attempted and failed. |
| `UNAVAILABLE` | The broker cannot serve requests — no store credential, trust root refused, shutting down. |

**A sixth value is not added without asking what it discloses.** This is the same discipline
`probe` is held to (`probe.go`): a verdict vocabulary is a disclosure surface,
and a status that distinguishes "the credential was empty" from "the credential was wrong"
tells a client something about a value it is not allowed to read.

The distinction between `DENIED` and `INVALID` is deliberate and is the one place this rule
is relaxed: a client needs to know whether to fix its request or to stop asking. Neither
value says anything about the credential.

### What a response may never contain

This is the protocol's central rule, and it is not situational:

- The credential, in whole or in part — not the bytes, not a prefix, not a suffix, not a
  length, not a hash, not a character count, not "the token starts with `gt`".
- The path of any file the credential was rendered into, or of the broker's runtime
  directory.
- Any part of the consumer process's environment.
- The consumer's raw stderr, or a raw error string from the store backend. Both routinely
  quote the input they were given, and the input they were given is the credential.
- A stack trace, a panic message, or a debug dump from the broker.

`error.message` is written by the broker from a fixed set of phrasings. It never
interpolates output from the consumer, the store, or the operating system. When the broker
needs the underlying detail for diagnosis, that detail goes to the broker's own log, which
the client cannot read — and the credential does not go there either.

### Error codes

| Code | Status | Cause |
| --- | --- | --- |
| `unsupported_protocol` | `INVALID` | `protocol` names a version this broker does not implement. |
| `malformed_request` | `INVALID` | Not valid JSON, an unknown field, a missing required field, or `operation` not matching the `<consumer>.<operation>` shape. |
| `unknown_operation` | `INVALID` | No consumer definition declares that `<consumer>.<operation>`. Defined for wire-format completeness; a correct implementation following the corrected "Serving one request" order below never actually produces it — a not-yet-authorized client can't learn this (it gets `DENIED` instead, regardless of existence), and an already-authorized client reaching an unresolved operation indicates a broker-side inconsistency, answered `broker_unavailable` instead. |
| `invalid_input` | `INVALID` | An input was missing, too long, or failed its declared pattern. |
| `not_authorized` | `DENIED` | The peer's uid is not permitted this operation. |
| `consumer_failed` | `ERROR` | The consumer exited non-zero, or its output did not match the declared response shape. |
| `result_too_large` | `ERROR` | The consumer's output exceeded the response bound. |
| `timeout` | `ERROR` | The operation exceeded its deadline. |
| `broker_unavailable` | `UNAVAILABLE` | No store credential, trust root refused, or shutdown in progress. |

`invalid_input` names the input that failed and what constraint it failed, because that is
the client's own data. It never echoes the value back — an operation whose input pattern is
narrow enough could otherwise be used as an oracle.

## Serving one request

> **Design note.** An earlier draft of
> this section resolved `<consumer>.<operation>` *before* authorizing the peer, on the theory
> that an `INVALID` answer "does not depend on whether the peer is authorized". That theory
> was wrong: returning `INVALID`/`unknown_operation` for an operation that does not exist, but
> `DENIED` for one that exists but is not authorized, lets an unauthorized peer enumerate every
> configured operation by comparing the two statuses — exactly the "unauthorized client cannot
> enumerate what exists" property the old wording claimed to provide. The sequence below is the
> corrected order, and is what `internal/broker` actually implements.

1. Accept the connection and read the peer's credentials from the kernel.
2. Read the length-prefixed request within the read timeout, enforcing the size bound.
3. Decode strictly — unknown field, trailing data, or an unimplemented `protocol` is
   `INVALID` with no further work.
4. Check `operation` against the `<consumer>.<operation>` shape only — a syntax check, not a
   resolution. This says nothing about whether either half is actually configured, which is
   what makes it safe to apply before authorization. Malformed shape is `INVALID`.
5. **Authorize the peer's uid against the requested operation *string***, before resolution is
   attempted. Not authorized is `DENIED` — **regardless of whether the operation exists** —
   and no credential is fetched. This ordering is the enumeration-safety property: an
   authorization check that only needs the string, decided before the broker ever discloses
   (via `INVALID` vs. `DENIED`) whether that string resolves to anything real.
6. **Resolve** `<consumer>.<operation>` against the loaded, root-owned consumer definitions —
   only now, after authorization has already succeeded. Because every authorized operation
   string was already checked to resolve at broker startup, failing to resolve here means the
   broker's own state is inconsistent with what it verified at startup — not a bad client
   request. This is `UNAVAILABLE`, not `INVALID`/`unknown_operation`, which would disclose
   something to a client that is already authorized for this string and has no legitimate need
   to learn more about broker internals.
7. Validate every input against its declared pattern and length bound, and build the argv
   vector by substitution. Failure is `INVALID`, and no credential is fetched.
8. Fetch the credential using the broker's own store authentication.
9. Create a `0700` runtime directory owned by the broker, and render the profile into a
   `0600` file inside it if the consumer needs one.
10. `execve` the absolute executable with the validated argv and a newly constructed minimal
    environment. Never `sh -c`; never the client's environment, `PATH`, loader variables,
    proxy settings, config-home paths, or inherited descriptors.
11. Capture stdout to the response bound, validate and canonicalize it against the declared
    response shape (never a raw passthrough of consumer stdout), and discard stderr to the
    broker's own log — its content, never captured, only its length and the exit status.
    Where a validator needs deployment facts (an exact expected origin, for example), they
    come from the operation's `response_config` in the root-owned consumer definition,
    checked once at startup, and never from the request.
12. Zero and remove the rendered file and the runtime directory. This runs **before** the
    response is built and sent (see "Audit", below, for why write ordering here matters too).
13. Write the response and close the connection.

Steps 5 and 7 both precede step 8 on purpose: a request that is going to be refused is refused
before the store is touched, so a rejected request leaves no credential in the broker's memory
and no read in the store's audit log.

Step 12 runs whether steps 10 and 11 succeeded, failed, or timed out.

## Audit

Every request is written to the broker's audit log with the peer's uid, the resolved
operation, the decision, the outcome, and the duration. The **names** of the inputs are
recorded; their **values** are not, because an input value is client-supplied data whose
sensitivity the broker cannot judge.

The credential never appears in the audit log, in any status, on any path — including the
failure paths, which is where it most often leaks in systems that get the success path
right.

**An `OK` response is never sent unless its audit record was durably written first.** Writing
the response before the audit record would let a client be told a request succeeded whose
audit trail was then lost to a write failure, with nothing left to show it ever happened. So
for an otherwise-successful request the response is built but held, the audit write is
attempted, and only if that write succeeds is `OK` actually sent — a failed audit write
downgrades the response to `UNAVAILABLE`/`broker_unavailable` instead. This is not a rollback:
the consumer operation has already run by this point, and cannot be un-run. The guarantee is
narrower and is exactly what it needs to be: the broker never *positively reports* an operation
whose audit record does not exist. Every other response (`DENIED`, `INVALID`, `ERROR`,
`UNAVAILABLE` for other reasons) is still audited unconditionally at this same point in the
sequence — the write happens regardless of whether the client-facing write that follows it
succeeds, or whether the client has already disconnected.

## Versioning

`protocol` is an integer, incremented when a change would alter how an existing client's
request is interpreted. A broker refuses a version it does not implement rather than
serving a best-effort approximation of it, for the reason `policy.SchemaVersion` exists: a
field whose *meaning* changed without its *name* changing cannot be caught by strict
parsing.

Adding a new error code, or a new operation to a consumer definition, is not a protocol
change. Adding a request field, changing the framing, or changing what a status means is.

## Relationship to the existing CLI

| Existing surface | In service mode |
| --- | --- |
| `get`, `--fd`, `--force` | Not exposed. There is no client-facing raw-read endpoint. |
| `exec PROFILE -- COMMAND` | Replaced by named operations. The client never names a command. |
| `mount MOUNTPOINT` | Not exposed. A mounted value is readable by whoever opens it. |
| `--as ID` | Replaced by kernel-supplied peer credentials. |
| Profiles and `{{cred}}` templates | Still used — by the broker, from a root-owned location, never named by the client. |
| `policy grant`, `policy apply` | Administrative. Not reachable over this socket. |
| `probe` | May be offered, under the same peer authorization, keeping its `OK`/`EMPTY`/`DENIED`/`ERROR` vocabulary. |

The CLI (`get`/`exec`/`mount`/`policy`) keeps its current behaviour for human workflows and
**must never be described as providing this document's boundary** — only `parzival-broker`,
running as its own dedicated account and authorizing by kernel-verified peer credentials,
does that.

## Related

- `THREAT-MODEL.md` §4d — the boundary statement, its assumptions, and what it excludes.
- `internal/consumer` — the consumer-definition schema this protocol resolves an operation
  against.
- `INSTALL.md` — installing and configuring `parzival-broker`.
