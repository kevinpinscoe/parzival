# Example exec profiles

Copy any of these into your profiles directory and edit the secret references to
match your store:

```bash
mkdir -p ~/.config/parzival/profiles
cp examples/profiles/aws.json ~/.config/parzival/profiles/
```

A profile is JSON with three parts:

| Key | Meaning |
| ----- | --------- |
| `secrets` | map of template-variable name → store reference (`bao:…`, `op://…`) |
| `template` | Go `text/template` rendered with those secrets into the RAM file |
| `inject.env` | environment variable set to the rendered **file's** path (optional) |
| `inject.env_dir` | environment variable set to the **RAM directory's** path (optional) |
| `inject.filename` | path of the rendered file inside the RAM dir (default `credential`). May be **nested** (`tea/config.yml`) — parent dirs are created `0700`. Absolute paths and any `..` element are rejected. |

`parzival exec <profile> -- <command>` fetches the secrets, renders the file onto
tmpfs, then runs the command with the paths available three ways each:

| | File path | Directory path |
| --- | --- | --- |
| always | `$PARZIVAL_CRED_FILE` | `$PARZIVAL_CRED_DIR` |
| if set | `inject.env` | `inject.env_dir` |
| in argv | `{{cred}}` | `{{creddir}}` |

The whole tree is zeroed and removed when the command exits — at any depth, and on
Ctrl-C as well as normal exit.

## The shipped examples

| Profile | Injection | Command example |
| --------- | ----------- | ----------------- |
| `aws` | `AWS_SHARED_CREDENTIALS_FILE` | `parzival exec aws -- aws s3 ls` |
| `kubectl` | `KUBECONFIG` | `parzival exec kubectl -- kubectl get pods` |
| `pgpass` | `PGPASSFILE` | `parzival exec pgpass -- psql -h postgres.example.com -U dbuser` |
| `gitea-token` | `{{cred}}` / `$PARZIVAL_CRED_FILE` | `parzival exec gitea-token -- sh -c 'wc -c < {{cred}}'` |
| `curl-bearer` | `EXAMPLE_CURL_CONFIG` | `parzival exec curl-bearer -- sh -c 'curl -K "$EXAMPLE_CURL_CONFIG" https://api.example.com/v1/items'` |
| `tea` | `XDG_CONFIG_HOME` (dir) | `parzival exec tea -- env HOME=/nonexistent tea repos list` |
| `ssh-key` | `PARZIVAL_SSH_KEY` / `{{cred}}` | `parzival exec ssh-key -- ssh -i {{cred}} -o IdentitiesOnly=yes host.example.com uptime` |
| `openbao-token` | `HOME` (dir) | `parzival exec openbao-token -- env BAO_ADDR=https://bao.example.com bao token lookup` |
| `homebrew-token` | `$PARZIVAL_CRED_FILE` (**read into an env var by the caller**) | `parzival exec homebrew-token -- sh -c 'export HOMEBREW_GITHUB_API_TOKEN=$(cat "$PARZIVAL_CRED_FILE"); exec brew "$@"' brew outdated` |

`tea` is the credential-**directory** case: the tool reads a fixed path inside a config
directory rather than a file it can be pointed at, so the profile renders
`tea/config.yml` and injects the *directory* as `XDG_CONFIG_HOME`.

`curl-bearer` is the generic "auth header in a config file" shape — useful for any REST
API where you want the token off the command line (`curl -H "Authorization: …"` would put
it in `/proc/<pid>/cmdline`; `curl -K <file>` does not).

`ssh-key` renders a private key that `ssh` is pointed at with `-i`. Pair it with
`-o IdentitiesOnly=yes`, or `ssh` still offers the agent's and `~/.ssh/`'s keys first.

`openbao-token` is the other credential-**directory** case, and the bluntest: `bao` reads
its token from `$HOME/.vault-token` via its default token helper, so injecting `HOME` gives
it the token with **no `BAO_TOKEN` in the environment**. The child sees a `HOME` containing
nothing else, which is fine for a `bao` call and wrong for anything needing a real home.
It is for brokering an OpenBao token to a downstream `bao` command, not for Parzival's own
secret zero. In AppRole broker-auth mode, Parzival obtains its own short-lived OpenBao token
internally and should not rely on a caller-readable `$HOME/.vault-token`.

`homebrew-token` is the **weakest** profile shipped here, and it is included precisely so
the weakness is written down. Homebrew reads `HOMEBREW_GITHUB_API_TOKEN` and offers no
file-based alternative, so the caller must `cat` the rendered file into an environment
variable — the one thing every other profile here exists to avoid. What it still buys:
nothing durable on disk, nothing in a dotfile, no interactive keychain prompt, and a
policy decision plus an audit record per invocation. Point it at a **dedicated,
public-read-only PAT**, not at a broad account token.

The secret references in these files are examples — adjust the mount/path/field to
your own store before use.
