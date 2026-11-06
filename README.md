# weichzelle

One long-lived VM per GitHub repo, for running coding agents (Claude Code,
opencode, …) fully autonomous. Agents are coordinated by herdr and treated
as hostile:
nothing from the host is mounted, egress is deny-by-default, and secrets
never enter the VM (only placeholders, swapped in at the network boundary).
Work leaves the VM only by pushing to GitHub.

See [DESIGN.md](DESIGN.md) for the threat model and decisions.

## Requirements

- Linux x86_64 with KVM
- [microsandbox](https://github.com/superradcompany/microsandbox) 0.7.8
  (`msb` on `PATH`)
- podman, buildah or docker (to build the base image)
- Rust (to build weichzelle)

## Quickstart

```sh
cargo install --locked --git https://github.com/TilRoth/weichzelle
# or from a local clone: cargo install --locked --path .
weichzelle init                    # writes ~/.config/weichzelle/{config.toml,Containerfile}
$EDITOR ~/.config/weichzelle/config.toml   # set [git] name and email

claude setup-token                 # on the host, for a Claude subscription
weichzelle secret set claude       # paste the token
weichzelle secret set github       # paste a fine-grained GitHub PAT

weichzelle create https://github.com/you/repo
weichzelle attach repo             # herdr inside the VM
```

The first `create` builds the base image, which takes a while. To use
opencode with another provider, or to drop the Claude token, see
[Secrets](#secrets).

## Secrets

Each `[secrets.<VAR>]` entry in `config.toml` becomes the env var `<VAR>` in
the VM, but its value there is only a placeholder. The real value is swapped
in at the network boundary, only in the listed `headers` (default
`authorization`) and only on requests to the listed `hosts`. The agent can't
read it or send it anywhere else.

The real value comes from `source`:

- `keyring:<name>`: the OS keyring, set with `weichzelle secret set <name>`
  (prompts, or reads stdin).
- `env:<VAR>`: an env var on the host when weichzelle runs.

Example: opencode with OpenRouter.

```toml
[network]
allow = [..., "openrouter.ai"]   # egress is separate from secrets

[secrets.OPENROUTER_API_KEY]
source = "keyring:openrouter"
hosts = ["openrouter.ai"]
headers = ["authorization"]
```

```sh
weichzelle secret set openrouter
weichzelle restart <name>        # applies network and secret changes
```

Every listed secret must resolve, or VMs won't start. Remove the entries you
don't use (e.g. `CLAUDE_CODE_OAUTH_TOKEN` without a Claude subscription).

## Commands

| Command | |
|---|---|
| `create <url> [--name n]` | New VM with a fresh clone |
| `attach <name>` / `shell <name>` | herdr / bash in the VM (starts it if stopped) |
| `start` / `stop <name>` | Stop keeps the disk |
| `restart <name>` | Stop and start; applies config changes (kills running agents) |
| `rebuild <name>` | Wipe and recreate; refuses if there is unpushed work (`--force` skips) |
| `destroy <name>` | Delete the VM and its clone |
| `list` | List VMs |
| `logs <name> --egress` | Hosts the VM tried to reach and was denied |
| `secret set\|delete <name>` | Manage keyring secrets |

Changes to `network.allow`, secrets, tool versions and provisioning apply on
the next start (`restart`). A running VM keeps its old rules until then;
`attach`, `shell` and `start` say so. VM resources need `rebuild`.
