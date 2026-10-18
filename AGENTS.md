# AGENTS.md

weichzelle is a Rust CLI that runs one long-lived microsandbox VM per GitHub
repo, for coding agents coordinated by herdr. Read `DESIGN.md` first: it holds
the threat model, the decisions and the accepted risks. Keep it current when
behaviour changes.

## Layout

- `src/main.rs`: clap CLI and dispatch.
- `src/config.rs`: the global host config (`~/.config/weichzelle/config.toml`),
  parsed strictly (`deny_unknown_fields`).
- `src/vm.rs`: VM lifecycle on the microsandbox SDK (create, start, attach,
  destroy, …).
- `src/image.rs`: builds the base image from the Containerfile with
  podman/buildah/docker and imports it into microsandbox.
- `src/network.rs`: egress presets and allowlist expansion.
- `src/secrets.rs`: keyring/env secret sources.
- `src/logs.rs`: egress denials from the microsandbox runtime log.
- `assets/`: compiled into the binary: the default `config.toml` and
  `Containerfile` (written by `weichzelle init`) and `provision.sh` (run in the
  VM on every start).

## Commands

```
cargo build
cargo test
cargo clippy
./target/debug/weichzelle <command>
```

Testing in a VM needs KVM, the microsandbox runtime (`~/.microsandbox`, `msb`
on PATH) and podman. Secrets live in the keyring under the service
`weichzelle`.

## Rules

- **Commits:** no `Co-Authored-By` or other attribution trailers.
- **Security first.** The agent inside the VM is assumed hostile. Never pass
  raw secret values to microsandbox (they end up persisted on disk); use
  `SecretSource::Env`. Never expose host paths, sockets or the host config to
  the guest. Network rules stay deny-by-default.
- **microsandbox is pinned** (`=0.7.8`). Check the SDK source in
  `~/.cargo/registry/src/*/microsandbox-0.7.8` instead of guessing APIs. Many
  types live under `microsandbox::sandbox::` instead of the crate root.
- **`provision.sh` must be idempotent.** It runs as `agent` on every start.
  Merge into existing harness config files (jq) instead of overwriting them.
- **Secrets are exported** into the process env in `main` before the tokio
  runtime starts (`set_var` isn't safe once threads exist).
- **The network policy and secrets are fixed when a VM is created.** Changes
  to them only reach a VM through `rebuild`. Tools and provisioning changes
  apply on the next start.
- Keep code comments short and plain.

## Debugging a VM

- `msb ls` lists all sandboxes; weichzelle's are prefixed `wz-`.
- `msb exec` mangles quoted arguments. Pipe scripts in base64:
  `msb exec wz-<name> -- sudo -E -u agent bash -c "echo <b64> | base64 -d | bash"`.
  `-E` keeps the secret placeholders in the environment.
- Logs: `~/.microsandbox/sandboxes/wz-<name>/logs/` (`runtime.log*`,
  `exec.log`). Denials: `weichzelle logs <name> --egress`.
- Missing egress host: deny-all, run the failing install, read the deny log,
  add the host to a preset in `src/network.rs`.
- `attach` needs a real terminal; provisioning streams output and works
  without one.
