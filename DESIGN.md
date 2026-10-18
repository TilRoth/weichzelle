# weichzelle — design

A long-running VM per GitHub repo, in which coding agent harnesses (Claude Code,
opencode, …) run unmodified and fully autonomous, coordinated by herdr.

## Threat model

The agent is assumed **hostile** (e.g. prompt-injected): it will try to escape,
steal credentials and exfiltrate data. Local, single user (no multi-tenancy).

## Stack

- **VM layer:** [microsandbox](https://github.com/superradcompany/microsandbox)
  (libkrun on KVM), pinned version (currently v0.7.x), running as the invoking
  user.
- **weichzelle:** Rust CLI built on microsandbox's Rust SDK.
- **Host:** Linux x86_64 only.

## Repos and work flow

- Each VM gets a **fresh clone from GitHub**. Nothing is mounted from the host.
- Work leaves the VM **only via push / PRs on GitHub**, as the user's own
  account (fine-grained PAT). No co-author trailers.
- **Rebuild wipes everything** (OS and clone). Before wiping, weichzelle lists
  unpushed commits, uncommitted changes and stashes, and refuses without
  `--force`. (This check is for avoiding accidental loss, not a security
  control: a compromised VM can lie.)

## Inside the VM

- **One global Containerfile:** OS packages, mise, git, gh.
- **mise:** weichzelle writes the global mise config (`~/.config/mise/config.toml`)
  on every VM start: herdr and harnesses as standalone binaries, versions pinned
  in the host config. Updating = bump version on host, restart VM. The repo's own
  `mise.toml` provides the project toolchain and is never modified.
  Backends: `claude` (native binary), `herdr` (GitHub release),
  `opencode` pinned to `aqua:anomalyco/opencode` (the default ≥ 2.0 backend is
  npm and would depend on the project's Node).
- **herdr** coordinates agents. Agents can see and drive each other via the
  herdr socket. The whole VM is one trust zone. The socket is never exposed
  outside the VM.
- **Harness profiles:** pre-written harness config that skips first-run and
  trust dialogs. Permission flags (e.g. `--auto`) are chosen when starting an
  agent. Adding a harness = a mise entry plus a profile.

## Access

- **Milestone 1:** `weichzelle attach` runs herdr via microsandbox exec with a TTY.
- **Milestone 2:** herdr remote machines over microsandbox's host-side SSH
  server: generated `~/.ssh/config` entry with
  `ProxyCommand msb ssh serve <name> --stdio`. No sshd, port or keys in the
  guest. SSH inactivity timeout disabled (`inactivity_timeout_secs: 0`).
  `ForwardAgent no`.

## Secrets and network

- **One global host config** (`~/.config/weichzelle/config.toml`), no per-repo
  settings. Never visible to the VM.
- **Secrets:** the VM only sees placeholders. The host injects the real value
  only on requests to the hosts listed for that secret (microsandbox TLS
  interception). Values come from the host keyring. Generic
  `{env, hosts, header}` entries, starting with Anthropic (API key) and GitHub.
  Substitution is restricted to the credential header (`header_fields`).
  Secrets are passed to microsandbox as **host environment references, never
  raw values**: raw values get persisted in the host-side sandbox config.
- **Egress:** deny by default, plus presets (`llm`, `github`, `mise`,
  per-ecosystem registries). Rules match whole hostnames only (no paths). DNS
  limited to allowlisted names. Denied requests are logged. The `mise` preset
  includes `storage.googleapis.com` (Claude Code downloads). Exact preset host
  lists are found empirically: deny-all, run the install, read the deny log.
- **Resources:** fixed vCPU and memory per VM; defaults in the config.

## CLI (v1)

```
weichzelle create <github-url> [--name N]   # clone into a new VM
weichzelle attach <name>                     # start if stopped, open herdr
weichzelle stop | start <name>
weichzelle rebuild <name> [--force]          # wipe and recreate
weichzelle destroy <name> [--force]
weichzelle list
weichzelle logs <name> --egress              # denied requests
```

## Accepted risks

- A hijacked agent can *use* injected tokens: push junk to any repo the PAT
  covers, spend LLM credit.
- Allowed hosts with write APIs (e.g. GitHub comments) can carry data out.
- libkrun treats guest and VMM as one security context, and the VMM runs as the
  user. Secret substitution runs in that same per-VM process, so a VMM escape
  gets **the real secrets and the user's privileges**.
- Allowing `storage.googleapis.com` opens an anonymous exfiltration channel
  (any publicly writable GCS bucket).
- Agent PRs appear as the user's own (GitHub forbids self-approval).

## Fact-check results (microsandbox v0.7.x, 2026-10-18)

1. **Secrets:** substituted in the per-VM runner process, which also runs
   libkrun and the userspace network stack (`crates/runtime/lib/runner/vm.rs`).
2. **Root filesystem:** virtio-blk (read-only EROFS image layers + ext4 writable
   upper). Only virtiofs: a small runtime mount (`/.msb`). Networking is
   virtio-net into microsandbox's smoltcp stack (not libkrun TSI).
3. **TTY:** interactive attach gives a real PTY with resize handling. The
   detach key (default `Ctrl-]`) is configurable. Still to test with herdr.
4. **mise:** see "Inside the VM". Still to check that the aqua opencode backend
   carries current versions.
5. **mise egress:** GitHub hosts (incl. release-asset CDN,
   `raw.githubusercontent.com`), `mise-versions.jdx.dev`,
   `storage.googleapis.com`, plus per-language hosts (`nodejs.org`, …).
   Exact list found empirically.

## Future work

- Subscription login via `claude setup-token`.
- Per-repo config sections with repo-scoped tokens.
- GitHub App for short-lived tokens.
- Automated `weichzelle selftest`, re-run on every microsandbox upgrade
  (v1: manual checklist).
- Containing the VMM process (dedicated user, jail).
- neovim and lazygit inside the VM.
- Two-phase start: boot with a wider install policy (e.g. `storage.googleapis.com`
  for downloads), run installs, then restart with the strict usage policy.
  Caveat: the repo's `mise.toml` is agent-editable, so anything it triggers runs
  inside the wider window.
