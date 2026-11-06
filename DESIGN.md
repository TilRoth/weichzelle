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

- **One global Containerfile:** Ubuntu 26.04 LTS (matches the host and
  GitHub's `ubuntu-latest`) with OS packages, git, jq and mise. Built with
  podman (or buildah or docker) and imported into microsandbox. The image tag is a hash of the Containerfile, so editing it
  triggers a new build on the next `create` or `rebuild`.
- **Non-root user:** agents run as `insasse` (uid 1000) with passwordless sudo.
  Claude Code refuses bypass mode as root. sudo gives nothing extra, because
  the VM is the boundary.
- **mise:** weichzelle writes the global mise config (`~/.config/mise/config.toml`)
  on every VM start: herdr and harnesses as standalone binaries, versions pinned
  in the host config. Updating = bump version on host, restart VM. The repo's own
  `mise.toml` provides the project toolchain and is never modified.
  Backends: `claude` (native binary), `herdr` (GitHub release), `gh`,
  `opencode` pinned to `aqua:anomalyco/opencode` (the default ≥ 2.0 backend is
  npm and would depend on the project's Node).
- **herdr** coordinates agents. Agents can see and drive each other via the
  herdr socket. The whole VM is one trust zone. The socket is never exposed
  outside the VM.
- **herdr config:** opt-in (`[herdr] copy_config`). weichzelle reads the
  host's `~/.config/herdr/config.toml` before starting the VM (missing file =
  error) and provisioning writes it into the VM on every start. The host copy
  wins, and edits apply after a restart. Turning it off leaves an existing copy
  in place until `rebuild`.
- **Harness profiles:** pre-written harness config that skips first-run and
  trust dialogs. Permission flags (e.g. `--auto`) are chosen when starting an
  agent. Adding a harness = a mise entry plus a profile. Claude Code's profile
  sets the onboarding and trust flags in `~/.claude.json` and turns off
  auto-updates. It doesn't set bypass mode as the default; pass
  `--dangerously-skip-permissions` when starting.
- **Provisioning** (`assets/provision.sh`) runs as `insasse` on every start, and
  must be idempotent. It writes the global mise config and installs it, sets
  the git identity and a credential helper that answers with the `GH_TOKEN`
  placeholder, clones the repo on the first run, installs the repo's mise
  toolchain (a failure only warns), and writes the harness profiles.
- **Docker:** Ubuntu's `docker.io` with buildx and compose, in every VM.
  `insasse` is in the `docker` group (no more than its sudo). There is no init
  system, so provisioning starts `dockerd` on every boot (log:
  `/var/log/dockerd.log`; a failure only warns). `/var/lib/docker` is a
  private sparse ext4 disk (`vm.docker_disk_gib`, default 40), because
  overlay2 can't sit on the overlayfs root. Docker's default networks
  (172.17+, 192.168.x) stay clear of microsandbox's guest addresses
  (172.16.0.x).
- **CA in containers:** images bring their own CA bundle, which lacks the
  interception CA, so HTTPS from containers would fail. Bypassing
  interception isn't possible: in strict mode (default) microsandbox denies
  bypassed connections allowed only by hostname, since an unverified SNI can
  be faked. Instead `assets/wz-runc` replaces `/usr/sbin/runc` (the real one
  is diverted to `runc.real` with `dpkg-divert`). On container create it
  bind-mounts the VM's bundle read-only over the CA files the image has
  (distro paths and files the image's own CA env vars name) and sets
  `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `CURL_CA_BUNDLE` where the image doesn't. Replacing runc itself covers
  BuildKit steps, which ignore dockerd's runtime settings. It never creates
  paths: runc would leave empty mount stubs in images built in the VM.
- **Environment:** `SHELL=/bin/bash` (herdr panes otherwise get `/bin/sh`,
  with no line editing), `NODE_EXTRA_CA_CERTS` pointing at the interception
  CA, and update checks turned off.

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
  interception). Values come from the host keyring
  (`weichzelle secret set|delete <name>`) or a host env var. Generic
  `{env, hosts, headers}` entries. Defaults: `CLAUDE_CODE_OAUTH_TOKEN`
  (subscription token from `claude setup-token`) and `GH_TOKEN`. Both Claude
  Code and gh accept the placeholder.
  Substitution is restricted to the credential header (`header_fields`).
  Secrets are passed to microsandbox as **host environment references, never
  raw values**: raw values get persisted in the host-side sandbox config.
- **Egress:** deny by default, plus presets (`llm`, `github`, `mise`,
  per-ecosystem registries). Rules match whole hostnames only (no paths). DNS
  limited to allowlisted names; other names get NXDOMAIN. The `mise` preset includes
  `storage.googleapis.com` (Claude Code downloads) and
  `tuf-repo-cdn.sigstore.dev` (attestation checks for GitHub releases, e.g.
  gh). The `opencode` preset allows `models.dev` and `opencode.ai` (release
  downloads since 2.x). Exact preset host lists are
  found empirically: deny-all, run the install, read the deny log.
- **Changing rules:** `config.toml` is the only source; there are no
  per-VM rules. Before each boot of a stopped VM (`start`, `restart`, or
  `attach`/`shell` on a stopped VM) weichzelle compares the VM's saved
  network policy and secrets with the config and updates them. Nothing
  changes in a running VM (microsandbox can't change a live policy);
  `attach`/`shell`/`start` on a running VM print a note when it differs, and
  `restart` applies it (killing running agents).
  Secrets go through the SDK's `modify` API, saved for the next start. The
  policy has no SDK API, so weichzelle rewrites `network.policy` in the VM's
  saved config in microsandbox's database (`msb.db`, table `sandbox`). The
  write only happens while the VM is stopped, only if the row is unchanged
  since it was read, and only if the result parses as a 0.7.8 config. After
  both steps the comparison must come out clean; any mismatch refuses the
  boot and points to `rebuild`.
- **Deny log:** microsandbox logs denials at debug level in the per-VM
  runtime log, which rotates every 10 MB (four files). Debug output is mostly
  device noise, so the log covers about the last 40 minutes of heavy use.
  `weichzelle logs <name> --egress` sums up denials per target. Known
  denials, left blocked: `herdr.dev` (herdr) and `downloads.claude.ai`
  (Claude Code).
- **Registries:** presets `dockerhub`, `ghcr`, `mcr`, on by default. Docker
  Hub serves blobs from both Cloudflare and CloudFront hosts.
- **Resources:** fixed vCPU, memory and Docker disk per VM; defaults in the
  config. The disk size is fixed at create.

## CLI (v1)

```
weichzelle create <github-url> [--name N]   # clone into a new VM
weichzelle attach <name>                     # start if stopped, open herdr
weichzelle shell <name>                      # start if stopped, open bash
weichzelle stop | start <name>
weichzelle rebuild <name> [--force]          # wipe and recreate
weichzelle destroy <name> [--force]
weichzelle list
weichzelle restart <name>                    # stop + start, applies config
weichzelle logs <name> --egress              # denied requests
weichzelle init                              # write default config
weichzelle secret set|delete <name>          # keyring values
```

## Testing

Two layers. microsandbox's own suite covers its enforcement (secret
substitution, header and host scoping, DNS, deep egress cases); weichzelle's
tests check how weichzelle configures it, plus one end-to-end smoke check per
guarantee, so an upgrade that changes defaults shows up.

- **Fast tests** (`cargo test`, also in CI): config validation, preset
  expansion, and invariants on the policy and secret spec handed to
  microsandbox (deny by default, only name rules, no TLD-wide suffixes;
  secrets are env references scoped to their hosts and headers, with
  query and body substitution off). `reconcile.rs` runs against
  `tests/fixtures/msb-0.7.8.db`, a sandbox row captured from a real 0.7.8 VM:
  drift detection, the policy rewrite, and refusing a changed row or an
  unknown format.
- **VM tests** (`cargo vmtest`, local only, one VM at a time): clone
  `github.com/TilRoth/weichzelle-fixture` into real VMs.
  - `probes`: `tests/vm/probes.sh` runs in the guest and prints one
    PASS/FAIL line per check: allowed and denied egress, NXDOMAIN, raw IPs,
    IPv6, metadata IP, a denied name on an allowed IP, host ports (a host
    listener counts hits), another VM, shared mounts and `/.msb` contents,
    the host config and herdr config, secret placeholders, Docker with the
    CA wrapper (run, build, denied), Docker's networks vs the guest's.
  - `lifecycle`: provisioning idempotency, the running-VM note, restart
    applying network and secret changes both ways, the rebuild guard,
    destroy. It also checks that the saved config still has the fixture's
    shape; `WZ_UPDATE_FIXTURE=1` rewrites the fixture instead.
  - Dummy secrets start with `wzleak`. After create and after each
    reconcile, the test home (database, configs, logs) and the guest are
    searched for it.
  - `WZ_TEST_GH_TOKEN` (optional): a real token, enables a push test.
- **Isolation:** everything lives in `~/.cache/weichzelle-test`
  (`MSB_HOME`, `XDG_CONFIG_HOME` per VM, `XDG_DATA_HOME`); the runtime comes
  from `~/.microsandbox`. Real VMs, config and keyring are never touched.
  Failed VMs are kept for debugging; the next run removes them.

## Accepted risks

- A hijacked agent can *use* injected tokens: push junk to any repo the PAT
  covers, spend LLM credit.
- Allowed hosts with write APIs (e.g. GitHub comments) can carry data out.
- libkrun treats guest and VMM as one security context, and the VMM runs as the
  user. Secret substitution runs in that same per-VM process, so a VMM escape
  gets **the real secrets and the user's privileges**.
- Allowing `storage.googleapis.com` opens an anonymous exfiltration channel
  (any publicly writable GCS bucket).
- Container registries accept pushes from any account the agent logs into,
  so they can carry data out.
- Java in containers doesn't trust the interception CA (own keystore). Images
  that only read a CA path the wrapper doesn't know fail too.
- An agent can bypass the CA wrapper (root via sudo). It only breaks its own
  HTTPS.
- weichzelle writes into microsandbox's internal database to change a VM's
  network policy. A microsandbox upgrade that changes the format makes
  `start` refuse (it never boots a half-applied policy), and weichzelle must
  be fixed before VMs start again without a `rebuild`.
- Agent PRs appear as the user's own (GitHub forbids self-approval).
- With `herdr.copy_config` on, the agent can read the host herdr config
  (custom commands, paths in it).

## Fact-check results (microsandbox v0.7.x, 2026-10-18)

1. **Secrets:** substituted in the per-VM runner process, which also runs
   libkrun and the userspace network stack (`crates/runtime/lib/runner/vm.rs`).
2. **Root filesystem:** virtio-blk (read-only EROFS image layers + ext4 writable
   upper). Only virtiofs: a small runtime mount (`/.msb`). Networking is
   virtio-net into microsandbox's smoltcp stack (not libkrun TSI).
3. **TTY:** interactive attach gives a real PTY with resize handling. The
   detach key (default `Ctrl-]`) is configurable. Works with herdr. The herdr
   server keeps running after you detach, so sessions survive.
4. **mise:** see "Inside the VM". The aqua opencode backend carries current
   versions (1.19.3 when tested).
5. **mise egress:** GitHub hosts (incl. release-asset CDN,
   `raw.githubusercontent.com`), `mise-versions.jdx.dev`,
   `storage.googleapis.com`, plus per-language hosts (`nodejs.org`, …).
   Exact list found empirically.
6. **Docker (2026-10-24, Ubuntu 26.04, Docker 29.1):** guest kernel 6.12 has
   everything built in (cgroup v2, overlay, netfilter, bridge, netns). Root is
   overlayfs; PID 1 is `/init.krun`. Docker uses the containerd image store,
   and BuildKit steps don't go through dockerd's `default-runtime`. Guest
   IPv4 addresses come from 172.16.0.0/12, lowest free /30 first
   (`runtime/network_slot.rs`); recheck on upgrades that Docker's ranges
   stay clear.

## Future work

- Per-repo config sections with repo-scoped tokens.
- GitHub App for short-lived tokens.
- Containing the VMM process (dedicated user, jail).
- neovim and lazygit inside the VM.
- Two-phase start: boot with a wider install policy (e.g. `storage.googleapis.com`
  for downloads), run installs, then restart with the strict usage policy.
  Caveat: the repo's `mise.toml` is agent-editable, so anything it triggers runs
  inside the wider window.
