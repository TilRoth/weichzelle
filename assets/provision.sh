#!/bin/bash
# Runs inside the VM as `agent` on every start. Must be idempotent.
# Inputs (env): WZ_MISE_CONFIG, WZ_REPO_URL, WZ_REPO_DIR, WZ_GIT_NAME, WZ_GIT_EMAIL,
# WZ_RUNC (assets/wz-runc),
# WZ_HERDR_CONFIG (only set when herdr.copy_config is on)
set -euo pipefail

log() { printf '\033[1m[weichzelle]\033[0m %s\n' "$*"; }

# Global tools (harnesses, herdr, gh). Rewritten each start, so a version
# bump in the host config takes effect on restart.
mkdir -p ~/.config/mise
printf '%s\n' "$WZ_MISE_CONFIG" > ~/.config/mise/config.toml
log "installing global tools"
mise install --yes

git config --global user.name "$WZ_GIT_NAME"
git config --global user.email "$WZ_GIT_EMAIL"
git config --global init.defaultBranch main
if [ -n "${GH_TOKEN:-}" ]; then
  # GH_TOKEN is a placeholder; the host swaps in the real token for github.com.
  git config --global --replace-all credential.https://github.com.helper \
    '!f() { test "$1" = get && echo username=x-access-token && echo "password=$GH_TOKEN"; }; f'
fi

# Host herdr config, rewritten each start. Left alone when copying is off.
if [ -n "${WZ_HERDR_CONFIG+x}" ]; then
  mkdir -p ~/.config/herdr
  printf '%s' "$WZ_HERDR_CONFIG" > ~/.config/herdr/config.toml
fi

# Docker. No init system in the VM, so dockerd is started here on every boot.
# Failures only warn: the VM stays usable without Docker.
setup_docker() {
  if ! command -v dockerd >/dev/null; then
    log "docker is not in the image; skipping (see the default Containerfile)"
    return 0
  fi
  # CA wrapper (assets/wz-runc) in place of runc, so BuildKit steps get it
  # too (they don't use dockerd's runtime settings). Takes effect for the
  # next container; no daemon restart needed.
  if [ ! -e /usr/sbin/runc.real ]; then
    sudo dpkg-divert --quiet --local --rename --divert /usr/sbin/runc.real --add /usr/sbin/runc \
      || return 1
  fi
  if ! printf '%s' "$WZ_RUNC" | sudo cmp -s - /usr/sbin/runc; then
    printf '%s' "$WZ_RUNC" | sudo tee /usr/sbin/runc >/dev/null && sudo chmod 755 /usr/sbin/runc \
      || return 1
  fi
  if ! sudo docker info >/dev/null 2>&1; then
    log "starting dockerd"
    # A pid file left over from the last boot blocks the start.
    pgrep -x dockerd >/dev/null || sudo rm -f /var/run/docker.pid
    sudo sh -c 'setsid dockerd >>/var/log/dockerd.log 2>&1 </dev/null &'
    for _ in $(seq 40); do sudo docker info >/dev/null 2>&1 && break; sleep 0.5; done
    sudo docker info >/dev/null 2>&1 || return 1
  fi
  docker info >/dev/null 2>&1 || log "warning: dockerd runs, but agent can't reach its socket"
}
setup_docker || log "warning: docker setup failed (see /var/log/dockerd.log in the VM)"

if [ ! -d "$WZ_REPO_DIR/.git" ]; then
  log "cloning $WZ_REPO_URL"
  git clone "$WZ_REPO_URL" "$WZ_REPO_DIR"
fi

cd "$WZ_REPO_DIR"
if compgen -G 'mise.toml' >/dev/null || compgen -G '.mise.toml' >/dev/null \
   || compgen -G 'mise/config.toml' >/dev/null || compgen -G '.tool-versions' >/dev/null; then
  log "installing project toolchain"
  if ! { mise trust --yes . && mise install --yes; }; then
    log "warning: project toolchain install failed (missing egress? see: weichzelle logs $(basename "$WZ_REPO_DIR") --egress)"
  fi
fi

# Harness profiles: skip first-run and trust dialogs so agents started by an
# orchestrator never block on a prompt nobody can answer.
setup_claude() {
  local f=~/.claude.json tail=""
  [ -f "$f" ] || echo '{}' > "$f"
  [ -n "${ANTHROPIC_API_KEY:-}" ] && tail="${ANTHROPIC_API_KEY: -20}"
  jq --arg dir "$WZ_REPO_DIR" --arg tail "$tail" '
      .hasCompletedOnboarding = true
    | .bypassPermissionsModeAccepted = true
    | .autoUpdates = false
    | .customApiKeyResponses.approved =
        (((.customApiKeyResponses.approved // []) + (if $tail == "" then [] else [$tail] end)) | unique)
    | .customApiKeyResponses.rejected = (.customApiKeyResponses.rejected // [])
    | .projects[$dir].hasTrustDialogAccepted = true
    | .projects[$dir].hasCompletedProjectOnboarding = true
  ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

setup_opencode() {
  local f=~/.config/opencode/opencode.json
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  jq '."$schema" = "https://opencode.ai/config.json" | .autoupdate = false' "$f" > "$f.tmp" \
    && mv "$f.tmp" "$f"
}

setup_claude
setup_opencode
log "ready: $WZ_REPO_DIR"
