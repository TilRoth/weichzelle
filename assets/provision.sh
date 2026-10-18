#!/bin/bash
# Runs inside the VM as `agent` on every start. Must be idempotent.
# Inputs (env): WZ_MISE_CONFIG, WZ_REPO_URL, WZ_REPO_DIR, WZ_GIT_NAME, WZ_GIT_EMAIL
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

if [ ! -d "$WZ_REPO_DIR/.git" ]; then
  log "cloning $WZ_REPO_URL"
  git clone "$WZ_REPO_URL" "$WZ_REPO_DIR"
fi

cd "$WZ_REPO_DIR"
if compgen -G 'mise.toml' >/dev/null || compgen -G '.mise.toml' >/dev/null \
   || compgen -G 'mise/config.toml' >/dev/null || compgen -G '.tool-versions' >/dev/null; then
  log "installing project toolchain"
  if ! { mise trust --yes . && mise install --yes; }; then
    log "warning: project toolchain install failed (missing egress? see: weichzelle logs --egress)"
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
