#!/bin/bash
# Health probes, run in the VM as `insasse` by `weichzelle doctor`. Read-only.
# Prints one line per check: `<id> ok|fail|skip`. The host only reads these
# lines; any other output is ignored.
# Inputs (env): WZ_REPO_DIR, WZ_RUNC_SHA256
set -u

# probe <id> <seconds> <cmd…>
probe() {
  local id=$1 secs=$2; shift 2
  # A child bash, so `timeout` can run the functions below too.
  if timeout -k 1 "$secs" bash -c '"$@"' _ "$@" </dev/null >/dev/null 2>&1; then
    echo "$id ok"
  else
    echo "$id fail"
  fi
}

has_project_mise() {
  local f
  for f in mise.toml .mise.toml mise/config.toml .tool-versions; do
    [ -e "$WZ_REPO_DIR/$f" ] && return 0
  done
  return 1
}

# Succeeds if `mise ls --missing` in $1 lists nothing.
none_missing() {
  cd "$1" || return 1
  local out
  out=$(mise ls --missing --no-header "${@:2}") || return 1
  [ -z "$out" ]
}

below_90() {
  local pct
  pct=$(df --output=pcent "$1" | tail -n 1 | tr -dc '0-9') || return 1
  [ -n "$pct" ] && [ "$pct" -lt 90 ]
}

runc_wrapped() {
  [ -e /usr/sbin/runc.real ] || return 1
  [ "$(sha256sum /usr/sbin/runc | cut -d' ' -f1)" = "$WZ_RUNC_SHA256" ]
}

export -f has_project_mise none_missing below_90 runc_wrapped

probe repo 5 git -C "$WZ_REPO_DIR" rev-parse --git-dir
probe tools 10 none_missing "$HOME" --global
probe herdr 5 herdr --version
if [ -d "$WZ_REPO_DIR" ] && has_project_mise; then
  probe toolchain 10 none_missing "$WZ_REPO_DIR" --current
else
  echo "toolchain skip"
fi
if command -v dockerd >/dev/null; then
  probe docker 5 docker info
  probe runc 5 runc_wrapped
else
  echo "docker skip"
  echo "runc skip"
fi
probe disk-root 5 below_90 /
probe disk-docker 5 below_90 /var/lib/docker
