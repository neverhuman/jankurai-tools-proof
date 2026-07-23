#!/usr/bin/env bash
# Shared CI helper module sourced by every ops/ci/<lane>.sh script.
# Single source of truth for tool version pins and artifact assertions so
# local runs and GitHub Actions execute the exact same commands.
set -euo pipefail

# Resolve the repository root regardless of where a lane is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

# Pinned tool versions. Lanes read these so CI and local environments match.
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"
export GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
export CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.21.0}"
export NEXTEST_VERSION="${NEXTEST_VERSION:-0.9}"

# Governed Jankurai identity. These values are deliberately not configurable:
# CI must fail closed rather than selecting an ambient, fused, or self-installed
# executable.
readonly GOVERNED_JANKURAI_BIN="/home/ubuntu/.jeryu/bin/jankurai"
readonly GOVERNED_JANKURAI_VERSION="jankurai 1.6.11"
readonly GOVERNED_JANKURAI_SHA256="fdb42e5fa7d9851c0729e59bf1e582c895aa9cfc03a7175b420c6025d2fd014e"
readonly GOVERNED_JANKURAI_RECEIPT="/home/ubuntu/.jeryu/receipts/jankurai/sha256/494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98.json"
readonly GOVERNED_JANKURAI_RECEIPT_SHA256="494ea02af28e6aa7fb2f817831dc8f00df102398677779f7decfce55b3b20b98"

# log <message> -- emit a structured progress line.
log() {
  printf '[ci] %s\n' "$*"
}

# require_tool <binary> -- fail fast with an actionable message when a pinned
# tool is missing from PATH so local parity gaps surface before the lane runs.
require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$tool" >&2
    return 1
  fi
}

# Verify the governed binary and production receipt before executing any
# Jankurai command. Canonical-path checks reject symlinks in the file or any
# parent component; hashes are checked before the executable is invoked.
require_jankurai() {
  local binary_real binary_sha receipt_real receipt_sha version

  if [ ! -f "$GOVERNED_JANKURAI_BIN" ] || [ ! -x "$GOVERNED_JANKURAI_BIN" ] ||
     [ -L "$GOVERNED_JANKURAI_BIN" ]; then
    printf '[ci] governed Jankurai is missing, non-regular, non-executable, or a symlink: %s\n' "$GOVERNED_JANKURAI_BIN" >&2
    return 1
  fi
  binary_real="$(realpath -e -- "$GOVERNED_JANKURAI_BIN")" || return 1
  if [ "$binary_real" != "$GOVERNED_JANKURAI_BIN" ]; then
    printf '[ci] governed Jankurai path is not canonical: %s -> %s\n' "$GOVERNED_JANKURAI_BIN" "$binary_real" >&2
    return 1
  fi

  if [ ! -f "$GOVERNED_JANKURAI_RECEIPT" ] || [ -L "$GOVERNED_JANKURAI_RECEIPT" ]; then
    printf '[ci] governed Jankurai receipt is missing, non-regular, or a symlink: %s\n' "$GOVERNED_JANKURAI_RECEIPT" >&2
    return 1
  fi
  receipt_real="$(realpath -e -- "$GOVERNED_JANKURAI_RECEIPT")" || return 1
  if [ "$receipt_real" != "$GOVERNED_JANKURAI_RECEIPT" ]; then
    printf '[ci] governed Jankurai receipt path is not canonical: %s -> %s\n' "$GOVERNED_JANKURAI_RECEIPT" "$receipt_real" >&2
    return 1
  fi

  binary_sha="$(sha256sum -- "$GOVERNED_JANKURAI_BIN" | awk '{print $1}')"
  if [ "$binary_sha" != "$GOVERNED_JANKURAI_SHA256" ]; then
    printf '[ci] governed Jankurai digest mismatch: expected %s, got %s\n' "$GOVERNED_JANKURAI_SHA256" "$binary_sha" >&2
    return 1
  fi
  receipt_sha="$(sha256sum -- "$GOVERNED_JANKURAI_RECEIPT" | awk '{print $1}')"
  if [ "$receipt_sha" != "$GOVERNED_JANKURAI_RECEIPT_SHA256" ]; then
    printf '[ci] governed Jankurai receipt digest mismatch: expected %s, got %s\n' "$GOVERNED_JANKURAI_RECEIPT_SHA256" "$receipt_sha" >&2
    return 1
  fi

  version="$(JANKURAI_NO_UPDATE_CHECK=1 GIT_TERMINAL_PROMPT=0 "$GOVERNED_JANKURAI_BIN" --version)"
  if [ "$version" != "$GOVERNED_JANKURAI_VERSION" ]; then
    printf '[ci] governed Jankurai version mismatch: expected %s, got %s\n' "$GOVERNED_JANKURAI_VERSION" "$version" >&2
    return 1
  fi
}

jankurai_run() {
  require_jankurai
  JANKURAI_NO_UPDATE_CHECK=1 GIT_TERMINAL_PROMPT=0 "$GOVERNED_JANKURAI_BIN" "$@"
}

# assert_artifact <path> -- confirm a lane produced the artifact it promised.
assert_artifact() {
  local artifact="$1"
  if [ ! -e "$REPO_ROOT/$artifact" ]; then
    printf '[ci] expected artifact missing: %s\n' "$artifact" >&2
    return 1
  fi
  log "artifact present: $artifact"
}
