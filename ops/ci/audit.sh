#!/usr/bin/env bash
# Jankurai self-audit lane: writes the repo-score artifacts that CI uploads.
# The same lane runs locally via `just audit`.
set -euo pipefail
ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

mkdir -p .jankurai
log "audit lane: jankurai audit -> .jankurai/repo-score.{json,md}"
run_public_jankurai audit . --no-score-history --full \
  --json .jankurai/repo-score.json \
  --md .jankurai/repo-score.md

assert_artifact .jankurai/repo-score.json
assert_artifact .jankurai/repo-score.md

if [[ -f agent/badge.toml && -f agent/jankurai-badge.svg ]]; then
  log "audit lane: first-party badge presence"
  grep -q 'jankurai-badge:start' README.md
  test -s agent/jankurai-badge.svg
  test -s agent/jankurai-badge.json
fi
