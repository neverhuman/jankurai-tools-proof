#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_jankurai
log "required lane: workspace tests"
cargo test --workspace --locked
