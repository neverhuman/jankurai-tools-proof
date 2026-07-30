#!/usr/bin/env bash
set -euo pipefail
ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

build_governed_jankurai_launcher
require_governed_jankurai
/usr/bin/bash ops/ci/governed-jankurai-hostile-test.sh
/usr/bin/bash ops/ci/changed-fast-evidence-test.sh
/usr/bin/bash ops/ci/contract-drift.sh
log "required lane: workspace tests"
cargo test --workspace --locked
