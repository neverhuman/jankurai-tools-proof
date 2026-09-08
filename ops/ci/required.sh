#!/usr/bin/env bash
# Public component proof: controlled hostile fixtures and the complete Rust suite.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
mkdir -p target/jankurai
bash ops/ci/governed-jankurai-hostile-test.sh
bash ops/ci/changed-fast-evidence-test.sh
bash ops/ci/contract-drift.sh
cargo test --workspace --locked
