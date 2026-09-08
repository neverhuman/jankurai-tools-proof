#!/usr/bin/env bash
# The launcher tests build controlled binaries/receipts under a private TempDir.
# Production policy and the sealed-execution verifier remain unchanged.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
cargo test --locked -p jankurai-governed-launcher --lib
