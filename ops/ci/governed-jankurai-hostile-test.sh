#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
cd "$repo_root"

# Build once before exporting hostile shell state. The second invocation must
# still use fixed toolchain paths and the in-process Rust verifier.
/usr/bin/bash ops/ci/governed-jankurai --version >/dev/null

dirname() { printf '/attacker\n'; }
realpath() { printf '/attacker/jankurai\n'; }
sha256sum() { printf '%064d  -\n' 0; }
awk() { printf 'attacker\n'; }
jq() { return 0; }
export -f dirname realpath sha256sum awk jq

actual="$(PATH=/definitely/hostile /usr/bin/bash ops/ci/governed-jankurai --version)"
if [[ "$actual" != "jankurai 1.6.11" ]]; then
  printf 'hostile verifier fixture returned an unexpected identity\n' >&2
  exit 1
fi

printf 'governed Jankurai hostile verifier fixture: ok\n'
