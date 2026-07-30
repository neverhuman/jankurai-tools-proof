#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
cd "$repo_root"

# Build once before exporting hostile shell state. Subsequent invocations must
# still use fixed tool/config paths and the in-process Rust verifier.
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

hostile_root="$repo_root/target/jankurai/governed-launcher-hostile"
/usr/bin/rm -rf "$hostile_root"
/usr/bin/mkdir -p "$hostile_root/home"
/usr/bin/printf '[diff]\n\texternal = /bin/true\n' >"$hostile_root/home/.gitconfig"

/usr/bin/env \
  PATH=/definitely/hostile \
  HOME="$hostile_root/home" \
  GIT_CONFIG_GLOBAL="$hostile_root/home/.gitconfig" \
  GIT_EXTERNAL_DIFF=/bin/true \
  RUSTC_WRAPPER=/bin/false \
  CARGO_HOME="$hostile_root/cargo" \
  /usr/bin/bash ops/ci/governed-jankurai audit . --full --no-score-history \
    --json target/jankurai/governed-launcher-hostile/audit.json \
    --md target/jankurai/governed-launcher-hostile/audit.md

/usr/bin/env \
  PATH=/definitely/hostile \
  HOME="$hostile_root/home" \
  GIT_CONFIG_GLOBAL="$hostile_root/home/.gitconfig" \
  GIT_EXTERNAL_DIFF=/bin/true \
  /usr/bin/bash ops/ci/governed-jankurai proof . --changed-from HEAD^ \
    --out target/jankurai/governed-launcher-hostile/proof-plan.json \
    --md target/jankurai/governed-launcher-hostile/proof-plan.md

/usr/bin/jq -e '.score >= 85 and ((.hard_caps // []) | length == 0)' \
  "$hostile_root/audit.json" >/dev/null
/usr/bin/jq -e '.base_ref == "HEAD^" and (.changed_paths | length > 0)' \
  "$hostile_root/proof-plan.json" >/dev/null

printf 'governed Jankurai hostile verifier fixture: ok\n'
