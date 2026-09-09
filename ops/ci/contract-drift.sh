#!/usr/bin/env bash
set -euo pipefail
ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

readonly baseline="agent/public-api-baseline.json"
readonly output_root="$REPO_ROOT/target/jankurai/public-api"
readonly governed_toolchain="nightly-2026-06-16-x86_64-unknown-linux-gnu"
readonly governed_rustdoc_version="rustdoc 1.98.0-nightly (01dfd7924 2026-06-15)"
readonly governed_rustdoc="$(rustup which --toolchain "$governed_toolchain" rustdoc)"

if [[ ! -f "$baseline" || -L "$baseline" ]]; then
  printf '[ci] public API baseline is unavailable\n' >&2
  exit 1
fi
if [[ ! -x "$CARGO_PUBLIC_API_BIN" || -L "$CARGO_PUBLIC_API_BIN" ]]; then
  printf '[ci] governed cargo-public-api binary is unavailable\n' >&2
  exit 1
fi
if [[ "$("$CARGO_PUBLIC_API_BIN" --version)" != "$CARGO_PUBLIC_API_VERSION" ]]; then
  printf '[ci] governed cargo-public-api version mismatch\n' >&2
  exit 1
fi
if [[ ! -x "$governed_rustdoc" || -L "$governed_rustdoc" ]]; then
  printf '[ci] governed nightly rustdoc is unavailable\n' >&2
  exit 1
fi
if [[ "$("$governed_rustdoc" --version)" != "$governed_rustdoc_version" ]]; then
  printf '[ci] governed nightly rustdoc version mismatch\n' >&2
  exit 1
fi

/usr/bin/jq -e \
  --arg tool "$CARGO_PUBLIC_API_VERSION" \
  --arg rustdoc_toolchain "$governed_toolchain" \
  --arg rustdoc_version "$governed_rustdoc_version" \
  '
    (keys | sort) == ["cargo_public_api_version", "packages", "rustdoc_toolchain", "rustdoc_version", "schema_version", "simplification"]
    and .schema_version == "jankurai.public-api-baseline/v1"
    and .cargo_public_api_version == $tool
    and .rustdoc_toolchain == $rustdoc_toolchain
    and .rustdoc_version == $rustdoc_version
    and .simplification == 3
    and (.packages | keys | sort) == ["jankurai-governed-launcher", "jankurai-proofbind", "jankurai-proofmark"]
    and all(.packages[]; type == "string" and test("^[0-9a-f]{64}$"))
  ' "$baseline" >/dev/null

/usr/bin/mkdir -p "$output_root"
temporary=""
cleanup_public_api_temporary() {
  if [[ -n "$temporary" && "$temporary" == "$output_root/"*.tmp.* &&
        -f "$temporary" && ! -L "$temporary" ]]; then
    /usr/bin/rm -f -- "$temporary"
  fi
}
trap cleanup_public_api_temporary EXIT

for package in jankurai-governed-launcher jankurai-proofbind jankurai-proofmark; do
  expected="$(/usr/bin/jq -er --arg package "$package" '.packages[$package]' "$baseline")"
  output="$output_root/$package.txt"
  temporary="$(/usr/bin/mktemp "$output.tmp.XXXXXX")"
  /usr/bin/env -i \
    CARGO_HOME=${CARGO_HOME:-$HOME/.cargo} \
    CARGO_NET_OFFLINE=true \
    CARGO_TARGET_DIR="$REPO_ROOT/target/public-api" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    HOME="$HOME" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="${RUSTUP_HOME:-$HOME/.rustup}/toolchains/$governed_toolchain/bin:${CARGO_HOME:-$HOME/.cargo}/bin:/usr/bin:/bin" \
    RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup} \
    RUSTUP_TOOLCHAIN="$governed_toolchain" \
    TZ=UTC \
    "$CARGO_PUBLIC_API_BIN" --package "$package" \
      --simplified --simplified --simplified --color=never >"$temporary"
  actual="$(/usr/bin/sha256sum "$temporary")"
  actual="${actual%% *}"
  if [[ "$actual" != "$expected" ]]; then
    /usr/bin/rm -f -- "$temporary"
    printf '[ci] public API baseline mismatch: %s\n' "$package" >&2
    exit 1
  fi
  /usr/bin/mv -f -- "$temporary" "$output"
  temporary=""
  log "public API baseline verified: $package sha256:$actual"
done
trap - EXIT
