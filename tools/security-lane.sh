#!/usr/bin/env bash
# Canonical security entrypoint expected by governed Jankurai security runs.
set -euo pipefail
script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir=.
repo_root="$(cd "$script_dir/.." && pwd -P)"
exec bash "$repo_root/ops/ci/security.sh"
