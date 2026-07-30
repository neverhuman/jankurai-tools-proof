#!/usr/bin/env bash
set -euo pipefail
script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir=.
cd "$script_dir/.."

lane="${1:-required}"
case "$lane" in
  required) /usr/bin/bash ops/ci/required.sh ;;
  security) /usr/bin/bash ops/ci/security.sh ;;
  contract-drift) /usr/bin/bash ops/ci/contract-drift.sh ;;
  *) echo "usage: $0 {required|security|contract-drift}" >&2; exit 2 ;;
esac
