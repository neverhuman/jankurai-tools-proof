#!/usr/bin/env bash
set -euo pipefail
script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir=.
cd "$script_dir/.."

lane="${1:-required}"
case "$lane" in
  required) bash ops/ci/required.sh ;;
  *) echo "usage: $0 {required}" >&2; exit 2 ;;
esac
