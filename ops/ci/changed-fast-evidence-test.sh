#!/usr/bin/env bash
set -euo pipefail

ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

fixture_root="$(/usr/bin/mktemp -d "$REPO_ROOT/target/jankurai/changed-fast-evidence-test.XXXXXX")"
cleanup_fixture() {
  case "$fixture_root" in
    "$REPO_ROOT"/target/jankurai/changed-fast-evidence-test.*)
      /usr/bin/rm -rf -- "$fixture_root"
      ;;
    *)
      printf '[ci] refusing unsafe changed-fast fixture cleanup\n' >&2
      return 1
      ;;
  esac
}
trap cleanup_fixture EXIT

fixture_repo="$fixture_root/repo"
/usr/bin/mkdir -p "$fixture_repo/agent"
/usr/bin/git -C "$fixture_repo" init -q
/usr/bin/printf 'tracked base\n' >"$fixture_repo/tracked.md"
/usr/bin/printf 'rename base\n' >"$fixture_repo/renamed.md"
/usr/bin/printf 'delete base\n' >"$fixture_repo/deleted.md"
/usr/bin/printf 'unchanged base\n' >"$fixture_repo/unchanged.md"
/usr/bin/printf '%s\n' \
  '{' \
  '  "schema": "jankurai.changed-fast-supporting-evidence/v1",' \
  '  "evidence": [' \
  '    {"path":"tracked.md","class":"context"},' \
  '    {"path":"untracked.md","class":"context"},' \
  '    {"path":"renamed.md","class":"release"},' \
  '    {"path":"deleted.md","class":"release"},' \
  '    {"path":"unchanged.md","class":"release"}' \
  '  ]' \
  '}' \
  >"$fixture_repo/agent/supporting-evidence.json"
/usr/bin/git -C "$fixture_repo" add agent deleted.md renamed.md tracked.md unchanged.md
/usr/bin/git -C "$fixture_repo" \
  -c user.name='Changed Fast Fixture' \
  -c user.email='changed-fast@example.invalid' \
  commit -q -m base

/usr/bin/printf 'tracked change\n' >"$fixture_repo/tracked.md"
/usr/bin/git -C "$fixture_repo" mv renamed.md renamed-now.md
/usr/bin/rm -- "$fixture_repo/deleted.md"
/usr/bin/printf 'untracked change\n' >"$fixture_repo/untracked.md"

output="$fixture_root/evidence.json"
/usr/bin/bash ops/ci/changed-fast-evidence.sh \
  "$fixture_repo" HEAD \
  "$fixture_repo/agent/supporting-evidence.json" \
  "$output"

/usr/bin/jq -e '
  .schema == "jankurai.changed-fast-evidence/v1"
  and .base_ref == "HEAD"
  and .summary == {
    "deleted": 1,
    "modified": 1,
    "renamed": 1,
    "total": 5,
    "unchanged": 1,
    "untracked": 1
  }
  and ([.supporting_evidence[] | select(.path == "tracked.md" and .state == "modified")] | length) == 1
  and ([.supporting_evidence[] | select(.path == "untracked.md" and .state == "untracked")] | length) == 1
  and ([.supporting_evidence[] | select(.path == "renamed.md" and .state == "renamed" and .current_path == "renamed-now.md")] | length) == 1
  and ([.supporting_evidence[] | select(.path == "deleted.md" and .state == "deleted")] | length) == 1
  and ([.supporting_evidence[] | select(.path == "unchanged.md" and .state == "unchanged")] | length) == 1
' "$output" >/dev/null

hostile_manifest="$fixture_root/hostile.json"
/usr/bin/printf '%s\n' \
  '{"schema":"jankurai.changed-fast-supporting-evidence/v1","evidence":[{"path":"../escape","class":"context"}]}' \
  >"$hostile_manifest"
if /usr/bin/bash ops/ci/changed-fast-evidence.sh \
  "$fixture_repo" HEAD "$hostile_manifest" "$fixture_root/hostile-output.json"
then
  printf '[ci] changed-fast evidence accepted path traversal\n' >&2
  exit 1
fi

printf 'changed-fast supporting evidence classification: ok\n'
