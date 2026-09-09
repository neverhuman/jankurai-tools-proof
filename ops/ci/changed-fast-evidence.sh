#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  printf 'usage: changed-fast-evidence.sh <repo> <base-ref> <manifest> <output>\n' >&2
  exit 2
fi

repo="$1"
base_ref="$2"
manifest="$3"
output="$4"

if [[ ! -d "$repo" || -L "$repo" || ! -f "$manifest" || -L "$manifest" ]]; then
  printf '[ci] changed-fast evidence input is unavailable or unsafe\n' >&2
  exit 1
fi
repo="$(cd "$repo" && pwd -P)"
output_parent="${output%/*}"
[[ "$output_parent" != "$output" ]] || output_parent=.
if [[ ! -d "$output_parent" || -L "$output_parent" || -L "$output" ]]; then
  printf '[ci] changed-fast evidence output is unsafe\n' >&2
  exit 1
fi

/usr/bin/jq -e '
  (keys | sort) == ["evidence", "schema"]
  and .schema == "jankurai.changed-fast-supporting-evidence/v1"
  and (.evidence | type == "array" and length > 0)
  and all(
    .evidence[];
    (keys | sort) == ["class", "path"]
    and (.class == "context" or .class == "release")
    and (.path | type == "string")
    and (.path | test("^[A-Za-z0-9._/-]+$"))
    and (.path | startswith("/") | not)
    and (.path | split("/") | all(. != "" and . != "." and . != ".."))
  )
  and (([.evidence[].path] | unique | length) == (.evidence | length))
' "$manifest" >/dev/null

base_commit="$(/usr/bin/git -C "$repo" rev-parse --verify "$base_ref^{commit}")"
head_commit="$(/usr/bin/git -C "$repo" rev-parse --verify HEAD^{commit})"

/usr/bin/mkdir -p "$repo/target/jankurai"
temporary_root="$(/usr/bin/mktemp -d "$repo/target/jankurai/changed-fast-evidence.XXXXXX")"
cleanup_temporary() {
  case "$temporary_root" in
    "$repo"/target/jankurai/changed-fast-evidence.*)
      /usr/bin/rm -rf -- "$temporary_root"
      ;;
    *)
      printf '[ci] refusing unsafe changed-fast evidence cleanup\n' >&2
      return 1
      ;;
  esac
}
trap cleanup_temporary EXIT

changes_jsonl="$temporary_root/changes.jsonl"
untracked_jsonl="$temporary_root/untracked.jsonl"
evidence_jsonl="$temporary_root/evidence.jsonl"
: >"$changes_jsonl"
: >"$untracked_jsonl"
: >"$evidence_jsonl"

declare -A state_by_path=()
declare -A current_by_path=()
declare -A prior_by_path=()
mapfile -d '' -t diff_fields < <(
  /usr/bin/git -C "$repo" diff --name-status -z --find-renames "$base_commit" --
)

index=0
while [[ "$index" -lt "${#diff_fields[@]}" ]]; do
  code="${diff_fields[$index]}"
  index=$((index + 1))
  case "$code" in
    R*|C*)
      old_path="${diff_fields[$index]}"
      new_path="${diff_fields[$((index + 1))]}"
      index=$((index + 2))
      state_by_path["$old_path"]="renamed"
      state_by_path["$new_path"]="renamed"
      current_by_path["$old_path"]="$new_path"
      prior_by_path["$new_path"]="$old_path"
      /usr/bin/jq -cn \
        --arg state "renamed" \
        --arg prior_path "$old_path" \
        --arg path "$new_path" \
        '{state:$state,prior_path:$prior_path,path:$path}' \
        >>"$changes_jsonl"
      ;;
    A*|M*|D*|T*|U*)
      path="${diff_fields[$index]}"
      index=$((index + 1))
      case "${code:0:1}" in
        A) state="added" ;;
        M) state="modified" ;;
        D) state="deleted" ;;
        T) state="type_changed" ;;
        U) state="unmerged" ;;
      esac
      state_by_path["$path"]="$state"
      /usr/bin/jq -cn --arg state "$state" --arg path "$path" \
        '{state:$state,path:$path}' >>"$changes_jsonl"
      ;;
    *)
      printf '[ci] unsupported changed-fast Git status: %s\n' "$code" >&2
      exit 1
      ;;
  esac
done

declare -A untracked_paths=()
mapfile -d '' -t untracked_fields < <(
  /usr/bin/git -C "$repo" ls-files --others --exclude-standard -z
)
for path in "${untracked_fields[@]}"; do
  untracked_paths["$path"]=1
  /usr/bin/jq -cn --arg path "$path" '{path:$path}' >>"$untracked_jsonl"
done

while IFS= read -r evidence; do
  path="$(/usr/bin/jq -er '.path' <<<"$evidence")"
  class="$(/usr/bin/jq -er '.class' <<<"$evidence")"
  state=""
  current_path=""
  prior_path=""

  if [[ -n "${state_by_path[$path]:-}" ]]; then
    state="${state_by_path[$path]}"
    current_path="${current_by_path[$path]:-}"
    prior_path="${prior_by_path[$path]:-}"
  elif [[ -n "${untracked_paths[$path]:-}" ]]; then
    state="untracked"
  elif /usr/bin/git -C "$repo" ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
    if [[ ! -f "$repo/$path" || -L "$repo/$path" ]]; then
      printf '[ci] tracked supporting evidence is not a regular file: %s\n' "$path" >&2
      exit 1
    fi
    state="unchanged"
  else
    state="missing"
  fi

  /usr/bin/jq -cn \
    --arg path "$path" \
    --arg class "$class" \
    --arg state "$state" \
    --arg current_path "$current_path" \
    --arg prior_path "$prior_path" \
    '{
      path:$path,
      class:$class,
      state:$state
    }
    + (if $current_path == "" then {} else {current_path:$current_path} end)
    + (if $prior_path == "" then {} else {prior_path:$prior_path} end)' \
    >>"$evidence_jsonl"
done < <(/usr/bin/jq -c '.evidence[]' "$manifest")

temporary_output="$temporary_root/output.json"
/usr/bin/jq -s '.' "$changes_jsonl" >"$temporary_root/changes.json"
/usr/bin/jq -s 'map(.path) | sort' "$untracked_jsonl" >"$temporary_root/untracked.json"
/usr/bin/jq -s 'sort_by(.path)' "$evidence_jsonl" >"$temporary_root/evidence.json"
/usr/bin/jq -n \
  --arg base_ref "$base_ref" \
  --arg base_commit "$base_commit" \
  --arg head "$head_commit" \
  --slurpfile changed "$temporary_root/changes.json" \
  --slurpfile untracked "$temporary_root/untracked.json" \
  --slurpfile evidence "$temporary_root/evidence.json" \
  '{
    schema:"jankurai.changed-fast-evidence/v1",
    base_ref:$base_ref,
    base_commit:$base_commit,
    head:$head,
    changed_paths:$changed[0],
    untracked_paths:$untracked[0],
    supporting_evidence:$evidence[0],
    summary:(
      reduce $evidence[0][] as $item (
        {total:0};
        .total += 1
        | .[$item.state] = ((.[$item.state] // 0) + 1)
      )
    )
  }' >"$temporary_output"

/usr/bin/mv -- "$temporary_output" "$output"
trap - EXIT
cleanup_temporary
