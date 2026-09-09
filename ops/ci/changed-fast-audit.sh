#!/usr/bin/env bash
set -euo pipefail

ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  printf 'usage: changed-fast-audit.sh <base-ref> [output-dir]\n' >&2
  exit 2
fi

base_ref="$1"
output_root="${2:-target/jankurai/changed-fast}"
case "$output_root" in
  target/jankurai/*) ;;
  *)
    printf '[ci] changed-fast output must stay under target/jankurai\n' >&2
    exit 1
    ;;
esac
if [[ -L "$output_root" ]]; then
  printf '[ci] changed-fast output must not be a symlink\n' >&2
  exit 1
fi
/usr/bin/mkdir -p "$output_root"

supporting_evidence="$output_root/supporting-evidence.json"
proof_plan="$output_root/proof-plan.json"
proof_plan_md="$output_root/proof-plan.md"
score_json="$output_root/repo-score.json"
score_md="$output_root/repo-score.md"

log "changed-fast: classify tracked, untracked, renamed, deleted, and unchanged support"
/usr/bin/bash ops/ci/changed-fast-evidence.sh \
  "$REPO_ROOT" "$base_ref" \
  "$REPO_ROOT/agent/supporting-evidence.json" \
  "$supporting_evidence"

/usr/bin/jq -e '
  (.untracked_paths | length) == 0
  and all(
    .supporting_evidence[];
    .state == "unchanged" or .state == "modified" or .state == "added"
  )
' "$supporting_evidence" >/dev/null

log "changed-fast: preserve exact changed-path attribution"
run_public_jankurai proof . \
  --changed-from "$base_ref" \
  --out "$proof_plan" \
  --md "$proof_plan_md"

log "changed-fast: evaluate repository-wide rules against the full exact tree"
run_public_jankurai audit . \
  --full \
  --mode advisory \
  --policy agent/audit-policy.toml \
  --json "$score_json" \
  --md "$score_md" \
  --no-score-history

/usr/bin/jq -e --arg base "$base_ref" '
  .base_ref == $base and (.changed_paths | length > 0)
' "$proof_plan" >/dev/null
/usr/bin/jq -e '
  .scope.mode == "full"
  and .score >= 85
  and ((.caps_applied // []) | length == 0)
  and ([.findings[]? | select(.hardness == "hard")] | length == 0)
' "$score_json" >/dev/null

supporting_evidence_sha256="$(/usr/bin/sha256sum "$supporting_evidence")"
supporting_evidence_sha256="${supporting_evidence_sha256%% *}"
proof_plan_sha256="$(/usr/bin/sha256sum "$proof_plan")"
proof_plan_sha256="${proof_plan_sha256%% *}"
score_sha256="$(/usr/bin/sha256sum "$score_json")"
score_sha256="${score_sha256%% *}"

/usr/bin/jq -n \
  --arg base_ref "$base_ref" \
  --arg head "$(/usr/bin/git rev-parse HEAD)" \
  --arg supporting_evidence_sha256 "$supporting_evidence_sha256" \
  --arg proof_plan_sha256 "$proof_plan_sha256" \
  --arg score_sha256 "$score_sha256" \
  '{
    schema:"jankurai.changed-fast-audit/v1",
    base_ref:$base_ref,
    head:$head,
    attribution_scope:"exact Git change from base_ref",
    evaluation_scope:"full exact candidate tree for repository-wide rules",
    supporting_evidence_sha256:$supporting_evidence_sha256,
    proof_plan_sha256:$proof_plan_sha256,
    repo_score_sha256:$score_sha256,
    conclusion:"success"
  }' >"$output_root/receipt.json"

log "changed-fast: score, caps, hard findings, support evidence, and attribution passed"
