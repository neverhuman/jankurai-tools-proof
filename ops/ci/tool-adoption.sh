#!/usr/bin/env bash
# Tool-adoption evidence lane.
#
# jankurai replaces a fleet of ad-hoc tools (manual scoring, gitleaks-only
# security, hand-rolled coverage/contract drift checks) with first-class
# subcommands. This lane runs each adopted command in CI and writes its
# evidence artifact under target/jankurai/ so the audit can prove the
# replacement actually executed. The matching artifacts are uploaded by the
# workflow's actions/upload-artifact step.
set -euo pipefail
ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

mkdir -p target/jankurai target/jankurai/security \
         target/jankurai/proofbind target/jankurai/proofmark

# audit-ci / proof-routing / contract-drift / authz-matrix / input-boundary /
# agent-tool-supply / release-readiness / cost-budget all adopt the ratchet
# audit command.
log "tool-adoption: governed predecessor baseline"
run_governed_jankurai audit . --full --mode advisory \
  --policy agent/audit-policy.toml \
  --json target/jankurai/accepted-baseline.json \
  --md target/jankurai/accepted-baseline.md \
  --repair-queue-jsonl target/jankurai/repair-queue.jsonl \
  --no-score-history
assert_artifact target/jankurai/accepted-baseline.json
assert_artifact target/jankurai/accepted-baseline.md

log "tool-adoption: full ratchet audit"
run_governed_jankurai audit . --full --mode ratchet \
  --baseline target/jankurai/accepted-baseline.json \
  --json target/jankurai/repo-score.json \
  --md target/jankurai/repo-score.md
# Adopted artifacts: .jankurai/repo-score.json .jankurai/repo-score.md
# target/jankurai/repair-queue.jsonl

# proofbind: changed-surface proof obligation routing.
log "tool-adoption: proofbind verify"
run_governed_jankurai proofbind verify . --changed-from HEAD^
# Adopted artifacts: target/jankurai/proofbind/surface-witness.json
# target/jankurai/proofbind/obligations.json

# proofmark-rust: in-diff mutation and coverage witness for Rust.
log "tool-adoption: proofmark rust"
run_governed_jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# Adopted artifacts: target/jankurai/proofmark/proofmark-receipt.json
# target/jankurai/proofmark/proof-receipt.json

# security: secret + dependency + SBOM/provenance evidence in one lane.
log "tool-adoption: security run"
run_governed_jankurai security run . \
  --script ops/ci/security.sh \
  --out target/jankurai/security/evidence.json
# Adopted artifact: target/jankurai/security/evidence.json
