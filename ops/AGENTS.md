# Proof tooling operations

This directory owns the local and CI entrypoints for the Proofbind, Proofmark,
and governed-auditor evidence lanes.

- Keep commands deterministic, offline after dependencies are present, and
  rooted in the canonical checkout.
- Never select Jankurai from ambient `PATH`; use `ops/ci/governed-jankurai`.
- Do not create worktrees, publish refs, or write outside ignored `target/` and
  the declared `.jankurai/` score outputs.
- Run `bash scripts/ci-local.sh required`, `bash ops/ci/audit.sh`, and
  `bash ops/ci/tool-adoption.sh` after changing these entrypoints.
