# jankurai-tools-proof Testing

Testing is routed proof. Agents should not guess which tests matter; the
machine-readable route lives in [`agent/test-map.json`](../agent/test-map.json).

| Lane | Purpose |
| --- | --- |
| `fast` | deterministic local proof for most edits (`cargo check` + `cargo nextest run`) |
| `test` | the full workspace test suite for both crates |
| `security` | secret scanning (`gitleaks`) plus dependency review (`cargo audit`) |
| `audit` | jankurai repo score and hard-rule findings, written to `.jankurai/repo-score.{json,md}` |
| `check` | release/merge gate: format, lint, fast, security, and self-audit |

## Crate proof suites

- **`jankurai-proofbind`** carries integration tests under
  `crates/jankurai-proofbind/tests/` plus a `proptest` property suite that
  exercises surface classification invariants. The authorization boundary path
  is covered by a direct negative-proof test that asserts a non-owner request is
  forbidden, satisfying `HLT-022-AUTHZ-ISOLATION-GAP`.
- **`jankurai-proofmark`** carries integration tests under
  `crates/jankurai-proofmark/tests/` that prove obligations move from `review`
  to `pass` only when the matching coverage, mutation, and negative-behavior
  proof receipts are present. Its hostiles retain zero-hit LCOV lines, reject
  legacy hit-only JSON as an executable-universe claim, reject absent production
  coverage, and keep test/example source out of the production LCOV denominator.
- **Receipt completeness** tests prove that every required lane and receipt kind
  must be present. Test and example sources accept only a successful typed
  `extensions.test_execution` receipt with the right kind, lane, and exact
  declared command. Non-Rust mapped surfaces likewise require the exact
  declared command; self-asserted `true` receipts remain missing.
- **Non-circular lane proof** is required. A script cannot use its own not-yet-
  completed receipt as evidence. Map the implementation path to a lower-level
  focused hostile/contract lane; the outer orchestrator may emit the higher-
  level lane receipt only after that command actually returns successfully.

Run everything with `cargo nextest run --workspace` (lane `fast`/`test`).

## Repair receipts and telemetry

When a proof lane fails, keep the next agent on the shortest possible rerun path.

- Emit structured errors instead of only free-form prose whenever the tool can do it.
- Record the failing command, exit code, changed paths, artifact paths, and the
  rerun command in the receipt.
- Prefer typed telemetry or JSON envelopes under `target/jankurai/` over ad hoc
  log spam.
- Surface the repair hint, docs URL, and common fixes together so the next rerun
  is obvious.

Observability repairs should stay typed. Each crate's proof receipt carries a
typed surface with `purpose`, `reason`, `common fixes`, a `docs_url`, and a
`repair_hint` field so the next rerun stays local instead of forcing a re-read of
chat history. An opaque failure with no `reason` and no `docs_url` is itself a
finding, not a pass.

## Budgets, quotas, and stops

Paid or unbounded work needs an explicit ceiling before it starts. These crates
run no paid APIs, but the proof lanes still declare their bounds:

- State the **budget** in time, runner minutes, or CI dollars for every lane.
- State the **quota** or spend cap that stops the run: the workspace test and
  audit lanes carry a fixed `timeout-minutes` in `.github/workflows/ci.yml`.
- State the **kill switch** / **stop condition**: a non-zero exit from any
  `ops/ci/*.sh` lane is the stop condition that aborts the pipeline, and the
  `spend cap` for an unbounded proof loop is the lane timeout above.
- Capture evidence of the stop in the receipt so the next agent can tell a
  planned stop from a silent failure.

## Agent-friendly exceptions

The default answer is "follow the standard." When a rule must be waived, follow
the dated, owned, expiring exception pattern documented in
[`docs/exceptions.md`](exceptions.md). Every exception records its `purpose`, the
`reason` it exists, the `common fixes` that remove it, and a `docs_url` /
`repair_hint` so the next agent can close it locally.
