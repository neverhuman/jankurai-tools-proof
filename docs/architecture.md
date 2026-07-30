# jankurai-tools-proof Architecture

This repository is a single-purpose Rust workspace holding the Jankurai proof
tooling crates extracted from the main auditor:

```text
crates/jankurai-proofbind   semantic surface routing + proof obligation binding
crates/jankurai-proofmark   changed-behavior proof receipt engine
schemas/                    JSON Schemas for the proof artifacts both crates emit
```

New implementation is Rust-first. There is no web, PostgreSQL, or Python AI/data
surface committed in this repo, so those arms of the family standard do not
apply here. Effects (filesystem, environment, time, networking) stay in the
library entrypoints; the pure routing and receipt logic is deterministic.

## Crate roles

- **`jankurai-proofbind`** classifies changed paths into semantic surfaces
  (public API, authz boundary, input boundary, agent-tool supply) and binds each
  surface to the proof obligations and required receipt kinds it must satisfy.
  Every declared lane and receipt kind is conjunctive. Changed test and example
  sources require a successful typed `test_execution` receipt on the declared
  lane whose `command` exactly matches the test-map/proof-lane command.
  Non-Rust fallback surfaces use that same declared-command binding rather than
  an impossible Rust Proofmark requirement. A lane may not satisfy an
  obligation by claiming an exact obligation ID or by reporting `command=true`.
- **`jankurai-proofmark`** ingests obligations plus coverage, mutation, and
  negative-proof evidence and writes a proof receipt that marks each obligation
  as `pass`, `review`, or `missing`. LCOV `DA` entries define the executable
  universe, including zero-hit lines. Git-added declarations outside that
  universe are not invented as uncovered statements, while a changed production
  file missing from the coverage inventory remains fail-closed. Legacy JSON
  that reports hits without `coverable_lines` has no trusted executable
  universe and remains `review`/`block`.

## Local workspace ownership

| Path | Role |
| --- | --- |
| `crates/` | proofbind + proofmark Rust crates (library + tests) |
| `schemas/` | JSON Schemas for proof plans, witnesses, obligations, and receipts |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |

Agents should prefer `agent/owner-map.json` and `agent/test-map.json` for
changes, then route to the smallest proof lane.
