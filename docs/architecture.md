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
- **`jankurai-proofmark`** ingests obligations plus coverage, mutation, and
  negative-proof evidence and writes a proof receipt that marks each obligation
  as `pass`, `review`, or `missing`.

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
