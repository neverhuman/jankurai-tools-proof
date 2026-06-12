# Boundaries

This repository is a single-purpose Rust workspace: the Jankurai proofbind and
proofmark crates. This document is the prose companion to the machine-readable
control maps under `agent/`.

## Domain

The product domain lives entirely under `crates/jankurai-proofbind/src` and
`crates/jankurai-proofmark/src`. There is no web surface, no PostgreSQL
database, and no Python AI/data service committed in this repo, so those stack
arms of the family standard are not applicable here.

## Generated zones

Generated output is never hand-edited. The only generated zone in this repo is
`target/` (Cargo build output), declared in
[`agent/generated-zones.toml`](../agent/generated-zones.toml). It is regenerated
by the build, not committed.

## Ownership and proof

- [`agent/owner-map.json`](../agent/owner-map.json) assigns an owner to every
  top-level path that exists.
- [`agent/test-map.json`](../agent/test-map.json) routes each owned path to a
  deterministic proof command.

## Reclassification

If a future change adds a web, database, or Python surface, declare the new
boundary block in `agent/` first, then add the matching owner, test, and proof
entries before landing the code.
