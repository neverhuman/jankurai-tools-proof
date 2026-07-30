# Changelog

All notable changes to jankurai-tools-proof are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The authoritative
version string lives in [`VERSION`](VERSION).

## [Unreleased]

### Added

- Root `Justfile` command surface with `setup`, `fast`, `check`, `security`, and
  `audit` lanes for one-command setup and validation.
- GitHub Actions CI (`.github/workflows/ci.yml`) with build, security, and
  jankurai audit jobs, all third-party actions pinned to commit SHAs, each job
  delegating to `ops/ci/*.sh`.
- Agent-readable documentation: `README.md`, `docs/architecture.md`,
  `docs/boundaries.md`, `docs/testing.md`, `docs/release.md`, and
  `docs/exceptions.md`.
- `proptest` property suite and a non-owner authorization negative-proof test in
  `crates/jankurai-proofbind/tests/`.

### Changed

- Re-scoped `agent/owner-map.json`, `agent/test-map.json`, and
  `agent/generated-zones.toml` to the paths that exist in this single-purpose
  repo, and added `agent/audit-policy.toml` excluding transient build paths.
- Proofmark now intersects changed Rust lines with the LCOV coverable universe,
  retains zero-hit executable lines, and fails closed when a changed production
  file has no coverage inventory.
- Proofbind now requires every declared lane and receipt kind conjunctively and
  requires typed execution receipts on the declared test lane for changed tests
  and examples.
- The descriptor-held governed launcher now authenticates the existing
  protected 1.6.11 split.2 binary and its content-addressed installation
  receipt.

## [1.7.0] - 2026-06-12

### Added

- Initial split-family extraction of the Jankurai proofbind and proofmark
  crates.
