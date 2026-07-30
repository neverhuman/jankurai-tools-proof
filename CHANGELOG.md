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
- Proofmark now derives the changed executable-line universe from the fixed Git
  change and candidate source, retains zero-hit LCOV lines, and treats every
  executable changed line omitted from LCOV as uncovered. Production coverage
  absence, empty intersections, and legacy hit-only JSON all block required
  proof.
- Proofbind now requires every declared lane and receipt kind conjunctively.
  Test/example and non-Rust fallback receipts must match the exact declared
  test-map/proof-lane command; self-asserted `command=true` receipts cannot
  satisfy an obligation.
- A descriptor-held Rust launcher authenticates and seals the protected
  Jankurai 1.6.11 split.2 binary and its content-addressed installation receipt
  before execution, then replaces caller state with a fixed minimal tool and
  Git configuration environment.
- Tool adoption now ratchets the candidate against the exact protected
  predecessor, executes a compiler-covered Rust contract fixture, and requires
  non-vacuous, fully satisfied Proofbind and Proofmark output.

## [1.7.0] - 2026-06-12

### Added

- Initial split-family extraction of the Jankurai proofbind and proofmark
  crates.
