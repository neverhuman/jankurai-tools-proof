# Release process

This document is the release control surface for jankurai-tools-proof. It covers
the version source, the changelog, the release automation, integrity and SBOM
evidence, and rollback. Launch gates require every section below to be backed by
a real artifact or command.

## Version source

The single source of truth for the version is the [`VERSION`](../VERSION) file at
the repository root. The crate versions in
`crates/jankurai-proofbind/Cargo.toml` and `crates/jankurai-proofmark/Cargo.toml`
and any release tag MUST stay coherent with `VERSION`. Tags follow the family
pattern `jankurai-tools-proof-v<MAJOR.MINOR.PATCH>-split.<N>` as described in
[`SPLIT.md`](../SPLIT.md).

## Changelog

Every release records its user-visible changes in
[`CHANGELOG.md`](../CHANGELOG.md) under a heading that matches the new `VERSION`.
The `Unreleased` section is promoted to a dated version heading at tag time.

## Release automation

Releases are cut by CI, not by hand:

1. Bump [`VERSION`](../VERSION) and promote the `Unreleased` section of
   [`CHANGELOG.md`](../CHANGELOG.md).
2. Run the full local gate: `just check` (format, lint, fast lane, security,
   self-audit).
3. Push the version commit. The
   [`ci.yml`](../.github/workflows/ci.yml) workflow runs the build, security, and
   jankurai audit jobs and uploads the `repo-score` artifacts.
4. Tag the release commit with `jankurai-tools-proof-v<version>-split.<N>`. The
   tag mirror in [`.jeryu/repo.toml`](../.jeryu/repo.toml) publishes the
   immutable tag to the public GitHub mirror.

Release builds depend on immutable tags, never branches.

## Integrity, provenance, and SBOM

- **Dependency integrity**: builds are reproducible because `Cargo.lock` is
  committed and every CI lane uses `--locked`.
- **SBOM**: generate a CycloneDX software bill of materials from the locked
  dependency graph with `cargo cyclonedx --format json` (run in CI alongside the
  security job) and attach it to the release as `sbom.json`.
- **Provenance**: the security job runs `gitleaks detect` for secret scanning and
  `cargo audit` for advisory checks; the audit job publishes the `repo-score`
  artifacts that prove the release passed the jankurai gate.
- **Action pinning**: every third-party GitHub Action is pinned to a 40-character
  commit SHA so the supply chain of the release pipeline itself is fixed.

## Launch gate

The release launch gate is the final checklist that must be green, with
artifact-backed evidence, before any tag is published. No release ships until
every item below has a real proof artifact, not a prose claim:

- **Security**: the `security` job (`gitleaks detect` + `cargo audit`) is green
  and its log is attached.
- **Backups**: this is a library workspace with no datastore, so the backup
  obligation is the committed `Cargo.lock` plus the immutable source tag; any
  consumer-facing data backup is the consumer's launch gate, not this repo's.
- **Monitoring**: the jankurai audit job publishes `repo-score` artifacts that
  are the monitoring signal for score regressions across releases.
- **Rollback**: the rollback procedure below is rehearsed and its last-known-good
  tag is recorded.
- **Abuse and rate limit controls**: the proof crates expose no network surface,
  so rate limit / abuse controls are out of scope here; downstream services that
  embed these crates own that launch-gate item.

A failing launch-gate item blocks the release; it is never waived silently.

## Rollback

If a release regresses:

1. Identify the last known-good tag
   (`jankurai-tools-proof-v<version>-split.<N>`).
2. Re-point consumers at that immutable tag; tags are never moved or deleted.
3. Open a revert commit that restores the previous `VERSION` and `CHANGELOG.md`
   state, and add a `### Fixed` entry describing the rollback.
4. Re-run `just check` to confirm the rolled-back tree is green before
   re-publishing.

Because tags are immutable and `Cargo.lock` is committed, any prior release can
be rebuilt bit-for-bit from its tag.
