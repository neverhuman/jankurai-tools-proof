# jankurai-tools-proof

[![CI](https://img.shields.io/badge/ci-pinned--lanes-green.svg)](.github/workflows/ci.yml)
[![jankurai audit](https://img.shields.io/badge/jankurai--audit-pass-green.svg)](docs/testing.md)

Rust source for the **Jankurai** proof tooling crates: `jankurai-proofbind`
(semantic surface routing and proof obligation binding) and `jankurai-proofmark`
(changed-behavior proof receipt engine). This repository is one member of the
Jankurai split family; read [`SPLIT.md`](SPLIT.md) for the family contract and
[`AGENTS.md`](AGENTS.md) for agent routing rules.

## Stack

Rust core + TypeScript/React/Vite product surface + PostgreSQL truth + generated
contracts + exception-only Python AI/data service. This member ships only the
Rust proof crates; new implementation is Rust-first. See
[`docs/architecture.md`](docs/architecture.md).

## Quick start

```bash
# One-command setup (toolchain + locked dependencies).
just setup

# Deterministic fast lane (check + tests).
just fast

# Full local check: format, lint, fast, security, and self-audit.
just check
```

The full command surface lives in the root [`Justfile`](Justfile). Continuous
integration runs the same lanes under
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Layout

| Path | Role |
| --- | --- |
| `crates/jankurai-proofbind` | semantic surface routing + obligation binding |
| `crates/jankurai-proofmark` | changed-behavior proof receipt engine |
| `schemas/` | JSON Schemas for the proof artifacts |
| `agent/` | machine-readable owner, test, boundary, and proof maps |
| `docs/` | architecture, testing, boundaries, release, and exception docs |
| `ops/` | pinned CI script entrypoints |
| `scripts/` | local CI and fusion helpers |

## Documentation

- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Boundaries](docs/boundaries.md)
- [Release process](docs/release.md)
- [Agent exceptions and overrides](docs/exceptions.md)

## Versioning

The current version is recorded in [`VERSION`](VERSION) and the change history in
[`CHANGELOG.md`](CHANGELOG.md). Release mechanics are documented in
[`docs/release.md`](docs/release.md).

## License

See [`LICENSE`](LICENSE).
