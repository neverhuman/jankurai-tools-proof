# jankurai-tools-proof

Status: initial split-family extraction
Owner: Jankurai maintainers
Last reviewed: 2026-06-12
Applies to: jankurai-tools-proof

## Role

Proofbind, proofmark, proof receipt helpers, and proof schemas.

## Repositories

- Historical Jeryu repo: `root/jankurai-tools-proof`
- Primary GitHub repository: `neverhuman/jankurai-tools-proof`
- Release tag pattern: `jankurai-tools-proof-v1.7.0-split.0`
- Source extraction commit: `cea83b0cbe204be276a2f0299cd760f6812ea2b0`

## Split Rules

- GitHub is authoritative; Jeryu refs remain historical inputs.
- Release builds depend on immutable GitHub tags, not branches.
- Local development uses the hub `scripts/fuse.sh` output under `.fusion/`.
- Committed manifests must not depend on sibling checkout paths.
- Generated outputs are regenerated from their source contracts or build commands.

## Required Local Check

```bash
bash scripts/ci-local.sh required
```
