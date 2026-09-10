# Frozen baseline build

`xid-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/xid` built from
commit `c1425268d9c23764aaf396fb2c77f66475f4a434`, the pre-redesign wire-format reference. It is built from
the PUBLISHED pre-redesign packages (`@bcts/xid` 1.0.0-beta.6 and its closure,
pinned by tests/baseline/package.json), so every sibling is inlined exactly
once, with the behaviour consumers had.
`xid-baseline.d.mts` is the public surface at that commit (Phase 0.5).

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: c1425268d9c23764aaf396fb2c77f66475f4a434
Baseline sha256: fe7af93fb0dcbc7a484ef135b6f82161838c7fffa76e9f63dff60c66dd3f32a1
