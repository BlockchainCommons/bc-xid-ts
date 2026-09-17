# Frozen baseline build

`xid-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/xid` as it
shipped at commit `050785674b2002245d332cd9df9e094168d97fd2` (`1.0.0-beta.2`), with every `@blockchaincommons`
sibling inlined from the workspace. It also re-exports the sibling values the
differential drives it with (keys, envelopes, CBOR, known values, the
provenance generator), so they are the bundle's own classes.
`xid-baseline.d.mts` is the public surface at that commit.

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes outside the enumerated
tombstones; it pins the sha256 below so an accidental rebuild cannot turn the
differential into a self-comparison. Rebuild with
`bun scripts/build-baseline.ts 0507856`.

Baseline commit: 050785674b2002245d332cd9df9e094168d97fd2
Baseline sha256: 44de782eb959ff35f0ee98b6dd803020d7d6e0dc28f1b05f13aaf4e059e78bb2
