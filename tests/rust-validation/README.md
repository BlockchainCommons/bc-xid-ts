# Rust validation harness

Replays `tests/vectors/vectors.json` (203 vectors: seeded documents with every
inception kind, key scheme, privilege, delegate form, service shape,
attachments, edges, custom assertions and genesis marks, rendered with every
private-key, generator and signing option; decodes of every golden UR with
each verification mode; mutation scripts; keys and provenance values on
their own; the privilege table) against the reference crate `bc-xid` 0.23.0
(a path dependency on `../../../Rust/bc-xid-rust`).

```sh
cd tests/rust-validation
cargo run --release -- ../vectors/vectors.json
VERBOSE=1 cargo run --release -- ../vectors/vectors.json   # print every expected divergence
DUMP=/tmp/rust.json cargo run --release -- ../vectors/vectors.json   # write every Rust outcome by name
```

The program exits 1 on any `MISMATCH`. Differences that are understood are
classified (see `RUST_DIVERGENCES.md` at the package root):

| Class | Meaning |
|---|---|
| `D1` | `roundtrip`: TypeScript's `equals` ignores private-key and generator material; the reference compares it. |
| `S1` | `ECPublicKey(…)` summary: 16 hex characters and an ellipsis here, the 8-character short reference there (a bc-components-ts rendering convention). |
| `S2` | `SigningPrivateKey(…)` / `EncapsulationPrivateKey(…)` summaries: the inner key is rendered with the outer reference or its raw bytes here, with its own short reference there (bc-components-ts). |
| `E1` | An error that is not an `XIDError` (a UR or envelope parse failure) is reported by message; the reference words it differently. |

Error codes: the TypeScript `XIDError.code` is the reference's `Error`
variant name in `SCREAMING_SNAKE_CASE` (`KeyNotFoundInDocument` →
`KEY_NOT_FOUND_IN_DOCUMENT`), so codes compare directly.
