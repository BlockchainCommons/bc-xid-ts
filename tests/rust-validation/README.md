# Rust reference cross-validation

Replays `tests/vectors/vectors.json` against the `bc-xid` reference: the
published `bc-xid` 0.23.0 crate from crates.io (sources `bc-xid-rust`
commit `e64924eb`) over the published `bc-envelope` 0.43.0,
`bc-components` 0.31.1, `provenance-mark` 0.24.0, `known-values` 0.15.5,
`bc-ur` 0.19.2 and `dcbor` 0.25.2. Nothing is patched. The toolchain is
pinned (`rust-toolchain.toml`: 1.98.1).

```sh
cd tests/rust-validation
cargo run --release --offline -- ../vectors/vectors.json
VERBOSE=1 cargo run --release --offline -- ../vectors/vectors.json   # full outcomes in mismatch reports
DUMP=/tmp/rust.json cargo run --release --offline -- ../vectors/vectors.json   # every reference outcome by name
```

Result line on 2026-09-16:

```
389 vectors - 362 match, 27 js-only (J3 23, J4 4), 0 unparsable, 0 MISMATCH
```

## What is compared

Every recipe (`tests/vectors/recipes.ts`) yields one outcome string on
each side and the two are compared textually. The TypeScript outcome is
the vector's `expect`, materialised by `scripts/generate-vectors.ts` with
the working tree (`tests/vectors/working-tree-adapter.ts`); the
reference's is computed by `src/main.rs`.

- Documents (`doc`): the format string, the tagged CBOR, UR and digest
  where the output is deterministic, the XID, reference, emptiness,
  counts, resolution methods, services, delegates, provenance, generator,
  a re-parse (`roundtrip`) and an inception-key verification (`verify`).
  A delegate spec may name resolution methods added to its source
  document after the delegate was built (`laterResolution`): the
  delegate's own copy does not carry them on either side.
- `decode` (a UR into `fromEnvelope` with each verification mode),
  `mutate` (scripts of mutations with their results: keys, delegates,
  services and resolution methods removed or taken, endpoints and
  service references removed, the consistency checks, both next-mark
  forms with the caller's generator advanced in place across the script,
  the generator dropped, clones), `key` and `provenance` values with each
  private-key and generator option (and, with `take`, what
  `takeGenerator` hands back and what is left), the privilege table.
- Hand-assembled envelopes: `docEnvelope`, `keyEnvelope`,
  `serviceEnvelope`, `provenanceEnvelope` build the exact envelope on
  both sides (leaves, known values, references, keys, salts, marks,
  generators, nodes, wrapped, elided and signed envelopes; assertions
  with assertions on them) and give it to the parser.
- `cbor`: bytes given to the tagged decoder (`fromCbor`, the codec) and
  the untagged one (`fromUntaggedCbor`); `ur`: a UR string given to
  `fromUR` in the reference's three steps (the UR grammar, the type check
  flattened into `dcbor::Error::Custom`, the decoder).
- `nickname`: `addNickname`/`setNickname` in sequence; `construct`: a
  caller's URI to a constructor.
- A rejection is `throw:<code>[<inner code>]|<message>`: the reference's
  error variant, the variant it wraps for `EnvelopeParsing`, `Component`,
  `Cbor` and `ProvenanceMark`, and its `Display`. A decoder entry point
  (`fromCbor`, `fromUntaggedCbor`, `fromUR`) returns the dcbor error itself
  in the reference, so its row reads `throw:Cbor[<dcbor variant>]|<dcbor
message>`; inside `fromEnvelope` the wrapping variant's own `Display`
  (`envelope parsing error`, `CBOR error`, …) is the message. A
  constructor's own input passes the components error through
  (`throw:InvalidData|invalid URI: invalid URI format`).
- The harness pins the known-values directory configuration first
  (`set_directory_config(DirectoryConfig::new())`), as the test setup file
  and the generator pin the port's, so no row reads the runner's home
  directory; then registers envelope's and provenance-mark's tags, as the
  setup file does.
- `domain` rows are the JavaScript input domain (`js-only`), in two
  classes: J3, a value the reference's types cannot express (a `null`
  where private keys go, a genesis without exactly one of a passphrase or
  a seed, a seed of the wrong length, an invalid `Date`, an unknown option
  string, a missing inception key, a plain object where a key, service,
  delegate, mark, generator, provenance or document goes, a string where
  a mark goes, the arguments of `setProvenanceWithGenerator` swapped);
  J4, a reference surface this program cannot compare (`random` with a
  genesis, whose output is random; a JavaScript `Date` at either date
  input, which this library accepts beside the reference's `CborDate`;
  generator equality after an envelope round trip).
- A recipe field this program cannot read is `unparsable`. A reference
  panic, or any other difference, is a MISMATCH. Both make the process
  exit 1.

## Reference behaviours reproduced on purpose

- A service's `'deny'` assertions are written by `toEnvelope` and
  rejected by `fromEnvelope` (`UnexpectedPredicate`, predicate 61), as the
  reference's `Service::into_envelope` and `Service::try_from` do. Rows:
  `serviceEnvelope uri(https://svc.example) +'deny':'Sign'` and the
  `roundtrip` line of every document whose service denies a privilege.
  Not yet reported upstream.

## Kept differences

- `Delegate.clone()` and `XIDDocument.clone()` copy the controller
  documents. The reference holds each controller in a shared handle, so
  its clones share the controller and two documents stay equal after a
  mutation made through a clone; that is the mechanism Rust needs to
  mutate a set element in place, which a JavaScript `Map` does not need.
  `Delegate.from` copies the controller at construction, as
  `Delegate::new` does.
- The JavaScript input domain is checked (`TypeError`); a JavaScript
  `Date` is accepted wherever the reference takes a `dcbor::Date`; the
  collection getters return copies of the reference's borrowed sets.

## Rows that guard the sibling packages

| Sibling behaviour                                                                                                                                                                  | Rows                                                                                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| envelope: identical assertions are added once; attachments are validated; `NotLeaf`, `NotWrapped`, `AmbiguousPredicate`, `NonexistentPredicate`, `NotKnownValue` inside a document | `docEnvelope … +'delegate':{…},'delegate':{…}`, `docEnvelope … +'attachment':"x"`, the `docEnvelope`/`keyEnvelope`/`serviceEnvelope` rejection rows |
| components: `Reference` rendering (`Reference(<short hex>)`), URI validity, XID and reference sizes                                                                                | `docEnvelope … +'service':…['key':ref(e9f1ab8b…)]`, the `construct` rows, `cbor untagged 581f…`                                                     |
| dcbor: tag and type errors named as the reference names them                                                                                                                       | the `cbor` rows                                                                                                                                     |
| provenance-mark: mark decoding, generator envelopes, seed length                                                                                                                   | `provenanceEnvelope` rows, `domain genesis.seed.*`                                                                                                  |
| bc-ur: grammar and type errors                                                                                                                                                     | the `ur` rows                                                                                                                                       |

## Self-checks

`mismatch.json` holds one row with a value flipped; the run must exit 1
with `1 MISMATCH`. `fixtures/classes.json` holds one row per class and
must count them as `1 match, 2 js-only (J3 1, J4 1)`;
`fixtures/malformed.json` has a recipe kind this program cannot read (`1
unparsable`) and must exit 1.

## CI

The `rust-validation` job in `.github/workflows/ci.yml` points `HOME` at an
empty directory, checks the golden file against the working tree
(`bun run test:golden`), builds the harness against the pinned crates and
toolchain (`cargo run --locked --offline` after `cargo fetch --locked`),
runs the golden file, then the mismatch and class fixtures. A MISMATCH
anywhere fails the job.

## Maintenance

When the reference moves: update the version and commit in
`.github/versions.yml` (the `upstream.yml` workflow compares against them),
update the pins in `Cargo.toml`, run `cargo update -p bc-xid`, check the
toolchain pin, regenerate the vectors (`bun run vectors:generate`), run the
replay and copy the result line above. A new difference is a bug on one
side: fix it. A JavaScript-only input becomes a class in `src/main.rs` and
here, never a difference.
