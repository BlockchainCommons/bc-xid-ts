# Divergences from the Rust reference implementation

This library is a TypeScript port of
[`BlockchainCommons/bc-xid-rust`](https://github.com/BlockchainCommons/bc-xid-rust),
tracked at version **0.23.0**
([`e64924eb`](https://github.com/BlockchainCommons/bc-xid-rust/commit/e64924eb04e7af3303674663f217768095d73475)).

The tracked version and commit are recorded in
[`.github/versions.yml`](./.github/versions.yml).

This document is the deliberate record of every place the TypeScript behaviour
differs from the Rust reference. It has three kinds of entry:

1. **True behavioral divergences** - the same input produces a different outcome.
2. **JS-only input domain** - inputs that have no Rust analog, so there is nothing to diverge from.
3. **Mapping equivalences** - JS-specific inputs that are validated through the bytes they produce.

Every entry below is checked by `tests/rust-validation`, a Rust program that
builds `bc-xid` at the tracked commit and replays
`tests/vectors/vectors.json` (203 vectors: seeded documents covering every
inception kind, key scheme, privilege, delegate form, service shape,
attachments, edges, custom assertions and genesis marks, each rendered with
every private-key, generator and signing option — format string, tagged
CBOR, UR and digest where deterministic, the document's fields, a re-parse
and an inception-key verification; decodes of every golden UR with each
verification mode; mutation scripts with their error codes; keys and
provenance values on their own; the privilege table). The current run:
**184 match, 19 expected divergences, 0 mismatches.**

Every wire output that both sides produce deterministically — the envelope
format string, the tagged CBOR, the UR, the digest, the XID, references,
identifiers, every error code and the round-trip equality — is
byte-identical; the expected divergences are the two rendering conventions
and the error-message wording listed below.

## 1. True behavioral divergences

_None._ (The pre-redesign `equals` compared public content only, so a
document re-parsed from an envelope that omitted, elided or locked its
private keys or generator still compared equal — 100 vectors diverged from
the reference's `PartialEq`. The redesign compares every field, private
material, salts and the generator included, as the reference does.)

## 2. JS-only input domain

- **Non-XID error messages (E1, 3 vectors).** A UR or envelope that fails to
  parse before the document is examined surfaces the underlying library's
  message (`Bytewords error (invalid word)`, `the envelope's subject is not a
  leaf`); the reference wraps the same failures as `UR decoder error` /
  `Error::EnvelopeParsing`. The `XIDError` codes themselves are identical.

## 3. Mapping equivalences

- **`ECPublicKey` summaries (S1, 2 vectors).** `bc-components-ts` renders
  `ECPublicKey(<first 16 hex>...)`; the reference renders the key's
  8-character short reference. Only the format string differs; the CBOR is
  identical (see the components package's `RUST_DIVERGENCES.md`).
- **Private-key summaries (S2, 14 vectors).** `SigningPrivateKey(ref,
  SchnorrPrivateKey(<outer ref>))` and `EncapsulationPrivateKey(X25519,
  <raw bytes>...)` here versus `SigningPrivateKey(ref, SchnorrPrivateKey(<inner
  ref>))` and `EncapsulationPrivateKey(ref, X25519PrivateKey(ref))` there —
  the inner summaries are rendering conventions of `bc-components-ts`; the
  keys and their CBOR are identical.
- Documents are built from seeded `PrivateKeyBase` material (32 bytes of
  hex), so every key, XID, reference, provenance chain and digest is
  reproducible on both sides; outputs that draw randomness (salts on
  included private keys, encryption nonces, Schnorr signatures) are compared
  through the format string only.
- Error codes are the reference's `Error` variant names in
  `SCREAMING_SNAKE_CASE`.
- A mark inside a document renders as raw tagged CBOR
  (`1347571542([…])`) on both sides: neither side registers the
  provenance-mark summariser for these vectors.

## Maintenance

When the upstream reference moves:

1. Port the relevant changes.
2. Update `.github/versions.yml` and the tracked version at the top of this file.
3. Re-run `tests/rust-validation`; add, amend, or remove entries as the port requires.
