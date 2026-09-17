import { format } from "@blockchaincommons/envelope/format";
/**
 * Custom (extension) assertion preservation tests
 * Ported from bc-xid-rust/tests/custom_assertions.rs
 *
 * Verifies that top-level assertions which are not recognized XID document
 * fields are preserved through parse → mutate → serialize round-trips, per
 * the 0.23.0 "Preserve XID document extension assertions" change.
 */

import { PrivateKeyBase } from "@blockchaincommons/components";
import { cbor } from "@blockchaincommons/dcbor";
import { SeededRng } from "@blockchaincommons/rand";
import { Key, XIDDocument } from "../src";

/**
 * Builds a XID document, serializes it, tacks on a custom top-level
 * assertion, then re-parses — yielding a document that carries the custom
 * assertion as a preserved extension assertion.
 *
 * Mirrors Rust `xid_document_with_custom_assertion()`.
 */
function xidDocumentWithCustomAssertion(): XIDDocument {
  const rng = SeededRng.forTesting();
  const privateKeyBase = PrivateKeyBase.random({ rng: rng });
  const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.schnorrPublicKeys() });
  const envelope = xidDocument.toEnvelope().addAssertion("customField", "customValue");

  return XIDDocument.fromEnvelope(envelope);
}

describe("Custom assertion preservation", () => {
  it("xid_document_parses_and_preserves_custom_assertions", () => {
    const xidDocument = xidDocumentWithCustomAssertion();
    const envelope = xidDocument.toEnvelope({
      sign: "none",
    });

    const expected = [
      "XID(71274df1) [",
      '    "customField": "customValue"',
      "    'key': PublicKeys(eb9b1cae, SigningPublicKey(71274df1, SchnorrPublicKey(9022010e)), EncapsulationPublicKey(b4f7059a, X25519PublicKey(b4f7059a))) [",
      "        'allow': 'All'",
      "    ]",
      "]",
    ].join("\n");

    expect(format(envelope)).toBe(expected);
  });

  it("xid_document_key_mutation_preserves_custom_assertions", () => {
    const xidDocument = xidDocumentWithCustomAssertion();

    const rng = SeededRng.forTesting();
    // Advance the deterministic RNG past the inception-key derivation so the
    // second key differs (mirrors Rust's `let _inception_base = ...`).
    PrivateKeyBase.random({ rng: rng });
    const secondBase = PrivateKeyBase.random({ rng: rng });
    xidDocument.addKey(Key.allowAll(secondBase.schnorrPublicKeys()));

    const envelope = xidDocument.toEnvelope({
      sign: "none",
    });

    expect(format(envelope)).toContain('"customField": "customValue"');
    expect(xidDocument.keys.length).toBe(2);
  });

  it("xid_document_provenance_mutation_preserves_custom_assertions", () => {
    const rng = SeededRng.forTesting();
    const privateKeyBase = PrivateKeyBase.random({ rng: rng });
    const xidDocument = XIDDocument.from({
      inceptionKey: privateKeyBase.schnorrPublicKeys(),
      genesis: {
        passphrase: "test passphrase",
        resolution: "high",
        date: new Date(Date.UTC(2024, 0, 1)),
        info: cbor("Genesis"),
      },
    });
    const envelope = xidDocument
      .toEnvelope({ generator: "include" })
      .addAssertion("customField", "customValue");

    const parsedDocument = XIDDocument.fromEnvelope(envelope);
    parsedDocument.nextProvenanceMarkWithEmbeddedGenerator({
      date: new Date(Date.UTC(2024, 0, 2)),
      info: cbor("Next"),
    });

    const advancedEnvelope = parsedDocument.toEnvelope({ generator: "include" });

    expect(format(advancedEnvelope)).toContain('"customField": "customValue"');
    expect(parsedDocument.provenance?.seq).toBe(1);
  });
});
