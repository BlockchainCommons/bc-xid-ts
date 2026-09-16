import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { format } from "@blockchaincommons/envelope/format";
/**
 * Edge tests
 * Ported from bc-xid-rust/tests/edge.rs
 */

import { PrivateKeyBase } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { Envelope } from "@blockchaincommons/envelope";
import { IS_A, SOURCE, TARGET } from "@blockchaincommons/known-values";
import {
  edgeIsA,
  edgeSource,
  edgeTarget,
  edgeSubject,
  validateEdge,
} from "@blockchaincommons/envelope/edge";
import { XIDDocument } from "../src";

/**
 * Helper to create a basic edge envelope with the three required assertions.
 */
function makeEdge(subject: string, isA: string, source: Envelope, target: Envelope): Envelope {
  return Envelope.from(subject)
    .addAssertion(IS_A, isA)
    .addAssertion(SOURCE, source)
    .addAssertion(TARGET, target);
}

describe("Edge", () => {
  describe("Adding and querying edges", () => {
    it("should initially have no edges", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      expect(xidDocument.hasEdges()).toBe(false);
      expect([...xidDocument.edges()]).toEqual([]);
      expect(xidDocument.edges().size).toBe(0);
    });

    it("should add edge", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      const edge = makeEdge("knows-bob", "schema:colleague", alice, bob);

      xidDocument.addEdge(edge);

      expect(xidDocument.hasEdges()).toBe(true);
      expect(xidDocument.edges().size).toBe(1);
    });

    it("should add multiple edges", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      const edge1 = makeEdge("knows-bob", "schema:colleague", alice, bob);
      const edge2 = makeEdge("self-desc", "foaf:Person", alice, alice);

      xidDocument.addEdge(edge1);
      xidDocument.addEdge(edge2);

      expect(xidDocument.edges().size).toBe(2);
    });

    it("should get edge by digest", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      const digest = edge.digest();

      xidDocument.addEdge(edge);

      const retrieved = xidDocument.getEdge(digest);
      expect(retrieved).toBeDefined();
      expect(retrieved?.isEquivalentTo(edge)).toBe(true);
    });

    it("should return undefined for nonexistent edge", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);

      expect(xidDocument.getEdge(edge.digest())).toBeUndefined();
    });

    it("should remove edge", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      const digest = edge.digest();

      xidDocument.addEdge(edge);
      expect(xidDocument.hasEdges()).toBe(true);

      const removed = xidDocument.removeEdge(digest);
      expect(removed).toBeDefined();
      expect(xidDocument.hasEdges()).toBe(false);
    });

    it("should return undefined when removing nonexistent edge", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);

      const removed = xidDocument.removeEdge(edge.digest());
      expect(removed).toBeUndefined();
    });

    it("should clear edges", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      xidDocument.addEdge(makeEdge("e1", "foaf:Person", alice, alice));
      xidDocument.addEdge(makeEdge("e2", "schema:colleague", alice, bob));
      expect(xidDocument.edges().size).toBe(2);

      xidDocument.clearEdges();
      expect(xidDocument.hasEdges()).toBe(false);
      expect(xidDocument.edges().size).toBe(0);
    });
  });

  describe("Envelope format with edges", () => {
    it("should round-trip single edge through envelope", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);

      const envelope = xidDocument.toEnvelope();

      // Round-trip
      const xidDocument2 = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(xidDocument2)).toBe(true);
    });

    it("should round-trip multiple edges through envelope", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      const edge1 = makeEdge("self-desc", "foaf:Person", alice, alice);
      const edge2 = makeEdge("knows-bob", "schema:colleague", alice, bob);
      xidDocument.addEdge(edge1);
      xidDocument.addEdge(edge2);

      const envelope = xidDocument.toEnvelope();

      // Round-trip
      const xidDocument2 = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(xidDocument2)).toBe(true);
      expect(xidDocument2.edges().size).toBe(2);
    });
  });

  describe("UR round-trip", () => {
    it("should round-trip edges through envelope UR", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      xidDocument.addEdge(makeEdge("cred-1", "foaf:Person", alice, alice));
      xidDocument.addEdge(makeEdge("knows-bob", "schema:colleague", alice, bob));

      // Round-trip through envelope UR string
      const envelope = xidDocument.toEnvelope();
      const ur = envelope.toUR().toString();
      const recoveredEnvelope = decodeURWith(UR.parse(ur), Envelope.codec);
      const recovered = XIDDocument.fromEnvelope(recoveredEnvelope);

      expect(xidDocument.equals(recovered)).toBe(true);
      expect(recovered.edges().size).toBe(2);
    });
  });

  describe("Signed documents with edges", () => {
    it("should preserve edges in signed document", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);

      const signedEnvelope = xidDocument.toEnvelope({ sign: "inception" });

      // Recover with signature verification
      const recovered = XIDDocument.fromEnvelope(signedEnvelope, { verify: "inception" });
      expect(xidDocument.xid.equals(recovered.xid)).toBe(true);
      expect(recovered.hasEdges()).toBe(true);
      expect(recovered.edges().size).toBe(1);
    });
  });

  describe("Encrypted keys with edges", () => {
    it("should coexist with encrypted keys", { timeout: 60_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);

      const password = new TextEncoder().encode("test_password");
      const envelope = xidDocument.toEnvelope({
        privateKeys: { encrypt: password, method: KeyDerivationMethod.Argon2id },
      });

      // Round-trip with decryption
      const recovered = XIDDocument.fromEnvelope(envelope, { password: password });
      expect(xidDocument.equals(recovered)).toBe(true);
      expect(recovered.hasEdges()).toBe(true);
    });
  });

  describe("Persistence", () => {
    it("should persist edges after modifications", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);
      expect(xidDocument.hasEdges()).toBe(true);

      // Add a resolution method — edges should still be present
      xidDocument.addResolutionMethod("https://resolver.example.com");
      expect(xidDocument.hasEdges()).toBe(true);
      expect(xidDocument.edges().size).toBe(1);

      // Serialize and recover
      const envelope = xidDocument.toEnvelope();
      const recovered = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(recovered)).toBe(true);
      expect(recovered.hasEdges()).toBe(true);
    });
  });

  describe("Edge accessors", () => {
    it("should extract edge properties", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      const edge = makeEdge("knows-bob", "schema:colleague", alice, bob);
      const digest = edge.digest();

      xidDocument.addEdge(edge);

      const retrieved = xidDocument.getEdge(digest);
      expect(retrieved).toBeDefined();
      expect(retrieved === undefined ? undefined : edgeIsA(retrieved).asText()).toBe(
        "schema:colleague",
      );
      expect(retrieved === undefined ? undefined : edgeSource(retrieved).asText()).toBe("Alice");
      expect(retrieved === undefined ? undefined : edgeTarget(retrieved).asText()).toBe("Bob");
      expect(retrieved === undefined ? undefined : edgeSubject(retrieved).asText()).toBe(
        "knows-bob",
      );
    });
  });

  describe("Edge iteration", () => {
    it("should iterate and validate edges", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      xidDocument.addEdge(makeEdge("e1", "foaf:Person", alice, alice));
      xidDocument.addEdge(makeEdge("e2", "schema:colleague", alice, bob));
      xidDocument.addEdge(makeEdge("e3", "schema:CreativeWork", alice, bob));

      let count = 0;
      for (const edgeEnv of xidDocument.edges()) {
        validateEdge(edgeEnv); // Should not throw
        count++;
      }
      expect(count).toBe(3);
    });
  });

  describe("Additional assertions", () => {
    it("should support edges with claim detail on target per BCR-2026-003", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      // Per BCR-2026-003, claim detail goes on the target object,
      // not on the edge subject.
      const bob = Envelope.from("Bob")
        .addAssertion("department", "Engineering")
        .addAssertion("since", "2024-01-15");
      const edge = makeEdge("knows-bob", "schema:colleague", alice, bob);

      xidDocument.addEdge(edge);

      const envelope = xidDocument.toEnvelope();

      // Round-trip preserves target assertions
      const recovered = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(recovered)).toBe(true);

      const [recoveredEdge] = [...recovered.edges()];
      validateEdge(recoveredEdge); // Should not throw
      expect(edgeIsA(recoveredEdge).asText()).toBe("schema:colleague");
      expect(format(edgeTarget(recoveredEdge))).toContain('"department"');
    });
  });

  describe("Coexistence with attachments", () => {
    it("should coexist with attachments", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);
      xidDocument.addAttachment({ payload: "metadata", vendor: "com.example" });

      expect(xidDocument.hasEdges()).toBe(true);
      expect(xidDocument.hasAttachments).toBe(true);

      const envelope = xidDocument.toEnvelope();
      const recovered = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(recovered)).toBe(true);
      expect(recovered.hasEdges()).toBe(true);
      expect(recovered.hasAttachments).toBe(true);
    });
  });

  describe("Edge equality", () => {
    it("should preserve equality through round-trip", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const alice = Envelope.from("Alice");
      const edge = makeEdge("cred-1", "foaf:Person", alice, alice);
      xidDocument.addEdge(edge);

      // Round-trip through envelope should produce equal documents
      const envelope = xidDocument.toEnvelope();
      const recovered = XIDDocument.fromEnvelope(envelope);
      expect(xidDocument.equals(recovered)).toBe(true);
    });
  });

  describe("Edge removal", () => {
    it("should leave other edges intact when removing one", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });

      const alice = Envelope.from("Alice");
      const bob = Envelope.from("Bob");
      const edge1 = makeEdge("e1", "foaf:Person", alice, alice);
      const edge2 = makeEdge("e2", "schema:colleague", alice, bob);
      const digest1 = edge1.digest();
      const digest2 = edge2.digest();

      xidDocument.addEdge(edge1);
      xidDocument.addEdge(edge2);
      expect(xidDocument.edges().size).toBe(2);

      xidDocument.removeEdge(digest1);
      expect(xidDocument.edges().size).toBe(1);
      expect(xidDocument.getEdge(digest2)).toBeDefined();
      expect(xidDocument.getEdge(digest1)).toBeUndefined();
    });
  });
});
