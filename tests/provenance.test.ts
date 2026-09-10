import { format } from "@blockchaincommons/envelope/format";
/**
 * Provenance tests
 * Ported from bc-xid-rust/tests/provenance.rs
 */

import { PrivateKeyBase } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { ProvenanceMarkGenerator } from "@blockchaincommons/provenance-mark";
import { cbor } from "@blockchaincommons/dcbor";
import { Provenance, XIDDocument, XIDError } from "../src";

describe("Provenance", () => {
  describe("Basic provenance", () => {
    it("should create provenance with mark", () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });

      const provenance = Provenance.from(mark);
      expect(provenance.mark.equals(mark)).toBe(true);
      expect(provenance.generator).toBeUndefined();

      // Round-trip through envelope
      const envelope = provenance.toEnvelope();
      const provenance2 = Provenance.fromEnvelope(envelope);
      expect(provenance.equals(provenance2)).toBe(true);
    });
  });

  describe("Provenance with generator", () => {
    it("should omit generator by default", () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      // Create a fresh generator for storage
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");

      const provenanceIncludingGenerator = Provenance.from(mark, { generator: generator });
      const provenanceOmittingGenerator = Provenance.from(mark);

      // Default envelope omits generator
      const envelopeOmitting = provenanceIncludingGenerator.toEnvelope();
      const provenance2 = Provenance.fromEnvelope(envelopeOmitting);
      expect(provenance2.generator).toBeUndefined();
      expect(provenanceOmittingGenerator.equals(provenance2)).toBe(true);
    });

    it("should include generator when specified", () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");

      const provenanceIncludingGenerator = Provenance.from(mark, { generator: generator });

      // Include generator
      const envelopeIncluding = provenanceIncludingGenerator.toEnvelope({ generator: "include" });
      const provenance2 = Provenance.fromEnvelope(envelopeIncluding);
      expect(provenance2.generator).toBeDefined();
      expect(provenanceIncludingGenerator.equals(provenance2)).toBe(true);
    });

    it("should elide generator when specified", () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");

      const provenanceIncludingGenerator = Provenance.from(mark, { generator: generator });
      const provenanceOmittingGenerator = Provenance.from(mark);

      // Elide generator
      const envelopeEliding = provenanceIncludingGenerator.toEnvelope({ generator: "elide" });
      const provenance2 = Provenance.fromEnvelope(envelopeEliding);
      expect(provenance2.generator).toBeUndefined();
      expect(provenanceOmittingGenerator.equals(provenance2)).toBe(true);

      // Elided envelope should be equivalent to included envelope (same digest)
      const envelopeIncluding = provenanceIncludingGenerator.toEnvelope({ generator: "include" });
      expect(envelopeEliding.digest().equals(envelopeIncluding.digest())).toBe(true);
    });
  });

  describe("Encrypted generator", () => {
    it("should encrypt and decrypt generator with password", { timeout: 60_000 }, () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const password = new TextEncoder().encode("correct_horse_battery_staple");

      const provenance = Provenance.from(mark, { generator: generator });

      // Encrypt the generator
      const envelopeEncrypted = provenance.toEnvelope({ generator: { encrypt: password } });

      // Extract without password - generator is None
      const provenanceNoPassword = Provenance.fromEnvelope(envelopeEncrypted);
      expect(provenanceNoPassword.generator).toBeUndefined();
      expect(provenanceNoPassword.mark.equals(mark)).toBe(true);

      // Extract with wrong password - generator is None
      const wrongPassword = new TextEncoder().encode("wrong_password");
      const provenanceWrongPassword = Provenance.fromEnvelope(envelopeEncrypted, {
        password: wrongPassword,
      });
      expect(provenanceWrongPassword.generator).toBeUndefined();

      // Extract with correct password - generator is available
      const provenanceDecrypted = Provenance.fromEnvelope(envelopeEncrypted, {
        password: password,
      });
      expect(provenanceDecrypted.generator).toBeDefined();
      expect(provenance.equals(provenanceDecrypted)).toBe(true);
    });
  });

  describe("Generator storage modes", () => {
    it("should handle all storage modes correctly", { timeout: 30_000 }, () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");

      const provenance = Provenance.from(mark, { generator: generator });

      // Mode 1: Omit (default)
      const envelopeOmit = provenance.toEnvelope();
      const provenanceOmit = Provenance.fromEnvelope(envelopeOmit);
      expect(provenanceOmit.generator).toBeUndefined();

      // Mode 2: Include
      const envelopeInclude = provenance.toEnvelope({ generator: "include" });
      const provenanceInclude = Provenance.fromEnvelope(envelopeInclude);
      expect(provenance.equals(provenanceInclude)).toBe(true);

      // Mode 3: Elide
      const envelopeElide = provenance.toEnvelope({ generator: "elide" });
      const provenanceElide = Provenance.fromEnvelope(envelopeElide);
      expect(provenanceElide.generator).toBeUndefined();
      expect(envelopeElide.digest().equals(envelopeInclude.digest())).toBe(true);

      // Mode 4: Encrypt
      const password = new TextEncoder().encode("secure_password");
      const envelopeEncrypt = provenance.toEnvelope({ generator: { encrypt: password } });
      const provenanceNoPassword = Provenance.fromEnvelope(envelopeEncrypt);
      expect(provenanceNoPassword.generator).toBeUndefined();
      const provenanceWithPassword = Provenance.fromEnvelope(envelopeEncrypt, {
        password: password,
      });
      expect(provenance.equals(provenanceWithPassword)).toBe(true);
    });
  });

  describe("Advancing provenance marks", () => {
    it("should advance with embedded generator", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const passphrase = "test_passphrase";
      const date1 = new Date(Date.UTC(2025, 0, 1));

      const xidDoc = XIDDocument.from({
        inceptionKey: privateKeyBase.ed25519PublicKeys(),
        genesis: { passphrase, resolution: "high", date: date1, info: cbor("Genesis mark") },
      });

      // Verify initial state
      const mark1 = xidDoc.provenance;
      expect(mark1).toBeDefined();
      expect(mark1?.seq).toBe(0);

      // Advance the provenance mark
      const xidDoc2 = xidDoc.clone();
      const date2 = new Date(Date.UTC(2025, 0, 2));
      xidDoc2.nextProvenanceMark({ date: date2, info: cbor("Second mark") });

      // Verify advancement
      const mark2 = xidDoc2.provenance;
      expect(mark2).toBeDefined();
      expect(mark2?.seq).toBe(1);

      // Verify generator is still available and advanced
      const generator = xidDoc2.provenanceGenerator;
      expect(generator).toBeDefined();
      expect(generator?.nextSeq).toBe(2);
    });

    it("should advance with provided generator", () => {
      // Create a generator
      const passphrase = "test_passphrase";
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", passphrase);

      // Generate genesis mark
      const date1 = new Date(Date.UTC(2025, 0, 1));
      const mark1 = generator.next(date1, { info: cbor("Genesis mark") });

      // Create XID document WITHOUT embedded generator
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocBase = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });
      const xidDoc = XIDDocument.fromXid(xidDocBase.xid);
      xidDoc.setProvenance(mark1);

      // Verify initial state
      expect(xidDoc.provenance?.seq).toBe(0);
      expect(xidDoc.provenanceGenerator).toBeUndefined();

      // Advance using the provided generator
      const date2 = new Date(Date.UTC(2025, 0, 2));
      xidDoc.nextProvenanceMark({ generator: generator, date: date2, info: cbor("Second mark") });

      // Verify advancement
      const mark2 = xidDoc.provenance;
      expect(mark2?.seq).toBe(1);

      // Generator should still be external
      expect(xidDoc.provenanceGenerator).toBeUndefined();

      // External generator should be advanced
      expect(generator.nextSeq).toBe(2);
    });
  });

  describe("Provenance errors", () => {
    it("should error when advancing without provenance mark", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const xidDoc = XIDDocument.from({ inceptionKey: privateKeyBase });

      // X1c: pin the specific error code/message rather than just `.toThrow()`,
      // so future regressions in error-classification get caught at write time.
      let caught: unknown;
      try {
        xidDoc.nextProvenanceMark({ info: cbor("Test") });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(XIDError);
      expect((caught as XIDError).code).toBe("NoProvenanceMark");
      expect((caught as XIDError).message).toBe("no provenance mark to advance");
    });

    it("should error when advancing without generator", () => {
      // Create a mark without generator
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test") });

      // Create XID document with mark but no generator
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocBase = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });
      const xidDoc = XIDDocument.fromXid(xidDocBase.xid);
      xidDoc.setProvenance(mark);

      expect(() => {
        xidDoc.nextProvenanceMark({ info: cbor("Test") });
      }).toThrow();
    });

    it("should error on generator conflict", () => {
      const passphrase = "test_passphrase";
      const date = new Date(Date.UTC(2025, 0, 1));
      const privateKeyBase = PrivateKeyBase.random();

      const xidDoc = XIDDocument.from({
        inceptionKey: privateKeyBase.ed25519PublicKeys(),
        genesis: { passphrase, resolution: "high", date, info: cbor("Genesis mark") },
      });

      // Create external generator
      const externalGenerator = ProvenanceMarkGenerator.fromPassphrase("high", passphrase);

      // Try to advance with provided generator (should fail because document has embedded generator)
      let caught: unknown;
      try {
        xidDoc.nextProvenanceMark({ generator: externalGenerator, info: cbor("Test") });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(XIDError);
      expect((caught as XIDError).code).toBe("GeneratorConflict");
      expect((caught as XIDError).message).toBe(
        "document already has generator, cannot provide external generator",
      );
    });

    it("should error on chain ID mismatch", () => {
      // Create a mark with one generator
      const generator1 = ProvenanceMarkGenerator.fromPassphrase("high", "passphrase1");
      const date1 = new Date(Date.UTC(2025, 0, 1));
      const mark1 = generator1.next(date1, { info: cbor("Test") });

      // Create XID document with mark but no embedded generator
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocBase = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });
      const xidDoc = XIDDocument.fromXid(xidDocBase.xid);
      xidDoc.setProvenance(mark1);

      // Try to advance with a different generator (different chain ID)
      const generator2 = ProvenanceMarkGenerator.fromPassphrase("high", "passphrase2");

      let caught: unknown;
      try {
        xidDoc.nextProvenanceMark({ generator: generator2, info: cbor("Test") });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(XIDError);
      expect((caught as XIDError).code).toBe("ChainIdMismatch");

      // The error message embeds the expected (mark1) and actual (generator2)
      // chain IDs as hex. Pin the prefix shape and confirm both hex strings
      // appear — that's exactly what the Rust `Error::ChainIdMismatch`
      // diagnostic carries.
      const chainIdExpectedHex = Array.from(generator1.chainId)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const chainIdActualHex = Array.from(generator2.chainId)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      expect((caught as XIDError).message).toBe(
        `generator chain ID mismatch: expected ${chainIdExpectedHex}, got ${chainIdActualHex}`,
      );
    });

    it("should error on sequence mismatch", () => {
      // Create a mark at seq 0
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test");
      const date1 = new Date(Date.UTC(2025, 0, 1));
      const mark1 = generator.next(date1, { info: cbor("Test") });

      // Advance generator to seq 2 (skip seq 1)
      const date2 = new Date(Date.UTC(2025, 0, 2));
      generator.next(date2, { info: cbor("Test") });

      // Create XID document with mark at seq 0
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocBase = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });
      const xidDoc = XIDDocument.fromXid(xidDocBase.xid);
      xidDoc.setProvenance(mark1);

      // Try to advance with generator at seq 2 (expecting seq 1)
      let caught: unknown;
      try {
        xidDoc.nextProvenanceMark({ generator: generator, info: cbor("Test") });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(XIDError);
      expect((caught as XIDError).code).toBe("SequenceMismatch");
      // mark1 is at seq 0 → expected next is 1; generator was advanced to nextSeq()=2.
      expect((caught as XIDError).message).toBe("generator sequence mismatch: expected 1, got 2");
    });

    it("should error when document has no provenance and provided-generator advance is attempted (X1c)", () => {
      // Pins the X1c "no-provenance" branch of `nextProvenanceMarkWithProvidedGenerator`
      // — distinct from the "no-provenance" branch of the embedded variant
      // already covered above.
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test");
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocBase = XIDDocument.from({
        inceptionKey: privateKeyBase,
      });
      const xidDoc = XIDDocument.fromXid(xidDocBase.xid);
      // Note: no setProvenance() — the document has no mark.

      let caught: unknown;
      try {
        xidDoc.nextProvenanceMark({ generator: generator, info: cbor("Test") });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(XIDError);
      expect((caught as XIDError).code).toBe("NoProvenanceMark");
      expect((caught as XIDError).message).toBe("no provenance mark to advance");
    });
  });

  describe("Encrypted with different methods", () => {
    it("should encrypt with Argon2id, PBKDF2, and Scrypt", { timeout: 30_000 }, () => {
      const generatorForMark = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generatorForMark.next(date, { info: cbor("Test mark") });

      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const password = new TextEncoder().encode("test_password_123");

      const provenance = Provenance.from(mark, { generator: generator });

      // Test encryption with Argon2id
      const envelopeArgon2id = provenance.toEnvelope({
        generator: { encrypt: password, method: KeyDerivationMethod.Argon2id },
      });
      const provenanceArgon2id = Provenance.fromEnvelope(envelopeArgon2id, { password: password });
      expect(provenance.equals(provenanceArgon2id)).toBe(true);

      // Test encryption with PBKDF2
      const envelopePbkdf2 = provenance.toEnvelope({
        generator: { encrypt: password, method: KeyDerivationMethod.PBKDF2 },
      });
      const provenancePbkdf2 = Provenance.fromEnvelope(envelopePbkdf2, { password: password });
      expect(provenance.equals(provenancePbkdf2)).toBe(true);

      // Test encryption with Scrypt
      const envelopeScrypt = provenance.toEnvelope({
        generator: { encrypt: password, method: KeyDerivationMethod.Scrypt },
      });
      const provenanceScrypt = Provenance.fromEnvelope(envelopeScrypt, { password: password });
      expect(provenance.equals(provenanceScrypt)).toBe(true);

      // Each encryption produces a different envelope (different salts/nonces)
      expect(envelopeArgon2id.toUR().toString()).not.toBe(envelopePbkdf2.toUR().toString());
      expect(envelopePbkdf2.toUR().toString()).not.toBe(envelopeScrypt.toUR().toString());
      expect(envelopeArgon2id.toUR().toString()).not.toBe(envelopeScrypt.toUR().toString());
    });
  });

  describe("Generator envelope", () => {
    it("should return undefined when no generator", () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });
      const provenance = Provenance.from(mark);

      const result = provenance.generatorEnvelope();
      expect(result).toBeUndefined();
    });

    it("should return envelope for unencrypted generator", () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });
      const provenance = Provenance.from(mark, { generator: generator });

      const envelope = provenance.generatorEnvelope();
      expect(envelope).toBeDefined();
    });

    it("should return encrypted envelope when no password provided", { timeout: 60_000 }, () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });
      const provenance = Provenance.from(mark, { generator: generator });
      const password = "test-password";

      // Encrypt the provenance
      const envelopeEncrypted = provenance.toEnvelope({
        generator: { encrypt: new TextEncoder().encode(password) },
      });

      const provenanceEncrypted = Provenance.fromEnvelope(envelopeEncrypted);

      // Get encrypted envelope without password
      const encryptedEnvelope = provenanceEncrypted.generatorEnvelope();
      expect(encryptedEnvelope).toBeDefined();

      // Should be encrypted
      const formatted = encryptedEnvelope === undefined ? undefined : format(encryptedEnvelope);
      expect(formatted).toContain("ENCRYPTED");
      expect(formatted).toContain("hasSecret");
    });

    it("should decrypt envelope with correct password", { timeout: 30_000 }, () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });
      const provenance = Provenance.from(mark, { generator: generator });
      const password = "test-password";

      // Encrypt the provenance
      const envelopeEncrypted = provenance.toEnvelope({
        generator: { encrypt: new TextEncoder().encode(password) },
      });

      const provenanceEncrypted = Provenance.fromEnvelope(envelopeEncrypted);

      // Get decrypted envelope with correct password
      const decryptedEnvelope = provenanceEncrypted.generatorEnvelope({ password: password });
      expect(decryptedEnvelope).toBeDefined();
    });

    it("should throw on wrong password", { timeout: 30_000 }, () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test_passphrase");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date, { info: cbor("Test mark") });
      const provenance = Provenance.from(mark, { generator: generator });
      const password = "test-password";

      // Encrypt the provenance
      const envelopeEncrypted = provenance.toEnvelope({
        generator: { encrypt: new TextEncoder().encode(password) },
      });

      const provenanceEncrypted = Provenance.fromEnvelope(envelopeEncrypted);

      // Try to decrypt with wrong password
      expect(() => {
        provenanceEncrypted.generatorEnvelope({ password: "wrong-password" });
      }).toThrow();
    });
  });

  describe("Advancing with encrypted generator", () => {
    it("should advance with embedded encrypted generator", { timeout: 30_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();

      const passphrase = "test_passphrase";
      const date1 = new Date(Date.UTC(2025, 0, 1));

      const xidDoc = XIDDocument.from({
        inceptionKey: privateKeyBase.ed25519PublicKeys(),
        genesis: { passphrase, resolution: "high", date: date1, info: cbor("Genesis mark") },
      });

      // Verify initial state
      const mark1 = xidDoc.provenance;
      expect(mark1).toBeDefined();
      expect(mark1?.seq).toBe(0);

      // Encrypt the generator
      const password = new TextEncoder().encode("encryption_password");
      const envelope = xidDoc.toEnvelope({ generator: { encrypt: password } });

      // Reload document (generator is now encrypted)
      const xidDocEncrypted = XIDDocument.fromEnvelope(envelope);

      // Verify generator is encrypted (not accessible without password)
      expect(xidDocEncrypted.provenanceGenerator).toBeUndefined();

      // Advance with correct password
      const date2 = new Date(Date.UTC(2025, 0, 2));
      xidDocEncrypted.nextProvenanceMark({
        password: password,
        date: date2,
        info: cbor("Second mark"),
      });

      // Verify advancement
      const mark2 = xidDocEncrypted.provenance;
      expect(mark2).toBeDefined();
      expect(mark2?.seq).toBe(1);

      // Generator should now be decrypted
      const generator = xidDocEncrypted.provenanceGenerator;
      expect(generator).toBeDefined();
      expect(generator?.nextSeq).toBe(2);
    });

    it("should error on wrong password for encrypted generator", { timeout: 30_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();

      const passphrase = "test_passphrase";
      const date = new Date(Date.UTC(2025, 0, 1));

      const xidDoc = XIDDocument.from({
        inceptionKey: privateKeyBase.ed25519PublicKeys(),
        genesis: { passphrase, resolution: "high", date, info: cbor("Genesis mark") },
      });

      // Encrypt the generator
      const password = new TextEncoder().encode("correct_password");
      const envelope = xidDoc.toEnvelope({ generator: { encrypt: password } });

      // Reload document (generator is now encrypted)
      const xidDocEncrypted = XIDDocument.fromEnvelope(envelope);

      // Try to advance with wrong password
      const wrongPassword = new TextEncoder().encode("wrong_password");
      expect(() => {
        xidDocEncrypted.nextProvenanceMark({ password: wrongPassword, info: cbor("Test") });
      }).toThrow();
    });
  });

  describe("Provenance equality and cloning", () => {
    it("should compare provenance by mark", () => {
      const generator1 = ProvenanceMarkGenerator.fromPassphrase("high", "pass1");
      const generator2 = ProvenanceMarkGenerator.fromPassphrase("high", "pass2");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark1 = generator1.next(date);
      const mark2 = generator2.next(date);

      const provenance1 = Provenance.from(mark1);
      const provenance1Clone = Provenance.from(mark1);
      const provenance2 = Provenance.from(mark2);

      expect(provenance1.equals(provenance1Clone)).toBe(true);
      expect(provenance1.equals(provenance2)).toBe(false);
    });

    it("should clone provenance correctly", () => {
      const generator = ProvenanceMarkGenerator.fromPassphrase("high", "test");
      const date = new Date(Date.UTC(2025, 0, 1));
      const mark = generator.next(date);

      const provenance = Provenance.from(mark, { generator: generator });
      const cloned = provenance.clone();

      expect(cloned.equals(provenance)).toBe(true);
    });
  });
});
