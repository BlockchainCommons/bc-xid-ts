import { format } from "@blockchaincommons/envelope/format";
/**
 * Key tests
 * Ported from bc-xid-rust/tests/key.rs
 */

import { PrivateKeyBase, type URI } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { Key } from "../src";

const hasUri = (set: ReadonlySet<URI>, value: string): boolean => {
  for (const uri of set) {
    if (uri.toString() === value) return true;
  }
  return false;
};

describe("Key", () => {
  describe("Basic key operations", () => {
    it("should create key from public keys", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const publicKeys = privateKeyBase.ed25519PublicKeys();

      const key = Key.from(publicKeys);
      expect(key.publicKeys.equals(publicKeys)).toBe(true);
      expect(key.privateKeys).toBeUndefined();
    });

    it("should create key with endpoints, nickname, and permissions", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const publicKeys = privateKeyBase.ed25519PublicKeys();

      const resolver1 = "https://resolver.example.com";
      const resolver2 = "btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33";

      const key = Key.from(publicKeys);
      key.addEndpoint(resolver1);
      key.addEndpoint(resolver2);
      key.addAllow("All");
      key.setNickname("Alice's key");

      expect(hasUri(key.endpoints, resolver1)).toBe(true);
      expect(hasUri(key.endpoints, resolver2)).toBe(true);
      expect(key.removeEndpoint("https://absent.example")).toBe(false);
      key.addEndpoint("https://gone.example");
      expect(key.removeEndpoint("https://gone.example")).toBe(true);
      expect(hasUri(key.endpoints, "https://gone.example")).toBe(false);
      expect(key.nickname).toBe("Alice's key");
      expect(key.permissions.allow.has("All")).toBe(true);

      // Round-trip through envelope
      const envelope = key.toEnvelope();
      const key2 = Key.fromEnvelope(envelope);
      expect(key.equals(key2)).toBe(true);
    });
  });

  describe("Private key handling", () => {
    it("should create key with private key base", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const keyIncludingPrivate = Key.fromPrivateKeyBase(privateKeyBase);
      expect(keyIncludingPrivate.hasPrivateKeys).toBe(true);
      expect(keyIncludingPrivate.privateKeys).toBeDefined();
    });

    it("should omit private key by default", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const keyIncludingPrivate = Key.fromPrivateKeyBase(privateKeyBase);
      const keyOmittingPrivate = Key.allowAll(privateKeyBase.schnorrPublicKeys());

      // Default envelope omits private key
      const envelopeOmitting = keyIncludingPrivate.toEnvelope();
      const key2 = Key.fromEnvelope(envelopeOmitting);
      expect(key2.hasPrivateKeys).toBe(false);
      expect(keyOmittingPrivate.equals(key2)).toBe(true);
    });

    it("should include private key when specified", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const keyIncludingPrivate = Key.fromPrivateKeyBase(privateKeyBase);

      // Include private key
      const envelopeIncluding = keyIncludingPrivate.toEnvelope({ privateKeys: "include" });
      const key2 = Key.fromEnvelope(envelopeIncluding);
      expect(key2.hasPrivateKeys).toBe(true);
      expect(keyIncludingPrivate.equals(key2)).toBe(true);
    });

    it("should elide private key when specified", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const keyIncludingPrivate = Key.fromPrivateKeyBase(privateKeyBase);
      const keyOmittingPrivate = Key.allowAll(privateKeyBase.schnorrPublicKeys());

      // Elide private key
      const envelopeEliding = keyIncludingPrivate.toEnvelope({ privateKeys: "elide" });
      const key2 = Key.fromEnvelope(envelopeEliding);
      expect(key2.hasPrivateKeys).toBe(false);
      expect(keyOmittingPrivate.equals(key2)).toBe(true);
    });
  });

  describe("Encrypted private key", () => {
    it("should encrypt and decrypt private key with password", { timeout: 60_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const password = new TextEncoder().encode("correct_horse_battery_staple");

      const key = Key.fromPrivateKeyBase(privateKeyBase);

      // Encrypt the private key
      const envelopeEncrypted = key.toEnvelope({ privateKeys: { encrypt: password } });

      // Extract without password - should succeed but private key is None
      const keyNoPassword = Key.fromEnvelope(envelopeEncrypted);
      expect(keyNoPassword.privateKeys).toBeUndefined();
      expect(keyNoPassword.publicKeys.equals(privateKeyBase.schnorrPublicKeys())).toBe(true);

      // Extract with wrong password - should succeed but private key is None
      const wrongPassword = new TextEncoder().encode("wrong_password");
      const keyWrongPassword = Key.fromEnvelope(envelopeEncrypted, { password: wrongPassword });
      expect(keyWrongPassword.privateKeys).toBeUndefined();

      // Extract with correct password - should succeed with private key
      const keyDecrypted = Key.fromEnvelope(envelopeEncrypted, { password: password });
      expect(keyDecrypted.privateKeys).toBeDefined();
      expect(keyDecrypted.equals(key)).toBe(true);
    });
  });

  describe("Private key storage modes", () => {
    it("should handle all storage modes correctly", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const key = Key.fromPrivateKeyBase(privateKeyBase);

      // Mode 1: Omit (default)
      const envelopeOmit = key.toEnvelope();
      const keyOmit = Key.fromEnvelope(envelopeOmit);
      expect(keyOmit.privateKeys).toBeUndefined();

      // Mode 2: Include
      const envelopeInclude = key.toEnvelope({ privateKeys: "include" });
      const keyInclude = Key.fromEnvelope(envelopeInclude);
      expect(keyInclude.equals(key)).toBe(true);

      // Mode 3: Elide
      const envelopeElide = key.toEnvelope({ privateKeys: "elide" });
      const keyElide = Key.fromEnvelope(envelopeElide);
      expect(keyElide.privateKeys).toBeUndefined();
    });
  });

  describe("Key equality and hashing", () => {
    it("should correctly compare keys", () => {
      const privateKeyBase1 = PrivateKeyBase.random();
      const privateKeyBase2 = PrivateKeyBase.random();

      const key1 = Key.from(privateKeyBase1.ed25519PublicKeys());
      const key1Clone = Key.from(privateKeyBase1.ed25519PublicKeys());
      const key2 = Key.from(privateKeyBase2.ed25519PublicKeys());

      expect(key1.equals(key1Clone)).toBe(true);
      expect(key1.equals(key2)).toBe(false);
    });

    it("should produce consistent hash keys", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const key1 = Key.from(privateKeyBase.ed25519PublicKeys());
      const key2 = Key.from(privateKeyBase.ed25519PublicKeys());

      expect(key1.reference.toHex()).toBe(key2.reference.toHex());
    });
  });

  describe("Key cloning", () => {
    it("should clone key correctly", () => {
      const privateKeyBase = PrivateKeyBase.random();

      const key = Key.fromPrivateKeyBase(privateKeyBase);
      key.setNickname("Test Key");
      key.addEndpoint("https://example.com");
      key.addAllow("Sign");

      const cloned = key.clone();
      expect(cloned.equals(key)).toBe(true);
      expect(cloned.nickname).toBe(key.nickname);
      expect(hasUri(cloned.endpoints, "https://example.com")).toBe(true);
    });
  });

  describe("Encrypted with different methods", () => {
    it("should encrypt with Argon2id, PBKDF2, and Scrypt", { timeout: 30_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const password = new TextEncoder().encode("test_password_123");

      const key = Key.fromPrivateKeyBase(privateKeyBase);

      // Test encryption with Argon2id
      const envelopeArgon2id = key.toEnvelope({
        privateKeys: { encrypt: password, method: KeyDerivationMethod.Argon2id },
      });
      const keyArgon2id = Key.fromEnvelope(envelopeArgon2id, { password: password });
      expect(keyArgon2id.equals(key)).toBe(true);

      // Test encryption with PBKDF2
      const envelopePbkdf2 = key.toEnvelope({
        privateKeys: { encrypt: password, method: KeyDerivationMethod.PBKDF2 },
      });
      const keyPbkdf2 = Key.fromEnvelope(envelopePbkdf2, { password: password });
      expect(keyPbkdf2.equals(key)).toBe(true);

      // Test encryption with Scrypt
      const envelopeScrypt = key.toEnvelope({
        privateKeys: { encrypt: password, method: KeyDerivationMethod.Scrypt },
      });
      const keyScrypt = Key.fromEnvelope(envelopeScrypt, { password: password });
      expect(keyScrypt.equals(key)).toBe(true);

      // Each encryption produces a different envelope (different salts/nonces)
      expect(envelopeArgon2id.toUR().toString()).not.toBe(envelopePbkdf2.toUR().toString());
      expect(envelopePbkdf2.toUR().toString()).not.toBe(envelopeScrypt.toUR().toString());
      expect(envelopeArgon2id.toUR().toString()).not.toBe(envelopeScrypt.toUR().toString());
    });
  });

  describe("Private key envelope", () => {
    it("should return undefined when no private key", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const key = Key.from(privateKeyBase.ed25519PublicKeys());

      const result = key.privateKeyEnvelope();
      expect(result).toBeUndefined();
    });

    it("should return envelope for unencrypted private key", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const key = Key.fromPrivateKeyBase(privateKeyBase);

      const envelope = key.privateKeyEnvelope();
      expect(envelope).toBeDefined();

      // A tagged-CBOR PrivateKeys leaf, mirroring Rust.
      const leaf = envelope?.subject().asLeaf();
      expect(leaf).toBeDefined();
    });

    it("should return encrypted envelope when no password provided", { timeout: 60_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const key = Key.fromPrivateKeyBase(privateKeyBase);
      const password = "test-password";

      // Encrypt the key
      const envelopeEncrypted = key.toEnvelope({
        privateKeys: { encrypt: new TextEncoder().encode(password) },
      });

      const keyEncrypted = Key.fromEnvelope(envelopeEncrypted);

      // Get encrypted envelope without password
      const encryptedEnvelope = keyEncrypted.privateKeyEnvelope();
      expect(encryptedEnvelope).toBeDefined();

      // Should be encrypted
      const formatted = encryptedEnvelope === undefined ? undefined : format(encryptedEnvelope);
      expect(formatted).toContain("ENCRYPTED");
      expect(formatted).toContain("hasSecret");
    });

    it("should decrypt envelope with correct password", { timeout: 30_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const key = Key.fromPrivateKeyBase(privateKeyBase);
      const password = "test-password";

      // Encrypt the key
      const envelopeEncrypted = key.toEnvelope({
        privateKeys: { encrypt: new TextEncoder().encode(password) },
      });

      const keyEncrypted = Key.fromEnvelope(envelopeEncrypted);

      // Get decrypted envelope with correct password
      const decryptedEnvelope = keyEncrypted.privateKeyEnvelope({ password: password });
      expect(decryptedEnvelope).toBeDefined();

      // Decrypted PrivateKeys are stored as a tagged-CBOR leaf, mirroring Rust.
      const leaf = decryptedEnvelope?.subject().asLeaf();
      expect(leaf).toBeDefined();
    });

    it("should throw on wrong password", { timeout: 30_000 }, () => {
      const privateKeyBase = PrivateKeyBase.random();
      const key = Key.fromPrivateKeyBase(privateKeyBase);
      const password = "test-password";

      // Encrypt the key
      const envelopeEncrypted = key.toEnvelope({
        privateKeys: { encrypt: new TextEncoder().encode(password) },
      });

      const keyEncrypted = Key.fromEnvelope(envelopeEncrypted);

      // Try to decrypt with wrong password
      expect(() => {
        keyEncrypted.privateKeyEnvelope({ password: "wrong-password" });
      }).toThrow();
    });
  });
});
