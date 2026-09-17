/**
 * Delegate tests
 * Ported from bc-xid-rust/tests/delegate.rs
 */

import { PrivateKeyBase } from "@blockchaincommons/components";
import { format } from "@blockchaincommons/envelope/format";
import { Delegate, XIDDocument } from "../src";

describe("Delegate", () => {
  it("should create delegate with controller and permissions", () => {
    // Create Alice's XIDDocument
    const alicePrivateKeyBase = PrivateKeyBase.random();
    const aliceXidDocument = XIDDocument.from({ inceptionKey: alicePrivateKeyBase });

    // Create Bob's XIDDocument
    const bobPrivateKeyBase = PrivateKeyBase.random();
    const bobPublicKeys = bobPrivateKeyBase.ed25519PublicKeys();
    const bobXidDocument = XIDDocument.from({ inceptionKey: bobPublicKeys });

    // Create an unresolved delegate (just XID, no full document)
    const bobUnresolvedDelegate = Delegate.from(XIDDocument.fromXid(bobXidDocument.xid));
    bobUnresolvedDelegate.permissions.addAllow("Encrypt");
    bobUnresolvedDelegate.permissions.addAllow("Sign");

    // Round-trip through envelope
    const envelope = bobUnresolvedDelegate.toEnvelope();
    const bobUnresolvedDelegate2 = Delegate.fromEnvelope(envelope);
    expect(bobUnresolvedDelegate.equals(bobUnresolvedDelegate2)).toBe(true);

    // Create a full delegate with full document
    const bobDelegate = Delegate.from(bobXidDocument);
    bobDelegate.permissions.addAllow("Encrypt");
    bobDelegate.permissions.addAllow("Sign");

    // Round-trip through envelope
    const envelope2 = bobDelegate.toEnvelope();
    const bobDelegate2 = Delegate.fromEnvelope(envelope2);
    expect(bobDelegate.equals(bobDelegate2)).toBe(true);

    // Add Bob as delegate to Alice's document
    const aliceXidDocumentWithDelegate = aliceXidDocument.clone();
    aliceXidDocumentWithDelegate.addDelegate(bobDelegate);

    // Verify the delegate was added
    const delegates = aliceXidDocumentWithDelegate.delegates;
    expect(delegates.length).toBe(1);
    expect(delegates[0].xid.equals(bobXidDocument.xid)).toBe(true);
  });

  describe("Delegate properties", () => {
    it("should get controller XID", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      expect(delegate.xid.equals(xidDocument.xid)).toBe(true);
    });

    it("holds its own copy of the controller, taken at construction", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      expect(delegate.controller.xid.equals(xidDocument.xid)).toBe(true);
      expect(delegate.controller).not.toBe(xidDocument);

      // A later change to the source document is not seen; one made
      // through the delegate's own copy is.
      xidDocument.addResolutionMethod("https://later.example");
      expect(format(delegate.toEnvelope())).not.toContain("later.example");
      (delegate.controller as XIDDocument).addResolutionMethod("https://own.example");
      expect(format(delegate.toEnvelope())).toContain("own.example");
      expect(delegate.equals(Delegate.from(xidDocument))).toBe(false);
    });

    it("copies the controller on clone, so a clone's changes stay in the clone", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });
      const delegate = Delegate.from(xidDocument);
      const cloned = delegate.clone();
      (cloned.controller as XIDDocument).addResolutionMethod("https://clone.example");
      expect(delegate.controller.equals(cloned.controller)).toBe(false);
      expect(delegate.equals(cloned)).toBe(false);
    });

    it("should get delegate reference", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      const reference = delegate.reference;
      expect(reference).toBeDefined();
    });
  });

  describe("Delegate permissions", () => {
    it("should manage delegate permissions", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      delegate.permissions.addAllow("Sign");
      delegate.permissions.addAllow("Verify");

      expect(delegate.permissions.allow.has("Sign")).toBe(true);
      expect(delegate.permissions.allow.has("Verify")).toBe(true);
    });
  });

  describe("Delegate equality and cloning", () => {
    it("should compare delegates by controller and permissions", () => {
      const privateKeyBase1 = PrivateKeyBase.random();
      const xidDocument1 = XIDDocument.from({ inceptionKey: privateKeyBase1.ed25519PublicKeys() });

      const privateKeyBase2 = PrivateKeyBase.random();
      const xidDocument2 = XIDDocument.from({ inceptionKey: privateKeyBase2.ed25519PublicKeys() });

      const delegate1 = Delegate.from(xidDocument1);
      const delegate1Clone = Delegate.from(XIDDocument.fromXid(xidDocument1.xid));
      const delegate2 = Delegate.from(xidDocument2);

      expect(delegate1.equals(Delegate.from(xidDocument1))).toBe(true);
      // A controller known only by its XID is not the resolved document.
      expect(delegate1.equals(delegate1Clone)).toBe(false);
      expect(delegate1.equals(delegate2)).toBe(false);
    });

    it("should clone delegate correctly", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      delegate.permissions.addAllow("Sign");

      const cloned = delegate.clone();
      expect(cloned.equals(delegate)).toBe(true);
      expect(cloned.permissions.allow.has("Sign")).toBe(true);
    });
  });

  describe("Delegate hash key", () => {
    it("should use XID hex as hash key", () => {
      const privateKeyBase = PrivateKeyBase.random();
      const xidDocument = XIDDocument.from({ inceptionKey: privateKeyBase.ed25519PublicKeys() });

      const delegate = Delegate.from(xidDocument);
      expect(delegate.reference.toHex()).toBe(xidDocument.xid.toHex());
    });
  });
});
