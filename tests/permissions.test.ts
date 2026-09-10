/**
 * Permissions tests
 * Ported from bc-xid-rust/tests/permissions.rs
 */

import { Envelope } from "@blockchaincommons/envelope";
import { Permissions } from "../src";

describe("Permissions", () => {
  it("should create empty permissions", () => {
    const permissions = Permissions.from();
    expect(permissions.allow.size).toBe(0);
    expect(permissions.deny.size).toBe(0);
  });

  it("should add allow and deny permissions", () => {
    const permissions = Permissions.from();
    expect(permissions.allow.size).toBe(0);
    expect(permissions.deny.size).toBe(0);

    permissions.addAllow("All");
    permissions.addDeny("Verify");

    expect(permissions.allow.has("All")).toBe(true);
    expect(permissions.deny.has("Verify")).toBe(true);
  });

  it("should add permissions to envelope and restore", () => {
    const permissions = Permissions.from();
    permissions.addAllow("All");
    permissions.addDeny("Verify");

    const envelope = permissions.addToEnvelope(Envelope.from("Subject"));
    const permissions2 = Permissions.fromEnvelope(envelope);
    expect(permissions.equals(permissions2)).toBe(true);
  });

  it("should create allow-all permissions", () => {
    const permissions = Permissions.allowAll();
    expect(permissions.allow.has("All")).toBe(true);
    expect(permissions.deny.size).toBe(0);
  });

  it("should add individual allow permissions", () => {
    const permissions = Permissions.from();
    permissions.addAllow("Encrypt");
    permissions.addAllow("Sign");

    expect(permissions.allow.has("Encrypt")).toBe(true);
    expect(permissions.allow.has("Sign")).toBe(true);
    expect(permissions.allow.size).toBe(2);
  });

  it("should clone permissions correctly", () => {
    const permissions = Permissions.from();
    permissions.addAllow("All");
    permissions.addDeny("Verify");

    const cloned = permissions.clone();
    expect(cloned.equals(permissions)).toBe(true);

    // Modifying clone should not affect original
    cloned.addAllow("Encrypt");
    expect(permissions.allow.has("Encrypt")).toBe(false);
    expect(cloned.allow.has("Encrypt")).toBe(true);
  });
});
