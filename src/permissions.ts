/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The allow and deny sets a key, delegate or service carries, and their
 * `'allow'`/`'deny'` assertions.
 */

// Ported from bc-xid-rust/src/permissions.rs

import { ALLOW, DENY } from "@blockchaincommons/known-values";
import { Envelope } from "@blockchaincommons/envelope";

import { type Privilege, privilegeFromEnvelope, privilegeKnownValue } from "./privilege";

/** What `Permissions.from` takes. */
export interface PermissionsInput {
  allow?: Iterable<Privilege> | undefined;
  deny?: Iterable<Privilege> | undefined;
}

/** Something that carries permissions: a key, a delegate, a service. */
export interface HasPermissions {
  readonly permissions: Permissions;
  allow(privilege: Privilege): void;
  deny(privilege: Privilege): void;
}

export class Permissions {
  private readonly _allow: Set<Privilege>;
  private readonly _deny: Set<Privilege>;

  private constructor(allow: Set<Privilege>, deny: Set<Privilege>) {
    this._allow = allow;
    this._deny = deny;
  }

  /** Empty sets unless given. */
  static from({ allow, deny }: PermissionsInput = {}): Permissions {
    return new Permissions(new Set(allow ?? []), new Set(deny ?? []));
  }

  /** `All` allowed, nothing denied. */
  static allowAll(): Permissions {
    return new Permissions(new Set<Privilege>(["All"]), new Set());
  }

  get allow(): ReadonlySet<Privilege> {
    return this._allow;
  }

  get deny(): ReadonlySet<Privilege> {
    return this._deny;
  }

  addAllow(privilege: Privilege): void {
    this._allow.add(privilege);
  }

  addDeny(privilege: Privilege): void {
    this._deny.add(privilege);
  }

  removeAllow(privilege: Privilege): void {
    this._allow.delete(privilege);
  }

  removeDeny(privilege: Privilege): void {
    this._deny.delete(privilege);
  }

  clear(): void {
    this._allow.clear();
    this._deny.clear();
  }

  /** Allowed (directly or through `All`) and not denied (directly or through `All`). */
  isAllowed(privilege: Privilege): boolean {
    if (this._deny.has(privilege) || this._deny.has("All")) return false;
    return this._allow.has(privilege) || this._allow.has("All");
  }

  isDenied(privilege: Privilege): boolean {
    return this._deny.has(privilege) || this._deny.has("All");
  }

  /** Adds an `'allow'` assertion per allowed privilege, then a `'deny'` per denied one. */
  addToEnvelope(envelope: Envelope): Envelope {
    let result = envelope;
    for (const privilege of this._allow) {
      result = result.addAssertion(
        Envelope.knownValue(ALLOW.value),
        Envelope.knownValue(privilegeKnownValue(privilege).value),
      );
    }
    for (const privilege of this._deny) {
      result = result.addAssertion(
        Envelope.knownValue(DENY.value),
        Envelope.knownValue(privilegeKnownValue(privilege).value),
      );
    }
    return result;
  }

  /** The `'allow'` and `'deny'` assertions of an envelope. */
  static fromEnvelope(envelope: Envelope): Permissions {
    const allow = new Set<Privilege>();
    const deny = new Set<Privilege>();
    for (const obj of envelope.objectsForPredicate(ALLOW)) allow.add(privilegeFromEnvelope(obj));
    for (const obj of envelope.objectsForPredicate(DENY)) deny.add(privilegeFromEnvelope(obj));
    return new Permissions(allow, deny);
  }

  equals(other: Permissions): boolean {
    if (this._allow.size !== other._allow.size || this._deny.size !== other._deny.size)
      return false;
    for (const p of this._allow) if (!other._allow.has(p)) return false;
    for (const p of this._deny) if (!other._deny.has(p)) return false;
    return true;
  }

  clone(): Permissions {
    return new Permissions(new Set(this._allow), new Set(this._deny));
  }
}
