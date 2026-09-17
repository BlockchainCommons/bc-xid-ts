/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The allow and deny sets a key, delegate or service carries, and their
 * `'allow'`/`'deny'` assertions.
 */

import { ALLOW, DENY } from "@blockchaincommons/known-values";
import { Envelope } from "@blockchaincommons/envelope";

import { type Privilege, privilegeFromEnvelope, privilegeKnownValue } from "./privilege";

/** What `Permissions.from` takes. */
export interface PermissionsInput {
  /** The privileges allowed. */
  allow?: Iterable<Privilege> | undefined;
  /** The privileges denied. */
  deny?: Iterable<Privilege> | undefined;
}

/**
 * Something that carries permissions: a key, a delegate, a service. The
 * members are the reference's `HasPermissions` trait: `allow` and `deny`
 * are the sets, `addAllow`/`addDeny`/`removeAllow`/`removeDeny` and
 * `clearAllPermissions` edit them.
 */
export interface HasPermissions {
  /** The permissions (live). */
  readonly permissions: Permissions;
  /** The allowed privileges (a copy). */
  readonly allow: ReadonlySet<Privilege>;
  /** The denied privileges (a copy). */
  readonly deny: ReadonlySet<Privilege>;
  /** Allows `privilege`. */
  addAllow(privilege: Privilege): void;
  /** Denies `privilege`. */
  addDeny(privilege: Privilege): void;
  /** Stops allowing `privilege`. */
  removeAllow(privilege: Privilege): void;
  /** Stops denying `privilege`. */
  removeDeny(privilege: Privilege): void;
  /** Empties both sets. */
  clearAllPermissions(): void;
}

/** An allow set and a deny set of privileges. */
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

  /** The allowed privileges (a copy). */
  get allow(): ReadonlySet<Privilege> {
    return new Set(this._allow);
  }

  /** The denied privileges (a copy). */
  get deny(): ReadonlySet<Privilege> {
    return new Set(this._deny);
  }

  /** Allows `privilege`. */
  addAllow(privilege: Privilege): void {
    this._allow.add(privilege);
  }

  /** Denies `privilege`. */
  addDeny(privilege: Privilege): void {
    this._deny.add(privilege);
  }

  /** Stops allowing `privilege`. */
  removeAllow(privilege: Privilege): void {
    this._allow.delete(privilege);
  }

  /** Stops denying `privilege`. */
  removeDeny(privilege: Privilege): void {
    this._deny.delete(privilege);
  }

  /** Empties both sets. */
  clearAllPermissions(): void {
    this._allow.clear();
    this._deny.clear();
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

  /**
   * The `'allow'` and `'deny'` assertions of an envelope. An object that
   * is not a known value is `EnvelopeParsing`; one that names no
   * privilege is `UnknownPrivilege`.
   */
  static fromEnvelope(envelope: Envelope): Permissions {
    const allow = new Set<Privilege>();
    const deny = new Set<Privilege>();
    for (const obj of envelope.objectsForPredicate(ALLOW)) allow.add(privilegeFromEnvelope(obj));
    for (const obj of envelope.objectsForPredicate(DENY)) deny.add(privilegeFromEnvelope(obj));
    return new Permissions(allow, deny);
  }

  /** Same allow and deny sets. */
  equals(other: Permissions): boolean {
    if (this._allow.size !== other._allow.size || this._deny.size !== other._deny.size)
      return false;
    for (const p of this._allow) if (!other._allow.has(p)) return false;
    for (const p of this._deny) if (!other._deny.has(p)) return false;
    return true;
  }

  /** A copy. */
  clone(): Permissions {
    return new Permissions(new Set(this._allow), new Set(this._deny));
  }
}
