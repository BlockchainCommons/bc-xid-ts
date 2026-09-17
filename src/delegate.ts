/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A delegate: another XID document (resolved, or just its XID) granted
 * permissions by this one.
 */

import { type Envelope } from "@blockchaincommons/envelope";
import { type Reference, type XID } from "@blockchaincommons/components";

import { Permissions, type HasPermissions } from "./permissions";
import { type Privilege } from "./privilege";
import { guarded } from "./domain";

/** What a delegate needs of its controller: `XIDDocument`, without importing it. */
export interface XIDDocumentLike {
  /** The controller's XID. */
  readonly xid: XID;
  /** The controller's envelope (private keys and generator omitted, unsigned). */
  toEnvelope(): Envelope;
  /** Whether the controller equals `other`. */
  equals(other: XIDDocumentLike): boolean;
  /** A deep copy of the controller. */
  clone(): XIDDocumentLike;
}

/** Parses a controller document from its envelope: `XIDDocument.fromEnvelope`. */
type ParseXIDDocument = (envelope: Envelope) => XIDDocumentLike;

/** What `Delegate.from` takes besides the controller. */
export interface DelegateInput {
  /** The permissions granted; none unless given. */
  permissions?: Permissions | undefined;
}

let documentParser: ParseXIDDocument | undefined;

/** Installs the controller parser (`XIDDocument.fromEnvelope`), late-bound to avoid an import cycle. @internal */
export function setDefaultDocumentParser(parser: ParseXIDDocument): void {
  documentParser = parser;
}

/** A delegate: a controller document and the permissions this document grants it. */
export class Delegate implements HasPermissions {
  private readonly _controller: XIDDocumentLike;
  private readonly _permissions: Permissions;

  private constructor(controller: XIDDocumentLike, permissions: Permissions) {
    this._controller = controller;
    this._permissions = permissions;
  }

  /**
   * A delegate controlled by a copy of `controller` taken now (as the
   * reference's `Delegate::new` clones it): a later change to the
   * caller's document is not seen. No permissions unless given.
   */
  static from(controller: XIDDocumentLike, { permissions }: DelegateInput = {}): Delegate {
    return new Delegate(controller.clone(), permissions ?? Permissions.from());
  }

  /** The delegate's own copy of the controlling document (live: mutating it mutates the delegate). */
  get controller(): XIDDocumentLike {
    return this._controller;
  }

  /** The controller's XID. */
  get xid(): XID {
    return this._controller.xid;
  }

  /** The reference of the controller's XID. */
  get reference(): Reference {
    return this.xid.reference();
  }

  /** The permissions (live). */
  get permissions(): Permissions {
    return this._permissions;
  }

  /** The allowed privileges (a copy). */
  get allow(): ReadonlySet<Privilege> {
    return this._permissions.allow;
  }

  /** The denied privileges (a copy). */
  get deny(): ReadonlySet<Privilege> {
    return this._permissions.deny;
  }

  /** Allows `privilege`. */
  addAllow(privilege: Privilege): void {
    this._permissions.addAllow(privilege);
  }

  /** Denies `privilege`. */
  addDeny(privilege: Privilege): void {
    this._permissions.addDeny(privilege);
  }

  /** Stops allowing `privilege`. */
  removeAllow(privilege: Privilege): void {
    this._permissions.removeAllow(privilege);
  }

  /** Stops denying `privilege`. */
  removeDeny(privilege: Privilege): void {
    this._permissions.removeDeny(privilege);
  }

  /** Empties both sets. */
  clearAllPermissions(): void {
    this._permissions.clearAllPermissions();
  }

  /** The controller's envelope, wrapped, with the permissions. */
  toEnvelope(): Envelope {
    return this._permissions.addToEnvelope(this._controller.toEnvelope().wrap());
  }

  /**
   * A delegate from its envelope: the permissions, then the unwrapped
   * controller parsed with `XIDDocument.fromEnvelope`. A sibling failure
   * is `EnvelopeParsing`.
   */
  static fromEnvelope(envelope: Envelope): Delegate {
    if (documentParser === undefined) throw new Error("the document module is not loaded");
    const permissions = Permissions.fromEnvelope(envelope);
    const inner = guarded(() => envelope.unwrap());
    return new Delegate(documentParser(inner), permissions);
  }

  /** Same controller document and permissions — as the reference's equality. */
  equals(other: Delegate): boolean {
    return (
      this._controller.equals(other._controller) && this._permissions.equals(other._permissions)
    );
  }

  /** A deep copy. */
  clone(): Delegate {
    return new Delegate(this._controller.clone(), this._permissions.clone());
  }
}
