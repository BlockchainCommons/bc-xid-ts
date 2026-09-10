/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A delegate: another XID document (resolved, or just its XID) granted
 * permissions by this one.
 */

// Ported from bc-xid-rust/src/delegate.rs

import { type Envelope } from "@blockchaincommons/envelope";
import { type Reference, type XID } from "@blockchaincommons/components";

import { Permissions, type HasPermissions } from "./permissions";
import { type Privilege } from "./privilege";

/** What a delegate needs of its controller: `XIDDocument`, without importing it. */
export interface XIDDocumentLike {
  readonly xid: XID;
  toEnvelope(): Envelope;
  equals(other: XIDDocumentLike): boolean;
  clone(): XIDDocumentLike;
}

/** Parses a controller document from its envelope: `XIDDocument.fromEnvelope`. */
export type ParseXIDDocument = (envelope: Envelope) => XIDDocumentLike;

export interface DelegateInput {
  permissions?: Permissions | undefined;
}

export class Delegate implements HasPermissions {
  private readonly _controller: XIDDocumentLike;
  private readonly _permissions: Permissions;

  private constructor(controller: XIDDocumentLike, permissions: Permissions) {
    this._controller = controller;
    this._permissions = permissions;
  }

  /** A delegate controlled by `controller`, with no permissions unless given. */
  static from(controller: XIDDocumentLike, { permissions }: DelegateInput = {}): Delegate {
    return new Delegate(controller, permissions ?? Permissions.from());
  }

  get controller(): XIDDocumentLike {
    return this._controller;
  }

  get xid(): XID {
    return this._controller.xid;
  }

  get reference(): Reference {
    return this.xid.reference();
  }

  get permissions(): Permissions {
    return this._permissions;
  }

  allow(privilege: Privilege): void {
    this._permissions.addAllow(privilege);
  }

  deny(privilege: Privilege): void {
    this._permissions.addDeny(privilege);
  }

  /** The controller's envelope, wrapped, with the permissions. */
  toEnvelope(): Envelope {
    return this._permissions.addToEnvelope(this._controller.toEnvelope().wrap());
  }

  /** `parseDocument` parses the unwrapped controller (`XIDDocument.fromEnvelope`). */
  static fromEnvelope(envelope: Envelope, parseDocument: ParseXIDDocument): Delegate {
    const permissions = Permissions.fromEnvelope(envelope);
    return new Delegate(parseDocument(envelope.unwrap()), permissions);
  }

  /** Same controller document and permissions — as the reference's equality. */
  equals(other: Delegate): boolean {
    return (
      this._controller.equals(other._controller) && this._permissions.equals(other._permissions)
    );
  }

  clone(): Delegate {
    return new Delegate(this._controller.clone(), this._permissions.clone());
  }
}
