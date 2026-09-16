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
export type ParseXIDDocument = (envelope: Envelope) => XIDDocumentLike;

/** What `Delegate.from` takes besides the controller. */
export interface DelegateInput {
  /** The permissions granted; none unless given. */
  permissions?: Permissions | undefined;
}

/** What `Delegate.fromEnvelope` takes besides the envelope. */
export interface DelegateParseOptions {
  /** The parser of the controller's envelope; `XIDDocument.fromEnvelope` unless given. */
  parseDocument?: ParseXIDDocument | undefined;
}

let defaultParser: ParseXIDDocument | undefined;

/** Installs the default controller parser (`XIDDocument.fromEnvelope`), late-bound to avoid an import cycle. */
export function setDefaultDocumentParser(parser: ParseXIDDocument): void {
  defaultParser = parser;
}

/** A delegate: a controller document and the permissions this document grants it. */
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

  /** The controlling document (live: mutating it mutates the delegate). */
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

  /** The permissions granted (live). */
  get permissions(): Permissions {
    return this._permissions;
  }

  /** Allows `privilege`. */
  allow(privilege: Privilege): void {
    this._permissions.addAllow(privilege);
  }

  /** Denies `privilege`. */
  deny(privilege: Privilege): void {
    this._permissions.addDeny(privilege);
  }

  /** The controller's envelope, wrapped, with the permissions. */
  toEnvelope(): Envelope {
    return this._permissions.addToEnvelope(this._controller.toEnvelope().wrap());
  }

  /**
   * A delegate from its envelope: the permissions, then the unwrapped
   * controller parsed by `parseDocument` (`XIDDocument.fromEnvelope`
   * unless given). A sibling failure is `EnvelopeParsing`.
   */
  static fromEnvelope(envelope: Envelope, { parseDocument }: DelegateParseOptions = {}): Delegate {
    const parse = parseDocument ?? defaultParser;
    if (parse === undefined) throw new TypeError("parseDocument is required");
    const permissions = Permissions.fromEnvelope(envelope);
    const inner = guarded(() => envelope.unwrap());
    return new Delegate(parse(inner), permissions);
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
