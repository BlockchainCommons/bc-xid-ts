/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A service a XID document offers: a URI, the keys and delegates it is
 * reached through, a capability, a name and permissions.
 */

import { expectText } from "@blockchaincommons/dcbor";
import { Envelope } from "@blockchaincommons/envelope";
import { KEY, DELEGATE, NAME, CAPABILITY, ALLOW } from "@blockchaincommons/known-values";
import { Reference, URI, type PublicKeys, type XID } from "@blockchaincommons/components";

import { Permissions, type HasPermissions } from "./permissions";
import { type Privilege, privilegeFromEnvelope } from "./privilege";
import { XIDError } from "./error";
import { guarded, leafAs } from "./domain";

/** What `Service.from` takes besides the URI. */
export interface ServiceInput {
  /** The capability (`addCapability`). */
  capability?: string | undefined;
  /** The name (`setName`). */
  name?: string | undefined;
  /** The keys the service is reached through, by reference. */
  keyReferences?: Iterable<Reference> | undefined;
  /** The delegates the service is reached through, by reference. */
  delegateReferences?: Iterable<Reference> | undefined;
  /** The permissions; empty unless given. */
  permissions?: Permissions | undefined;
}

/**
 * A service of a XID document: a URI, key and delegate references, a
 * capability, a name and permissions. On the wire only `'allow'`
 * permissions round-trip: the parser rejects `'deny'` as the reference's
 * does.
 */
export class Service implements HasPermissions {
  private readonly _uri: URI;
  private readonly _keyReferences: Map<string, Reference>;
  private readonly _delegateReferences: Map<string, Reference>;
  private readonly _permissions: Permissions;
  private _capability: string;
  private _name: string;

  private constructor(
    uri: URI,
    keyReferences: Map<string, Reference>,
    delegateReferences: Map<string, Reference>,
    permissions: Permissions,
    capability: string,
    name: string,
  ) {
    this._uri = uri;
    this._keyReferences = keyReferences;
    this._delegateReferences = delegateReferences;
    this._permissions = permissions;
    this._capability = capability;
    this._name = name;
  }

  /**
   * A service at a URI (a components error for text that is not a URI);
   * references and permissions can be added later.
   */
  static from(
    uri: URI | string,
    { capability, name, keyReferences, delegateReferences, permissions }: ServiceInput = {},
  ): Service {
    const service = new Service(
      uri instanceof URI ? uri : URI.from(uri),
      new Map(),
      new Map(),
      permissions ?? Permissions.from(),
      "",
      "",
    );
    if (capability !== undefined) service.addCapability(capability);
    if (name !== undefined) service.setName(name);
    for (const r of keyReferences ?? []) service.addKeyReference(r);
    for (const r of delegateReferences ?? []) service.addDelegateReference(r);
    return service;
  }

  /** The URI. */
  get uri(): URI {
    return this._uri;
  }

  /** The capability; empty when there is none. */
  get capability(): string {
    return this._capability;
  }

  /** Sets (or clears, with `""`) the capability. */
  setCapability(capability: string): void {
    this._capability = capability;
  }

  /** Sets the capability once; `Duplicate` when set, `EmptyValue` when empty. */
  addCapability(capability: string): void {
    if (this._capability !== "") throw XIDError.duplicate("capability");
    if (capability === "") throw XIDError.emptyValue("capability");
    this._capability = capability;
  }

  /** The key references (a copy). */
  get keyReferences(): ReadonlySet<Reference> {
    return new Set(this._keyReferences.values());
  }

  /** Whether the service references this key. */
  hasKeyReference(reference: Reference): boolean {
    return this._keyReferences.has(reference.toHex());
  }

  /** Adds a key reference; `Duplicate` when it is already there. */
  addKeyReference(keyReference: Reference): void {
    const key = keyReference.toHex();
    if (this._keyReferences.has(key)) throw XIDError.duplicate("key reference");
    this._keyReferences.set(key, keyReference);
  }

  /** Adds a key reference given as 64 hex characters (a components error otherwise). */
  addKeyReferenceHex(keyReferenceHex: string): void {
    this.addKeyReference(Reference.fromHex(keyReferenceHex));
  }

  /** References the key's public keys. */
  addKey(key: { readonly publicKeys: PublicKeys }): void {
    this.addKeyReference(key.publicKeys.reference());
  }

  /** The delegate references (a copy). */
  get delegateReferences(): ReadonlySet<Reference> {
    return new Set(this._delegateReferences.values());
  }

  /** Whether the service references this delegate. */
  hasDelegateReference(reference: Reference): boolean {
    return this._delegateReferences.has(reference.toHex());
  }

  /** Adds a delegate reference; `Duplicate` when it is already there. */
  addDelegateReference(delegateReference: Reference): void {
    const key = delegateReference.toHex();
    if (this._delegateReferences.has(key)) throw XIDError.duplicate("delegate reference");
    this._delegateReferences.set(key, delegateReference);
  }

  /** Adds a delegate reference given as 64 hex characters (a components error otherwise). */
  addDelegateReferenceHex(delegateReferenceHex: string): void {
    this.addDelegateReference(Reference.fromHex(delegateReferenceHex));
  }

  /** References the delegate's (or document's) XID. */
  addDelegate(delegate: { readonly xid: XID }): void {
    this.addDelegateReference(delegate.xid.reference());
  }

  /** The name; empty when there is none. */
  get name(): string {
    return this._name;
  }

  /** Sets the name once; `Duplicate` when set, `EmptyValue` when empty. */
  setName(name: string): void {
    if (this._name !== "") throw XIDError.duplicate("name");
    if (name === "") throw XIDError.emptyValue("name");
    this._name = name;
  }

  /** The permissions (live). */
  get permissions(): Permissions {
    return this._permissions;
  }

  /** Allows `privilege`. */
  allow(privilege: Privilege): void {
    this._permissions.addAllow(privilege);
  }

  /** Denies `privilege` (written to the wire, but not read back: see the class). */
  deny(privilege: Privilege): void {
    this._permissions.addDeny(privilege);
  }

  /** The URI as the subject; `'key'`, `'delegate'`, `'capability'`, `'name'` and the permissions. */
  toEnvelope(): Envelope {
    let envelope = Envelope.from(this._uri);
    for (const reference of this._keyReferences.values()) {
      envelope = envelope.addAssertion(KEY, reference);
    }
    for (const reference of this._delegateReferences.values()) {
      envelope = envelope.addAssertion(DELEGATE, reference);
    }
    if (this._capability !== "") envelope = envelope.addAssertion(CAPABILITY, this._capability);
    if (this._name !== "") envelope = envelope.addAssertion(NAME, this._name);
    return this._permissions.addToEnvelope(envelope);
  }

  /**
   * A service from its envelope. Rejects nested assertions
   * (`UnexpectedNestedAssertions`) and any predicate but `'key'`,
   * `'delegate'`, `'capability'`, `'name'` and `'allow'`
   * (`UnexpectedPredicate`; a predicate that is not a known value is
   * `EnvelopeParsing`); a subject or object of the wrong type is `Cbor`.
   */
  static fromEnvelope(envelope: Envelope): Service {
    const uri = leafAs(envelope.subject(), (c) => URI.fromCbor(c));
    const service = Service.from(uri);
    for (const assertion of envelope.assertions()) {
      const knownValue = guarded(() => assertion.expectPredicate().expectKnownValue());
      const object = guarded(() => assertion.expectObject());
      if (object.hasAssertions()) throw XIDError.unexpectedNestedAssertions();
      const predicate = knownValue.value;
      switch (predicate) {
        case KEY.value:
          service.addKeyReference(leafAs(object, (c) => Reference.fromCbor(c)));
          break;
        case DELEGATE.value:
          service.addDelegateReference(leafAs(object, (c) => Reference.fromCbor(c)));
          break;
        case CAPABILITY.value:
          service.addCapability(leafAs(object, expectText));
          break;
        case NAME.value:
          service.setName(leafAs(object, expectText));
          break;
        case ALLOW.value:
          service._permissions.addAllow(privilegeFromEnvelope(object));
          break;
        default:
          throw XIDError.unexpectedPredicate(String(predicate));
      }
    }
    return service;
  }

  /** Same URI, references, permissions, capability and name — as the reference's equality. */
  equals(other: Service): boolean {
    if (this._uri.toString() !== other._uri.toString()) return false;
    if (this._keyReferences.size !== other._keyReferences.size) return false;
    for (const k of this._keyReferences.keys()) if (!other._keyReferences.has(k)) return false;
    if (this._delegateReferences.size !== other._delegateReferences.size) return false;
    for (const k of this._delegateReferences.keys()) {
      if (!other._delegateReferences.has(k)) return false;
    }
    if (this._capability !== other._capability || this._name !== other._name) return false;
    return this._permissions.equals(other._permissions);
  }

  /** A copy. */
  clone(): Service {
    return new Service(
      this._uri,
      new Map(this._keyReferences),
      new Map(this._delegateReferences),
      this._permissions.clone(),
      this._capability,
      this._name,
    );
  }
}
