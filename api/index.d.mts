import { KnownValue } from "@blockchaincommons/known-values";
import { Envelope, ToEnvelope } from "@blockchaincommons/envelope";
import { Digest, EncapsulationPublicKey, PrivateKeyBase, PrivateKeys, PublicKeys, Reference, Salt, Signature, Signer, SigningPublicKey, URI, Verifier, XID } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution } from "@blockchaincommons/provenance-mark";
import { Cbor, CborCodec, CborTagged, Tag, ToCbor } from "@blockchaincommons/dcbor";
import { Attachments } from "@blockchaincommons/envelope/attachment";
import { Edgeable, Edges } from "@blockchaincommons/envelope/edge";
import { ToUR, UR } from "@blockchaincommons/uniform-resources";
import { RngOptions } from "@blockchaincommons/rand";
//#region src/error.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The one error this package throws: a `code` naming what went wrong (the
 * reference's variant names) and `details` typed by that code.
 */
type XIDErrorCode = "Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue" | "UnknownPrivilege" | "InvalidXid" | "MissingInceptionKey" | "InvalidResolutionMethod" | "MultipleProvenanceMarks" | "UnexpectedPredicate" | "UnexpectedNestedAssertions" | "NoPermissions" | "NoReferences" | "UnknownKeyReference" | "UnknownDelegateReference" | "KeyNotFoundInDocument" | "DelegateNotFoundInDocument" | "InvalidPassword" | "EnvelopeNotSigned" | "SignatureVerificationFailed" | "NoProvenanceMark" | "GeneratorConflict" | "NoGenerator" | "ChainIdMismatch" | "SequenceMismatch" | "EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark";
declare const XID_ERROR_CODES: readonly XIDErrorCode[];
/** A named item (a key, a delegate, a service, a nickname, …). */
interface ItemDetails {
  code: "Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue";
  item: string;
}
/** A structural rejection with nothing more to say. */
interface PlainDetails {
  code: "UnknownPrivilege" | "InvalidXid" | "MissingInceptionKey" | "InvalidResolutionMethod" | "MultipleProvenanceMarks" | "UnexpectedNestedAssertions" | "InvalidPassword" | "EnvelopeNotSigned" | "SignatureVerificationFailed" | "NoProvenanceMark" | "GeneratorConflict" | "NoGenerator";
}
interface UnexpectedPredicateDetails {
  code: "UnexpectedPredicate";
  predicate: string;
}
/** A service that is incomplete. */
interface ServiceDetails {
  code: "NoPermissions" | "NoReferences";
  uri: string;
}
/** A service reference that names nothing in the document. */
interface UnknownReferenceDetails {
  code: "UnknownKeyReference" | "UnknownDelegateReference";
  reference: string;
  uri: string;
}
interface KeyNotFoundDetails {
  code: "KeyNotFoundInDocument";
  key: string;
}
interface DelegateNotFoundDetails {
  code: "DelegateNotFoundInDocument";
  delegate: string;
}
interface ChainIdMismatchDetails {
  code: "ChainIdMismatch";
  expected: Uint8Array;
  actual: Uint8Array;
}
interface SequenceMismatchDetails {
  code: "SequenceMismatch";
  expected: number;
  actual: number;
}
/** A wrapped failure from envelope, components, dcbor or provenance-mark. */
interface WrappedDetails {
  code: "EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark";
  message: string;
}
type XIDErrorDetails = ItemDetails | PlainDetails | UnexpectedPredicateDetails | ServiceDetails | UnknownReferenceDetails | KeyNotFoundDetails | DelegateNotFoundDetails | ChainIdMismatchDetails | SequenceMismatchDetails | WrappedDetails;
declare class XIDError extends Error {
  override readonly name = "XIDError";
  readonly code: XIDErrorCode;
  readonly details: XIDErrorDetails;
  private constructor();
  static isXIDError(value: unknown): value is XIDError;
  is(code: XIDErrorCode): boolean;
  private static plain;
  static duplicate(item: string): XIDError;
  static notFound(item: string): XIDError;
  static stillReferenced(item: string): XIDError;
  static emptyValue(field: string): XIDError;
  static unknownPrivilege(): XIDError;
  static invalidXid(): XIDError;
  static missingInceptionKey(): XIDError;
  static invalidResolutionMethod(): XIDError;
  static multipleProvenanceMarks(): XIDError;
  static unexpectedPredicate(predicate: string): XIDError;
  static unexpectedNestedAssertions(): XIDError;
  static noPermissions(uri: string): XIDError;
  static noReferences(uri: string): XIDError;
  static unknownKeyReference(reference: string, uri: string): XIDError;
  static unknownDelegateReference(reference: string, uri: string): XIDError;
  static keyNotFoundInDocument(key: string): XIDError;
  static delegateNotFoundInDocument(delegate: string): XIDError;
  static invalidPassword(): XIDError;
  static envelopeNotSigned(): XIDError;
  static signatureVerificationFailed(): XIDError;
  static noProvenanceMark(): XIDError;
  static generatorConflict(): XIDError;
  static noGenerator(): XIDError;
  static chainIdMismatch(expected: Uint8Array, actual: Uint8Array): XIDError;
  static sequenceMismatch(expected: number, actual: number): XIDError;
  private static wrapped;
  static envelopeParsing(cause?: unknown): XIDError;
  static component(cause?: unknown): XIDError;
  static cbor(cause?: unknown): XIDError;
  static provenanceMark(cause?: unknown): XIDError;
}
//#endregion
//#region src/privilege.d.ts
/**
 * `All` grants every privilege; the operational ones (`Auth`, `Sign`,
 * `Encrypt`, `Elide`, `Issue`, `Access`) and the management ones
 * (`Delegate`, `Verify`, `Update`, `Transfer`, `Elect`, `Burn`, `Revoke`)
 * name one capability each.
 */
type Privilege = "All" | "Auth" | "Sign" | "Encrypt" | "Elide" | "Issue" | "Access" | "Delegate" | "Verify" | "Update" | "Transfer" | "Elect" | "Burn" | "Revoke";
declare const PRIVILEGES: readonly Privilege[];
declare function isPrivilege(value: unknown): value is Privilege;
/** The known value the privilege is encoded as. */
declare function privilegeKnownValue(privilege: Privilege): KnownValue;
/** The privilege a known value names; `UnknownPrivilege` for any other value. */
declare function privilegeFromKnownValue(knownValue: KnownValue): Privilege;
/** The privilege as a known-value envelope. */
declare function privilegeEnvelope(privilege: Privilege): Envelope;
/** The privilege a known-value envelope names. */
declare function privilegeFromEnvelope(envelope: Envelope): Privilege;
//#endregion
//#region src/permissions.d.ts
/** What `Permissions.from` takes. */
interface PermissionsInput {
  allow?: Iterable<Privilege> | undefined;
  deny?: Iterable<Privilege> | undefined;
}
/** Something that carries permissions: a key, a delegate, a service. */
interface HasPermissions {
  readonly permissions: Permissions;
  allow(privilege: Privilege): void;
  deny(privilege: Privilege): void;
}
declare class Permissions {
  private readonly _allow;
  private readonly _deny;
  private constructor();
  /** Empty sets unless given. */
  static from({ allow, deny }?: PermissionsInput): Permissions;
  /** `All` allowed, nothing denied. */
  static allowAll(): Permissions;
  get allow(): ReadonlySet<Privilege>;
  get deny(): ReadonlySet<Privilege>;
  addAllow(privilege: Privilege): void;
  addDeny(privilege: Privilege): void;
  removeAllow(privilege: Privilege): void;
  removeDeny(privilege: Privilege): void;
  clear(): void;
  /** Allowed (directly or through `All`) and not denied (directly or through `All`). */
  isAllowed(privilege: Privilege): boolean;
  isDenied(privilege: Privilege): boolean;
  /** Adds an `'allow'` assertion per allowed privilege, then a `'deny'` per denied one. */
  addToEnvelope(envelope: Envelope): Envelope;
  /** The `'allow'` and `'deny'` assertions of an envelope. */
  static fromEnvelope(envelope: Envelope): Permissions;
  equals(other: Permissions): boolean;
  clone(): Permissions;
}
//#endregion
//#region src/key.d.ts
/**
 * How a key's private keys go into an envelope: left out, included (with
 * a salt), elided (the digest of the included form), or locked with a
 * password (Argon2id unless `method` says otherwise).
 */
type XIDPrivateKeyOptions = "omit" | "include" | "elide" | {
  encrypt: Uint8Array | string;
  method?: KeyDerivationMethod | undefined;
};
/** Private keys as held: decrypted, or the locked envelope as parsed. */
type PrivateKeyData = {
  type: "decrypted";
  privateKeys: PrivateKeys;
} | {
  type: "encrypted";
  envelope: Envelope;
};
/** What `Key.from` takes besides the public keys. */
interface KeyInput {
  /** With private keys the key is allowed `All` unless `permissions` says otherwise. */
  privateKeys?: PrivateKeys | undefined;
  nickname?: string | undefined;
  endpoints?: Iterable<URI | string> | undefined;
  permissions?: Permissions | undefined;
}
interface PasswordOptions {
  password?: Uint8Array | string | undefined;
}
interface KeyEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
}
declare class Key implements HasPermissions, Verifier {
  private readonly _publicKeys;
  private readonly _privateKeyData;
  private _nickname;
  private readonly _endpoints;
  private readonly _permissions;
  private constructor();
  /** A key from its public keys; no permissions unless private keys or `permissions` are given. */
  static from(publicKeys: PublicKeys, { privateKeys, nickname, endpoints, permissions }?: KeyInput): Key;
  /** A public key allowed `All`. */
  static allowAll(publicKeys: PublicKeys): Key;
  /** The Schnorr and X25519 keys of a base, private keys included, allowed `All`. */
  static fromPrivateKeyBase(privateKeyBase: PrivateKeyBase): Key;
  get publicKeys(): PublicKeys;
  /** The private keys when held in the clear. */
  get privateKeys(): PrivateKeys | undefined;
  get hasPrivateKeys(): boolean;
  get hasEncryptedPrivateKeys(): boolean;
  /** The salt the `'privateKey'` assertion carries. */
  get privateKeySalt(): Salt | undefined;
  get reference(): Reference;
  get signingPublicKey(): SigningPublicKey;
  encapsulationPublicKey(): EncapsulationPublicKey;
  verify(signature: Signature, message: Uint8Array): boolean;
  get endpoints(): ReadonlySet<URI>;
  addEndpoint(endpoint: URI | string): void;
  get nickname(): string;
  setNickname(name: string): void;
  get permissions(): Permissions;
  allow(privilege: Privilege): void;
  deny(privilege: Privilege): void;
  private privateKeyAssertionEnvelope;
  /**
   * The public keys as the subject, the private keys per `privateKeys`
   * (a locked key stays locked), then `'nickname'`, `'endpoint'`s and
   * the permissions.
   */
  toEnvelope({ privateKeys }?: KeyEnvelopeOptions): Envelope;
  /**
   * A key from its envelope. A locked `'privateKey'` is unlocked with the
   * password when one is given and it fits; otherwise it is kept locked.
   */
  static fromEnvelope(envelope: Envelope, { password }?: PasswordOptions): Key;
  /**
   * The private keys as an envelope: in the clear when held so, unlocked
   * with the password when locked (an `InvalidPassword` error when it
   * does not fit), or the locked envelope itself without a password.
   */
  privateKeyEnvelope({ password }?: PasswordOptions): Envelope | undefined;
  /**
   * Same public keys, private material (in the clear or locked, with its
   * salt), nickname, endpoints and permissions — as the reference's
   * equality; a key parsed from an envelope that omitted its private
   * keys is not equal to the original.
   */
  equals(other: Key): boolean;
  clone(): Key;
}
//#endregion
//#region src/service.d.ts
/** What `Service.from` takes besides the URI. */
interface ServiceInput {
  capability?: string | undefined;
  name?: string | undefined;
  keyReferences?: Iterable<Reference> | undefined;
  delegateReferences?: Iterable<Reference> | undefined;
  permissions?: Permissions | undefined;
}
declare class Service implements HasPermissions {
  private readonly _uri;
  private readonly _keyReferences;
  private readonly _delegateReferences;
  private readonly _permissions;
  private _capability;
  private _name;
  private constructor();
  /** A service at a URI; references and permissions can be added later. */
  static from(uri: URI | string, { capability, name, keyReferences, delegateReferences, permissions }?: ServiceInput): Service;
  get uri(): URI;
  get capability(): string;
  setCapability(capability: string): void;
  /** Sets the capability once; `Duplicate` when set, `EmptyValue` when empty. */
  addCapability(capability: string): void;
  get keyReferences(): ReadonlySet<Reference>;
  hasKeyReference(reference: Reference): boolean;
  /** `Duplicate` when the reference is already there. */
  addKeyReference(keyReference: Reference): void;
  addKeyReferenceHex(keyReferenceHex: string): void;
  /** References the key's public keys. */
  addKey(key: {
    readonly publicKeys: PublicKeys;
  }): void;
  get delegateReferences(): ReadonlySet<Reference>;
  hasDelegateReference(reference: Reference): boolean;
  addDelegateReference(delegateReference: Reference): void;
  addDelegateReferenceHex(delegateReferenceHex: string): void;
  /** References the delegate's (or document's) XID. */
  addDelegate(delegate: {
    readonly xid: XID;
  }): void;
  get name(): string;
  /** Sets the name once; `Duplicate` when set, `EmptyValue` when empty. */
  setName(name: string): void;
  get permissions(): Permissions;
  allow(privilege: Privilege): void;
  deny(privilege: Privilege): void;
  /** The URI as the subject; `'key'`, `'delegate'`, `'capability'`, `'name'` and the permissions. */
  toEnvelope(): Envelope;
  /** Rejects nested assertions and any predicate but the five above. */
  static fromEnvelope(envelope: Envelope): Service;
  /** Same URI, references, permissions, capability and name — as the reference's equality. */
  equals(other: Service): boolean;
  clone(): Service;
}
//#endregion
//#region src/delegate.d.ts
/** What a delegate needs of its controller: `XIDDocument`, without importing it. */
interface XIDDocumentLike {
  readonly xid: XID;
  toEnvelope(): Envelope;
  equals(other: XIDDocumentLike): boolean;
  clone(): XIDDocumentLike;
}
/** Parses a controller document from its envelope: `XIDDocument.fromEnvelope`. */
type ParseXIDDocument = (envelope: Envelope) => XIDDocumentLike;
interface DelegateInput {
  permissions?: Permissions | undefined;
}
declare class Delegate implements HasPermissions {
  private readonly _controller;
  private readonly _permissions;
  private constructor();
  /** A delegate controlled by `controller`, with no permissions unless given. */
  static from(controller: XIDDocumentLike, { permissions }?: DelegateInput): Delegate;
  get controller(): XIDDocumentLike;
  get xid(): XID;
  get reference(): Reference;
  get permissions(): Permissions;
  allow(privilege: Privilege): void;
  deny(privilege: Privilege): void;
  /** The controller's envelope, wrapped, with the permissions. */
  toEnvelope(): Envelope;
  /** `parseDocument` parses the unwrapped controller (`XIDDocument.fromEnvelope`). */
  static fromEnvelope(envelope: Envelope, parseDocument: ParseXIDDocument): Delegate;
  /** Same controller document and permissions — as the reference's equality. */
  equals(other: Delegate): boolean;
  clone(): Delegate;
}
//#endregion
//#region src/provenance.d.ts
/** How the generator goes into an envelope; the same four forms as private keys. */
type XIDGeneratorOptions = "omit" | "include" | "elide" | {
  encrypt: Uint8Array | string;
  method?: KeyDerivationMethod | undefined;
};
/** The generator as held: decrypted, or the locked envelope as parsed. */
type GeneratorData = {
  type: "decrypted";
  generator: ProvenanceMarkGenerator;
} | {
  type: "encrypted";
  envelope: Envelope;
};
interface ProvenanceInput {
  generator?: ProvenanceMarkGenerator | undefined;
}
interface ProvenanceEnvelopeOptions {
  generator?: XIDGeneratorOptions | undefined;
}
declare class Provenance {
  private _mark;
  private _generator;
  private constructor();
  /** A mark, with the generator that produced it when the document should keep it. */
  static from(mark: ProvenanceMark, { generator }?: ProvenanceInput): Provenance;
  get mark(): ProvenanceMark;
  /** The generator when held in the clear. */
  get generator(): ProvenanceMarkGenerator | undefined;
  get hasGenerator(): boolean;
  get hasEncryptedGenerator(): boolean;
  get generatorSalt(): Salt | undefined;
  setMark(mark: ProvenanceMark): void;
  setGenerator(generator: ProvenanceMarkGenerator): void;
  /** Removes and returns the held generator data. */
  takeGenerator(): {
    data: GeneratorData;
    salt: Salt;
  } | undefined;
  /**
   * The generator, unlocking a locked one with the password (it stays
   * unlocked); `InvalidPassword` when it is locked and the password is
   * missing or wrong; `undefined` when there is no generator.
   */
  unlockGenerator({ password }?: PasswordOptions): ProvenanceMarkGenerator | undefined;
  private generatorAssertionEnvelope;
  /**
   * The generator as an envelope: in the clear when held so, unlocked
   * with the password when locked (`InvalidPassword` when it does not
   * fit), or the locked envelope itself without a password.
   */
  generatorEnvelope({ password }?: PasswordOptions): Envelope | undefined;
  /** The mark as the subject; the generator per `generator` (a locked one stays locked). */
  toEnvelope({ generator }?: ProvenanceEnvelopeOptions): Envelope;
  /**
   * A provenance from its envelope. A locked generator is unlocked with
   * the password when one is given and it fits; otherwise it is kept
   * locked.
   */
  static fromEnvelope(envelope: Envelope, { password }?: PasswordOptions): Provenance;
  /** Same mark and generator (in the clear or locked, with its salt) — as the reference's equality. */
  equals(other: Provenance): boolean;
  clone(): Provenance;
}
//#endregion
//#region src/xid-document.d.ts
/**
 * The inception key of a new document: public keys only, a private key
 * base (Schnorr keys, private keys held), or a public/private pair.
 */
type XIDInceptionKey = PublicKeys | PrivateKeyBase | {
  publicKeys: PublicKeys;
  privateKeys: PrivateKeys;
};
/** The genesis provenance mark of a new document, from a passphrase or a seed. */
interface XIDGenesis {
  passphrase?: string | undefined;
  /** 32 bytes (longer input is cut to 32). */
  seed?: Uint8Array | undefined;
  resolution?: ProvenanceMarkResolution | undefined;
  date?: Date | undefined;
  info?: Cbor | undefined;
}
/** What `XIDDocument.from` takes. */
interface XIDDocumentInput {
  inceptionKey: XIDInceptionKey;
  genesis?: XIDGenesis | undefined;
}
/** Who signs the document's envelope: nobody, the inception key, or a given signer. */
type XIDSigning = "none" | "inception" | Signer;
/** Which signature `fromEnvelope` demands. */
type XIDVerifySignature = "none" | "inception";
interface XIDEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
  generator?: XIDGeneratorOptions | undefined;
  sign?: XIDSigning | undefined;
}
interface XIDParseOptions extends PasswordOptions {
  verify?: XIDVerifySignature | undefined;
}
interface SignedEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
}
/** What `nextProvenanceMark` takes. */
interface NextProvenanceMarkOptions extends PasswordOptions {
  date?: Date | undefined;
  info?: Cbor | undefined;
  /** A generator kept outside the document; refused when the document holds one. */
  generator?: ProvenanceMarkGenerator | undefined;
}
declare class XIDDocument implements ToEnvelope, ToCbor, CborTagged, ToUR, Edgeable {
  private readonly _xid;
  private readonly _resolutionMethods;
  private readonly _keys;
  private readonly _delegates;
  private readonly _services;
  private _provenance;
  private _attachments;
  private _edges;
  private _extraAssertions;
  private constructor();
  /**
   * A document whose XID derives from the inception key's signing key;
   * the key is added allowed `All`. A genesis mark starts the provenance
   * chain and keeps the generator in the document.
   */
  static from({ inceptionKey, genesis }: XIDDocumentInput): XIDDocument;
  /** A document with a random private key base as its inception key. */
  static random({ rng }?: RngOptions, genesis?: XIDGenesis): XIDDocument;
  /** An empty document: just the XID. */
  static fromXid(xid: XID): XIDDocument;
  private static keyFor;
  private static genesisFor;
  get xid(): XID;
  get reference(): Reference;
  /** No keys, delegates, services, resolution methods, provenance, attachments, edges or extra assertions. */
  get isEmpty(): boolean;
  /** Assertions the parser did not recognise, kept as they were. */
  get extraAssertions(): readonly Envelope[];
  get resolutionMethods(): ReadonlySet<URI>;
  addResolutionMethod(method: URI | string): void;
  /** Whether it was there. */
  removeResolutionMethod(method: URI | string): boolean;
  get keys(): readonly Key[];
  /** `Duplicate` when the public keys are already there. */
  addKey(key: Key): void;
  key(publicKeys: PublicKeys): Key | undefined;
  keyByReference(reference: Reference): Key | undefined;
  /**
   * Removes and returns the key; `StillReferenced` when a service names
   * it, `NotFound` when it is not there.
   */
  removeKey(publicKeys: PublicKeys): Key;
  /** Removes and returns the key without checking services; `undefined` when absent. */
  takeKey(publicKeys: PublicKeys): Key | undefined;
  /** `KeyNotFoundInDocument` unless the key is there. */
  expectKey(publicKeys: PublicKeys): Key;
  isInceptionSigningKey(signingPublicKey: SigningPublicKey): boolean;
  /** The key whose signing key the XID derives from. */
  get inceptionKey(): Key | undefined;
  get inceptionPrivateKeys(): PrivateKeys | undefined;
  get inceptionSigningKey(): SigningPublicKey | undefined;
  /** The inception key's signing key, else the first key's. */
  get verificationKey(): SigningPublicKey | undefined;
  /** The inception key's encapsulation key, else the first key's. */
  get encryptionKey(): EncapsulationPublicKey | undefined;
  /** Removes and returns the inception key, if there is one. */
  removeInceptionKey(): Key | undefined;
  /** `NotFound` unless the key is there. */
  setNameForKey(publicKeys: PublicKeys, name: string): void;
  /** The private keys of a key as an envelope (see `Key.privateKeyEnvelope`). */
  privateKeyEnvelopeForKey(publicKeys: PublicKeys, options?: PasswordOptions): Envelope | undefined;
  /** The inception key's private keys of a parsed envelope, unlocked with the password. */
  static inceptionPrivateKeysFromEnvelope(envelope: Envelope, password: Uint8Array | string): PrivateKeys | undefined;
  get delegates(): readonly Delegate[];
  /** `Duplicate` when a delegate with that XID is already there. */
  addDelegate(delegate: Delegate): void;
  delegate(xid: XID): Delegate | undefined;
  delegateByReference(reference: Reference): Delegate | undefined;
  /** Removes and returns the delegate; `StillReferenced` when a service names it, `NotFound` when absent. */
  removeDelegate(xid: XID): Delegate;
  /** Removes and returns the delegate without checking services; `undefined` when absent. */
  takeDelegate(xid: XID): Delegate | undefined;
  /** `DelegateNotFoundInDocument` unless the delegate is there. */
  expectDelegate(xid: XID): Delegate;
  get services(): readonly Service[];
  service(uri: URI | string): Service | undefined;
  /** `Duplicate` when a service at that URI is already there. */
  addService(service: Service): void;
  /** Removes and returns the service; `undefined` when absent. */
  takeService(uri: URI | string): Service | undefined;
  /** Removes and returns the service; `NotFound` when absent. */
  removeService(uri: URI | string): Service;
  /** Every service references known keys and delegates and allows something. */
  expectServicesConsistent(): void;
  /**
   * `NoReferences` without any key or delegate reference,
   * `UnknownKeyReference`/`UnknownDelegateReference` for one the document
   * lacks, `NoPermissions` without an allowed privilege.
   */
  expectServiceConsistent(service: Service): void;
  servicesReferenceKey(publicKeys: PublicKeys): boolean;
  servicesReferenceDelegate(xid: XID): boolean;
  get attachments(): Attachments;
  get hasAttachments(): boolean;
  addAttachment(payload: Parameters<Attachments["add"]>[0], vendor: string, conformsTo?: string): void;
  attachment(digest: Digest): Envelope | undefined;
  removeAttachment(digest: Digest): Envelope | undefined;
  clearAttachments(): void;
  edges(): Edges;
  edgesMut(): Edges;
  hasEdges(): boolean;
  addEdge(edgeEnvelope: Envelope): void;
  edge(digest: Digest): Envelope | undefined;
  getEdge(digest: Digest): Envelope | undefined;
  removeEdge(digest: Digest): Envelope | undefined;
  clearEdges(): void;
  /** The current provenance mark. */
  get provenance(): ProvenanceMark | undefined;
  /** The generator when the document holds it in the clear. */
  get provenanceGenerator(): ProvenanceMarkGenerator | undefined;
  /** Sets (or clears) the mark, dropping any generator. */
  setProvenance(provenance: ProvenanceMark | undefined): void;
  setProvenanceWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): void;
  /**
   * Advances the chain: with the document's own generator (unlocked with
   * the password when locked), or with a provided one when the document
   * has none. The generator must continue the current mark's chain at
   * the next sequence number. `NoProvenanceMark` without a mark,
   * `NoGenerator`/`GeneratorConflict` for the wrong choice.
   */
  nextProvenanceMark({ date, info, password, generator }?: NextProvenanceMarkOptions): void;
  /**
   * The XID as the subject; `'dereferenceVia'`, `'key'`, `'delegate'`,
   * `'service'`, `'provenance'`, the extra assertions, attachments and
   * edges; then signed per `sign` (`MissingInceptionKey` when the
   * inception key or its private keys are missing).
   */
  toEnvelope({ privateKeys, generator, sign: signing }?: XIDEnvelopeOptions): Envelope;
  /** `toEnvelope` signed by `signer`, the generator omitted. */
  toSignedEnvelope(signer: Signer, { privateKeys }?: SignedEnvelopeOptions): Envelope;
  /**
   * A document from its envelope. With `verify: "inception"` the envelope
   * must be signed by the document's own inception key
   * (`EnvelopeNotSigned`, `SignatureVerificationFailed`, `InvalidXid`);
   * otherwise a wrapped (signed) subject is unwrapped and read as it is.
   * The password unlocks locked private keys and generators.
   */
  static fromEnvelope(envelope: Envelope, { password, verify }?: XIDParseOptions): XIDDocument;
  private static parse;
  /** An empty document is its XID's bytes; otherwise the envelope's tagged CBOR. */
  untaggedCbor(): Cbor;
  /** Tag `xid` (40024) over `untaggedCbor`. */
  toCbor(): Cbor;
  cborTags(): Tag[];
  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): CborCodec<XIDDocument> & {
    readonly tags: readonly Tag[];
  };
  private static fromUntaggedCbor;
  /** `ur:xid/…` over `untaggedCbor`. */
  toUR(): UR;
  static fromUR(ur: UR): XIDDocument;
  /**
   * Same XID, resolution methods, keys (public and private material,
   * nickname, endpoints, permissions), delegates, services, provenance
   * (mark and generator), attachments, edges and extra assertions — as
   * the reference's equality.
   */
  equals(other: XIDDocument): boolean;
  clone(): XIDDocument;
  toString(): string;
}
//#endregion
export { type ChainIdMismatchDetails, Delegate, type DelegateInput, type DelegateNotFoundDetails, type GeneratorData, type HasPermissions, type ItemDetails, Key, type KeyEnvelopeOptions, type KeyInput, type KeyNotFoundDetails, type NextProvenanceMarkOptions, PRIVILEGES, type ParseXIDDocument, type PasswordOptions, Permissions, type PermissionsInput, type PlainDetails, type PrivateKeyData, type Privilege, Provenance, type ProvenanceEnvelopeOptions, type ProvenanceInput, type SequenceMismatchDetails, Service, type ServiceDetails, type ServiceInput, type SignedEnvelopeOptions, type UnexpectedPredicateDetails, type UnknownReferenceDetails, type WrappedDetails, XIDDocument, type XIDDocumentInput, type XIDDocumentLike, type XIDEnvelopeOptions, XIDError, type XIDErrorCode, type XIDErrorDetails, type XIDGeneratorOptions, type XIDGenesis, type XIDInceptionKey, type XIDParseOptions, type XIDPrivateKeyOptions, type XIDSigning, type XIDVerifySignature, XID_ERROR_CODES, isPrivilege, privilegeEnvelope, privilegeFromEnvelope, privilegeFromKnownValue, privilegeKnownValue };
//# sourceMappingURL=index.d.mts.map