import { KnownValue } from "@blockchaincommons/known-values";
import { Envelope, EnvelopeInput, ToEnvelope } from "@blockchaincommons/envelope";
import { Cbor, CborCodec, CborTagged, Tag, ToCbor } from "@blockchaincommons/dcbor";
import { Digest, EncapsulationPublicKey, PrivateKeyBase, PrivateKeys, PublicKeys, Reference, Salt, Signature, Signer, SigningPublicKey, URI, Verifier, XID } from "@blockchaincommons/components";
import { ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution, ProvenanceSeed } from "@blockchaincommons/provenance-mark";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
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
/** Every code an `XIDError` can carry: the reference's `Error` variant names. */
type XIDErrorCode = "Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue" | "UnknownPrivilege" | "InvalidXid" | "MissingInceptionKey" | "InvalidResolutionMethod" | "MultipleProvenanceMarks" | "UnexpectedPredicate" | "UnexpectedNestedAssertions" | "NoPermissions" | "NoReferences" | "UnknownKeyReference" | "UnknownDelegateReference" | "KeyNotFoundInDocument" | "DelegateNotFoundInDocument" | "InvalidPassword" | "EnvelopeNotSigned" | "SignatureVerificationFailed" | "NoProvenanceMark" | "GeneratorConflict" | "NoGenerator" | "ChainIdMismatch" | "SequenceMismatch" | "EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark";
/** Every code, for exhaustive tables and tests. */
export declare const XID_ERROR_CODES: readonly XIDErrorCode[];
/** The fields each code carries besides `code`. */
interface XIDErrorDetailsByCode {
  /** An item of this kind is already there. */
  Duplicate: {
    /** The item's kind: `"key"`, `"delegate"`, `"service"`, `"nickname"`, … */
    readonly item: string;
  };
  /** No item of this kind is there. */
  NotFound: {
    /** The item's kind. */
    readonly item: string;
  };
  /** A service still names the item. */
  StillReferenced: {
    /** The item's kind. */
    readonly item: string;
  };
  /** The field must not be empty. */
  EmptyValue: {
    /** The field's name. */
    readonly item: string;
  };
  /** A known value that names no privilege. */
  UnknownPrivilege: unknown;
  /** The inception key does not produce the document's XID. */
  InvalidXid: unknown;
  /** The document has no inception key, or it has no private keys. */
  MissingInceptionKey: unknown;
  /** A `'dereferenceVia'` object that is not a URI. */
  InvalidResolutionMethod: unknown;
  /** More than one `'provenance'` assertion. */
  MultipleProvenanceMarks: unknown;
  /** A service assertion with a predicate the parser does not take. */
  UnexpectedPredicate: {
    /** The predicate's known value, as decimal text. */
    readonly predicate: string;
  };
  /** A service assertion whose object has assertions. */
  UnexpectedNestedAssertions: unknown;
  /** The service allows nothing. */
  NoPermissions: {
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names no key and no delegate. */
  NoReferences: {
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names a key the document lacks. */
  UnknownKeyReference: {
    /** The reference, rendered `Reference(<short hex>)`. */
    readonly reference: string;
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names a delegate the document lacks. */
  UnknownDelegateReference: {
    /** The reference, rendered `Reference(<short hex>)`. */
    readonly reference: string;
    /** The service's URI. */
    readonly uri: string;
  };
  /** `expectKey` found no such key. */
  KeyNotFoundInDocument: {
    /** The key's public keys, rendered. */
    readonly key: string;
  };
  /** `expectDelegate` found no such delegate. */
  DelegateNotFoundInDocument: {
    /** The delegate's XID, rendered. */
    readonly delegate: string;
  };
  /** A locked key or generator did not open. */
  InvalidPassword: unknown;
  /** Verification was asked of an unsigned envelope. */
  EnvelopeNotSigned: unknown;
  /** The inception key did not sign the envelope. */
  SignatureVerificationFailed: unknown;
  /** The document has no mark to advance. */
  NoProvenanceMark: unknown;
  /** A generator was given to a document that holds one. */
  GeneratorConflict: unknown;
  /** The document holds no generator and none was given. */
  NoGenerator: unknown;
  /** The generator continues another chain. */
  ChainIdMismatch: {
    /** The mark's chain id. */
    readonly expected: Uint8Array;
    /** The generator's chain id. */
    readonly actual: Uint8Array;
  };
  /** The generator's next sequence number is not the mark's plus one. */
  SequenceMismatch: {
    /** The sequence number the mark demands. */
    readonly expected: number;
    /** The generator's next sequence number. */
    readonly actual: number;
  };
  /** An envelope error inside a decoder; the error itself is `cause`. */
  EnvelopeParsing: {
    /** The envelope error's message. */
    readonly message: string;
  };
  /** A components error; the error itself is `cause`. */
  Component: {
    /** The components error's message. */
    readonly message: string;
  };
  /** A dcbor error inside a decoder; the error itself is `cause`. */
  Cbor: {
    /** The dcbor error's message. */
    readonly message: string;
  };
  /** A provenance-mark error; the error itself is `cause`. */
  ProvenanceMark: {
    /** The provenance-mark error's message. */
    readonly message: string;
  };
}
/** `details` of one code: `code` and that code's fields. */
type XIDErrorDetailsFor<C extends XIDErrorCode> = C extends XIDErrorCode ? {
  /** The discriminant. */
  readonly code: C;
} & XIDErrorDetailsByCode[C] : never;
/** `details` is discriminated by `code`. */
type XIDErrorDetails = XIDErrorDetailsFor<XIDErrorCode>;
/**
 * An `XIDError` whose `code` and `details` are narrowed to one code (or,
 * with the default argument, the union over every code), so `error.code
 * === "Duplicate"` narrows `error.details.item` to a string.
 */
type XIDErrorTyped<C extends XIDErrorCode = XIDErrorCode> = C extends XIDErrorCode ? XIDError & {
  /** The condition. */
  readonly code: C;
  /** The condition's fields. */
  readonly details: XIDErrorDetailsFor<C>;
} : never;
/** `details` of the four item codes. */
type ItemDetails = XIDErrorDetailsFor<"Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue">;
/** `details` of the codes with nothing more to say. */
type PlainDetails = XIDErrorDetailsFor<"UnknownPrivilege" | "InvalidXid" | "MissingInceptionKey" | "InvalidResolutionMethod" | "MultipleProvenanceMarks" | "UnexpectedNestedAssertions" | "InvalidPassword" | "EnvelopeNotSigned" | "SignatureVerificationFailed" | "NoProvenanceMark" | "GeneratorConflict" | "NoGenerator">;
/** `details` of `UnexpectedPredicate`. */
type UnexpectedPredicateDetails = XIDErrorDetailsFor<"UnexpectedPredicate">;
/** `details` of a service that is incomplete. */
type ServiceDetails = XIDErrorDetailsFor<"NoPermissions" | "NoReferences">;
/** `details` of a service reference that names nothing in the document. */
type UnknownReferenceDetails = XIDErrorDetailsFor<"UnknownKeyReference" | "UnknownDelegateReference">;
/** `details` of `KeyNotFoundInDocument`. */
type KeyNotFoundDetails = XIDErrorDetailsFor<"KeyNotFoundInDocument">;
/** `details` of `DelegateNotFoundInDocument`. */
type DelegateNotFoundDetails = XIDErrorDetailsFor<"DelegateNotFoundInDocument">;
/** `details` of `ChainIdMismatch`. */
type ChainIdMismatchDetails = XIDErrorDetailsFor<"ChainIdMismatch">;
/** `details` of `SequenceMismatch`. */
type SequenceMismatchDetails = XIDErrorDetailsFor<"SequenceMismatch">;
/** `details` of a wrapped failure from envelope, components, dcbor or provenance-mark. */
type WrappedDetails = XIDErrorDetailsFor<"EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark">;
/**
 * The error every operation of this package throws. `code` names the
 * condition (one of `XIDErrorCode`, the reference's variant names),
 * `details` is discriminated by it, and `cause` carries the sibling
 * error when a decoder wrapped one.
 *
 * ```ts
 * try {
 *   doc.addKey(key);
 * } catch (e) {
 *   if (XIDError.isXIDError(e) && e.is("Duplicate")) console.log(e.details.item);
 * }
 * ```
 */
export declare class XIDError extends Error {
  /** Always `"XIDError"`. */
  override readonly name = "XIDError";
  /** The condition, one of `XIDErrorCode`. */
  readonly code: XIDErrorCode;
  /** The fields of the condition, discriminated by `code`. */
  readonly details: XIDErrorDetails;
  private constructor();
  private static make;
  /** Whether `value` is an `XIDError`: an instance of this class. */
  static isXIDError(value: unknown): value is XIDError;
  /** Whether this error's code is `code`, narrowing `details`. */
  is<C extends XIDErrorCode>(code: C): this is XIDErrorTyped<C>;
  private static plain;
  /** `Duplicate`: an item of this kind is already there. */
  static duplicate(item: string): XIDErrorTyped<"Duplicate">;
  /** `NotFound`: no item of this kind is there. */
  static notFound(item: string): XIDErrorTyped<"NotFound">;
  /** `StillReferenced`: a service still names the item. */
  static stillReferenced(item: string): XIDErrorTyped<"StillReferenced">;
  /** `EmptyValue`: the field must not be empty. */
  static emptyValue(field: string): XIDErrorTyped<"EmptyValue">;
  /** `UnknownPrivilege`: a known value that names no privilege. */
  static unknownPrivilege(): XIDErrorTyped<"UnknownPrivilege">;
  /** `InvalidXid`: the inception key does not produce the document's XID. */
  static invalidXid(): XIDErrorTyped<"InvalidXid">;
  /** `MissingInceptionKey`: the document has no inception key, or it has no private keys. */
  static missingInceptionKey(): XIDErrorTyped<"MissingInceptionKey">;
  /** `InvalidResolutionMethod`: a `'dereferenceVia'` object that is not a URI. */
  static invalidResolutionMethod(): XIDErrorTyped<"InvalidResolutionMethod">;
  /** `MultipleProvenanceMarks`: more than one `'provenance'` assertion. */
  static multipleProvenanceMarks(): XIDErrorTyped<"MultipleProvenanceMarks">;
  /** `UnexpectedPredicate`: a service assertion with a predicate the parser does not take. */
  static unexpectedPredicate(predicate: string): XIDErrorTyped<"UnexpectedPredicate">;
  /** `UnexpectedNestedAssertions`: a service assertion whose object has assertions. */
  static unexpectedNestedAssertions(): XIDErrorTyped<"UnexpectedNestedAssertions">;
  /** `NoPermissions`: the service allows nothing. */
  static noPermissions(uri: string): XIDErrorTyped<"NoPermissions">;
  /** `NoReferences`: the service names no key and no delegate. */
  static noReferences(uri: string): XIDErrorTyped<"NoReferences">;
  /** `UnknownKeyReference`: the service names a key the document lacks. */
  static unknownKeyReference(reference: string, uri: string): XIDErrorTyped<"UnknownKeyReference">;
  /** `UnknownDelegateReference`: the service names a delegate the document lacks. */
  static unknownDelegateReference(reference: string, uri: string): XIDErrorTyped<"UnknownDelegateReference">;
  /** `KeyNotFoundInDocument`: `expectKey` found no such key. */
  static keyNotFoundInDocument(key: string): XIDErrorTyped<"KeyNotFoundInDocument">;
  /** `DelegateNotFoundInDocument`: `expectDelegate` found no such delegate. */
  static delegateNotFoundInDocument(delegate: string): XIDErrorTyped<"DelegateNotFoundInDocument">;
  /** `InvalidPassword`: a locked key or generator did not open. */
  static invalidPassword(): XIDErrorTyped<"InvalidPassword">;
  /** `EnvelopeNotSigned`: verification was asked of an unsigned envelope. */
  static envelopeNotSigned(): XIDErrorTyped<"EnvelopeNotSigned">;
  /** `SignatureVerificationFailed`: the inception key did not sign the envelope. */
  static signatureVerificationFailed(): XIDErrorTyped<"SignatureVerificationFailed">;
  /** `NoProvenanceMark`: the document has no mark to advance. */
  static noProvenanceMark(): XIDErrorTyped<"NoProvenanceMark">;
  /** `GeneratorConflict`: a generator was given to a document that holds one. */
  static generatorConflict(): XIDErrorTyped<"GeneratorConflict">;
  /** `NoGenerator`: the document holds no generator and none was given. */
  static noGenerator(): XIDErrorTyped<"NoGenerator">;
  /** `ChainIdMismatch`: the generator continues another chain. */
  static chainIdMismatch(expected: Uint8Array, actual: Uint8Array): XIDErrorTyped<"ChainIdMismatch">;
  /** `SequenceMismatch`: the generator's next sequence number is not the mark's plus one. */
  static sequenceMismatch(expected: number, actual: number): XIDErrorTyped<"SequenceMismatch">;
  /**
   * `EnvelopeParsing`: an envelope error inside a decoder. The message is
   * the reference's `envelope parsing error`; the envelope error is
   * `cause` and its message is `details.message`.
   */
  static envelopeParsing(cause: unknown): XIDErrorTyped<"EnvelopeParsing">;
  /** `Component`: a components error; the message is the reference's `component error`. */
  static component(cause: unknown): XIDErrorTyped<"Component">;
  /** `Cbor`: a dcbor error inside a decoder; the message is the reference's `CBOR error`. */
  static cbor(cause: unknown): XIDErrorTyped<"Cbor">;
  /**
   * `Cbor` from a CBOR or UR decoder entry point (`fromCbor`,
   * `fromUntaggedCbor`, `fromUR`), where the reference returns the dcbor
   * error itself: the message is the dcbor error's.
   */
  static cborDecode(cause: Error): XIDErrorTyped<"Cbor">;
  /** `ProvenanceMark`: a provenance-mark error; the message is the reference's `provenance mark error`. */
  static provenanceMark(cause: unknown): XIDErrorTyped<"ProvenanceMark">;
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
/** Every privilege, in the reference's order. */
export declare const PRIVILEGES: readonly Privilege[];
/** Whether `value` is one of the privilege names. */
export declare function isPrivilege(value: unknown): value is Privilege;
/** The known value the privilege is encoded as; `UnknownPrivilege` for a name that is not one. */
export declare function privilegeKnownValue(privilege: Privilege): KnownValue;
/** The privilege a known value names; `UnknownPrivilege` for any other value. */
export declare function privilegeFromKnownValue(knownValue: KnownValue): Privilege;
/** The privilege as a known-value envelope. */
export declare function privilegeEnvelope(privilege: Privilege): Envelope;
/**
 * The privilege a known-value envelope names: `EnvelopeParsing` when the
 * subject is not a known value, `UnknownPrivilege` when it names no
 * privilege.
 */
export declare function privilegeFromEnvelope(envelope: Envelope): Privilege;
//#endregion
//#region src/permissions.d.ts
/** What `Permissions.from` takes. */
interface PermissionsInput {
  /** The privileges allowed. */
  allow?: Iterable<Privilege> | undefined;
  /** The privileges denied. */
  deny?: Iterable<Privilege> | undefined;
}
/** Something that carries permissions: a key, a delegate, a service. */
interface HasPermissions {
  /** The permissions (live). */
  readonly permissions: Permissions;
  /** Allows `privilege`. */
  allow(privilege: Privilege): void;
  /** Denies `privilege`. */
  deny(privilege: Privilege): void;
}
/** An allow set and a deny set of privileges. */
export declare class Permissions {
  private readonly _allow;
  private readonly _deny;
  private constructor();
  /** Empty sets unless given. */
  static from({ allow, deny }?: PermissionsInput): Permissions;
  /** `All` allowed, nothing denied. */
  static allowAll(): Permissions;
  /** The allowed privileges (a copy). */
  get allow(): ReadonlySet<Privilege>;
  /** The denied privileges (a copy). */
  get deny(): ReadonlySet<Privilege>;
  /** Allows `privilege`. */
  addAllow(privilege: Privilege): void;
  /** Denies `privilege`. */
  addDeny(privilege: Privilege): void;
  /** Stops allowing `privilege`. */
  removeAllow(privilege: Privilege): void;
  /** Stops denying `privilege`. */
  removeDeny(privilege: Privilege): void;
  /** Empties both sets. */
  clear(): void;
  /**
   * Allowed (directly or through `All`) and not denied (directly or
   * through `All`): a denial wins over an allowance. This is the
   * package's own rule; the reference exposes the sets only.
   */
  isAllowed(privilege: Privilege): boolean;
  /** Denied directly or through `All`. */
  isDenied(privilege: Privilege): boolean;
  /** Adds an `'allow'` assertion per allowed privilege, then a `'deny'` per denied one. */
  addToEnvelope(envelope: Envelope): Envelope;
  /**
   * The `'allow'` and `'deny'` assertions of an envelope. An object that
   * is not a known value is `EnvelopeParsing`; one that names no
   * privilege is `UnknownPrivilege`.
   */
  static fromEnvelope(envelope: Envelope): Permissions;
  /** Same allow and deny sets. */
  equals(other: Permissions): boolean;
  /** A copy. */
  clone(): Permissions;
}
//#endregion
//#region src/key.d.ts
/**
 * How a key's private keys go into an envelope: left out, included (with
 * a salt), elided (the digest of the included form), or locked with a
 * password (Argon2id unless `method` says otherwise).
 */
type XIDPrivateKeyOptions = "omit" | "include" | "elide" | EncryptOptions;
/** The password-locked form of private keys or a generator. */
interface EncryptOptions {
  /** The password, as text or bytes. */
  encrypt: Uint8Array | string;
  /** The key derivation method; Argon2id unless given. */
  method?: KeyDerivationMethod | undefined;
}
/** What `Key.from` takes besides the public keys. */
interface KeyInput {
  /** With private keys the key is allowed `All` unless `permissions` says otherwise. */
  privateKeys?: PrivateKeys | undefined;
  /** The nickname; none unless given. */
  nickname?: string | undefined;
  /** The endpoints, as URIs or their text. */
  endpoints?: Iterable<URI | string> | undefined;
  /** The permissions; empty unless given (or `All` with private keys). */
  permissions?: Permissions | undefined;
}
/** A password for a locked key or generator, as text or bytes. */
interface PasswordOptions {
  /** The password; absent means "leave locked material locked". */
  password?: Uint8Array | string | undefined;
}
/** What `Key.toEnvelope` takes. */
interface KeyEnvelopeOptions {
  /** How the private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
}
/**
 * A key of a XID document: public keys, optionally private keys (in the
 * clear or password-locked), a nickname, endpoints and permissions.
 */
export declare class Key implements HasPermissions, Verifier {
  private readonly _publicKeys;
  private readonly _privateKeyData;
  private _nickname;
  private readonly _endpoints;
  private readonly _permissions;
  private constructor();
  /**
   * A key from its public keys; no permissions unless private keys or
   * `permissions` are given. A `null` `privateKeys` is a `TypeError`:
   * absent private keys are `undefined`.
   */
  static from(publicKeys: PublicKeys, { privateKeys, nickname, endpoints, permissions }?: KeyInput): Key;
  /** A public key allowed `All`. */
  static allowAll(publicKeys: PublicKeys): Key;
  /** The Schnorr and X25519 keys of a base, private keys included, allowed `All`. */
  static fromPrivateKeyBase(privateKeyBase: PrivateKeyBase): Key;
  /** The public keys. */
  get publicKeys(): PublicKeys;
  /** The private keys when held in the clear. */
  get privateKeys(): PrivateKeys | undefined;
  /** Whether the private keys are held in the clear. */
  get hasPrivateKeys(): boolean;
  /** Whether the private keys are held locked (parsed without the password). */
  get hasEncryptedPrivateKeys(): boolean;
  /** The salt the `'privateKey'` assertion carries. */
  get privateKeySalt(): Salt | undefined;
  /** The reference of the public keys. */
  get reference(): Reference;
  /** The signing public key. */
  get signingPublicKey(): SigningPublicKey;
  /** The encapsulation public key. */
  encapsulationPublicKey(): EncapsulationPublicKey;
  /** Whether `signature` is the public keys' signature of `message`. */
  verify(signature: Signature, message: Uint8Array): boolean;
  /** The endpoints (a copy). */
  get endpoints(): ReadonlySet<URI>;
  /** Adds an endpoint, as a URI or its text (a components error for text that is not a URI). */
  addEndpoint(endpoint: URI | string): void;
  /** The nickname; empty when there is none. */
  get nickname(): string;
  /** Sets (or clears, with `""`) the nickname. */
  setNickname(name: string): void;
  /** Sets the nickname once: `Duplicate` when set, `EmptyValue` when empty. */
  addNickname(name: string): void;
  /** The permissions (live). */
  get permissions(): Permissions;
  /** Allows `privilege`. */
  allow(privilege: Privilege): void;
  /** Denies `privilege`. */
  deny(privilege: Privilege): void;
  private privateKeyAssertionEnvelope;
  /**
   * The public keys as the subject, the private keys per `privateKeys`
   * (a locked key stays locked), then `'nickname'`, `'endpoint'`s and
   * the permissions. An unknown option is a `TypeError`.
   */
  toEnvelope({ privateKeys }?: KeyEnvelopeOptions): Envelope;
  /**
   * A key from its envelope. A locked `'privateKey'` is unlocked with the
   * password when one is given and it fits; otherwise it is kept locked.
   * Every failure is an `XIDError`: a subject or leaf of the wrong type
   * is `Cbor`; a missing or repeated `'salt'`, a second `'nickname'` or
   * one that is not text are `EnvelopeParsing`; a permission that is not
   * a known value is `EnvelopeParsing`, one that names no privilege is
   * `UnknownPrivilege`.
   */
  static fromEnvelope(envelope: Envelope, { password }?: PasswordOptions): Key;
  private static privateKeyDataOf;
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
  /** A copy: the private material shared, the endpoints and permissions copied. */
  clone(): Key;
}
//#endregion
//#region src/service.d.ts
/** What `Service.from` takes besides the URI. */
interface ServiceInput {
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
export declare class Service implements HasPermissions {
  private readonly _uri;
  private readonly _keyReferences;
  private readonly _delegateReferences;
  private readonly _permissions;
  private _capability;
  private _name;
  private constructor();
  /**
   * A service at a URI (a components error for text that is not a URI);
   * references and permissions can be added later.
   */
  static from(uri: URI | string, { capability, name, keyReferences, delegateReferences, permissions }?: ServiceInput): Service;
  /** The URI. */
  get uri(): URI;
  /** The capability; empty when there is none. */
  get capability(): string;
  /** Sets (or clears, with `""`) the capability. */
  setCapability(capability: string): void;
  /** Sets the capability once; `Duplicate` when set, `EmptyValue` when empty. */
  addCapability(capability: string): void;
  /** The key references (a copy). */
  get keyReferences(): ReadonlySet<Reference>;
  /** Whether the service references this key. */
  hasKeyReference(reference: Reference): boolean;
  /** Adds a key reference; `Duplicate` when it is already there. */
  addKeyReference(keyReference: Reference): void;
  /** Adds a key reference given as 64 hex characters (a components error otherwise). */
  addKeyReferenceHex(keyReferenceHex: string): void;
  /** References the key's public keys. */
  addKey(key: {
    readonly publicKeys: PublicKeys;
  }): void;
  /** The delegate references (a copy). */
  get delegateReferences(): ReadonlySet<Reference>;
  /** Whether the service references this delegate. */
  hasDelegateReference(reference: Reference): boolean;
  /** Adds a delegate reference; `Duplicate` when it is already there. */
  addDelegateReference(delegateReference: Reference): void;
  /** Adds a delegate reference given as 64 hex characters (a components error otherwise). */
  addDelegateReferenceHex(delegateReferenceHex: string): void;
  /** References the delegate's (or document's) XID. */
  addDelegate(delegate: {
    readonly xid: XID;
  }): void;
  /** The name; empty when there is none. */
  get name(): string;
  /** Sets the name once; `Duplicate` when set, `EmptyValue` when empty. */
  setName(name: string): void;
  /** The permissions (live). */
  get permissions(): Permissions;
  /** Allows `privilege`. */
  allow(privilege: Privilege): void;
  /** Denies `privilege` (written to the wire, but not read back: see the class). */
  deny(privilege: Privilege): void;
  /** The URI as the subject; `'key'`, `'delegate'`, `'capability'`, `'name'` and the permissions. */
  toEnvelope(): Envelope;
  /**
   * A service from its envelope. Rejects nested assertions
   * (`UnexpectedNestedAssertions`) and any predicate but `'key'`,
   * `'delegate'`, `'capability'`, `'name'` and `'allow'`
   * (`UnexpectedPredicate`; a predicate that is not a known value is
   * `EnvelopeParsing`); a subject or object of the wrong type is `Cbor`.
   */
  static fromEnvelope(envelope: Envelope): Service;
  /** Same URI, references, permissions, capability and name — as the reference's equality. */
  equals(other: Service): boolean;
  /** A copy. */
  clone(): Service;
}
//#endregion
//#region src/delegate.d.ts
/** What a delegate needs of its controller: `XIDDocument`, without importing it. */
interface XIDDocumentLike {
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
interface DelegateInput {
  /** The permissions granted; none unless given. */
  permissions?: Permissions | undefined;
}
/** What `Delegate.fromEnvelope` takes besides the envelope. */
interface DelegateParseOptions {
  /** The parser of the controller's envelope; `XIDDocument.fromEnvelope` unless given. */
  parseDocument?: ParseXIDDocument | undefined;
}
/** A delegate: a controller document and the permissions this document grants it. */
export declare class Delegate implements HasPermissions {
  private readonly _controller;
  private readonly _permissions;
  private constructor();
  /** A delegate controlled by `controller`, with no permissions unless given. */
  static from(controller: XIDDocumentLike, { permissions }?: DelegateInput): Delegate;
  /** The controlling document (live: mutating it mutates the delegate). */
  get controller(): XIDDocumentLike;
  /** The controller's XID. */
  get xid(): XID;
  /** The reference of the controller's XID. */
  get reference(): Reference;
  /** The permissions granted (live). */
  get permissions(): Permissions;
  /** Allows `privilege`. */
  allow(privilege: Privilege): void;
  /** Denies `privilege`. */
  deny(privilege: Privilege): void;
  /** The controller's envelope, wrapped, with the permissions. */
  toEnvelope(): Envelope;
  /**
   * A delegate from its envelope: the permissions, then the unwrapped
   * controller parsed by `parseDocument` (`XIDDocument.fromEnvelope`
   * unless given). A sibling failure is `EnvelopeParsing`.
   */
  static fromEnvelope(envelope: Envelope, { parseDocument }?: DelegateParseOptions): Delegate;
  /** Same controller document and permissions — as the reference's equality. */
  equals(other: Delegate): boolean;
  /** A deep copy. */
  clone(): Delegate;
}
//#endregion
//#region src/provenance.d.ts
/** How the generator goes into an envelope; the same four forms as private keys. */
type XIDGeneratorOptions = "omit" | "include" | "elide" | EncryptOptions;
/** What `Provenance.from` takes besides the mark. */
interface ProvenanceInput {
  /** The generator that produced the mark, when the document should keep it. */
  generator?: ProvenanceMarkGenerator | undefined;
}
/** What `Provenance.toEnvelope` takes. */
interface ProvenanceEnvelopeOptions {
  /** How the generator goes into the envelope; `"omit"` unless given. */
  generator?: XIDGeneratorOptions | undefined;
}
/** A provenance mark and, optionally, the generator that continues its chain. */
export declare class Provenance {
  private _mark;
  private _generator;
  private constructor();
  /** A mark, with the generator that produced it when the document should keep it. */
  static from(mark: ProvenanceMark, { generator }?: ProvenanceInput): Provenance;
  /** The current mark. */
  get mark(): ProvenanceMark;
  /** The generator when held in the clear. */
  get generator(): ProvenanceMarkGenerator | undefined;
  /** Whether the generator is held in the clear. */
  get hasGenerator(): boolean;
  /** Whether the generator is held locked (parsed without the password). */
  get hasEncryptedGenerator(): boolean;
  /** The salt the `'provenanceGenerator'` assertion carries. */
  get generatorSalt(): Salt | undefined;
  /** Replaces the mark (no chain check, as the reference's `set_mark`). */
  setMark(mark: ProvenanceMark): void;
  /** Sets or replaces the generator, with a fresh salt. */
  setGenerator(generator: ProvenanceMarkGenerator): void;
  /** Removes the generator, returning whether one was held. */
  takeGenerator(): boolean;
  /**
   * The generator, unlocking a locked one with the password (it stays
   * unlocked); `InvalidPassword` when it is locked and the password is
   * missing or wrong; `undefined` when there is no generator.
   */
  unlockGenerator({ password }?: PasswordOptions): ProvenanceMarkGenerator | undefined;
  /** A generator from its envelope; a provenance-mark failure is `ProvenanceMark`. */
  private static generatorOf;
  private generatorAssertionEnvelope;
  /**
   * The generator as an envelope: in the clear when held so, unlocked
   * with the password when locked (`InvalidPassword` when it does not
   * fit), or the locked envelope itself without a password.
   */
  generatorEnvelope({ password }?: PasswordOptions): Envelope | undefined;
  /**
   * The mark as the subject; the generator per `generator` (a locked one
   * stays locked). An unknown option is a `TypeError`.
   */
  toEnvelope({ generator }?: ProvenanceEnvelopeOptions): Envelope;
  /**
   * A provenance from its envelope. A locked generator is unlocked with
   * the password when one is given and it fits; otherwise it is kept
   * locked. A subject that is not a mark is `Cbor`; a missing or repeated
   * `'salt'` is `EnvelopeParsing`; a generator envelope that is not a
   * generator's is `ProvenanceMark`.
   */
  static fromEnvelope(envelope: Envelope, { password }?: PasswordOptions): Provenance;
  private static generatorDataOf;
  /** Same mark and generator (in the clear or locked, with its salt) — as the reference's equality. */
  equals(other: Provenance): boolean;
  /** A copy: the generator material shared. */
  clone(): Provenance;
}
//#endregion
//#region src/xid-document.d.ts
/**
 * The inception key of a new document: public keys only, a private key
 * base (Schnorr keys, private keys held), or a public/private pair.
 */
type XIDInceptionKey = PublicKeys | PrivateKeyBase | XIDInceptionKeyPair;
/** An inception key given as a public/private pair. */
interface XIDInceptionKeyPair {
  /** The public keys. */
  publicKeys: PublicKeys;
  /** The private keys (not checked against the public keys, as the reference does not). */
  privateKeys: PrivateKeys;
}
/**
 * The genesis provenance mark of a new document: exactly one of a
 * passphrase or a 32-byte seed (a `ProvenanceSeed` or its bytes), the
 * resolution (`"high"` unless given), the date (now unless given) and
 * the mark's info.
 */
interface XIDGenesis {
  /** The passphrase the chain's seed derives from. */
  passphrase?: string | undefined;
  /** The chain's seed: a `ProvenanceSeed` or exactly 32 bytes. */
  seed?: Uint8Array | ProvenanceSeed | undefined;
  /** The chain's resolution; `"high"` unless given. */
  resolution?: ProvenanceMarkResolution | undefined;
  /** The genesis mark's date; now unless given. */
  date?: Date | undefined;
  /** The genesis mark's info. */
  info?: Cbor | undefined;
}
/** What `XIDDocument.from` takes. */
interface XIDDocumentInput {
  /** The inception key, whose signing key the XID derives from. */
  inceptionKey: XIDInceptionKey;
  /** A genesis mark to start the provenance chain with. */
  genesis?: XIDGenesis | undefined;
}
/** What `XIDDocument.random` takes. */
interface XIDRandomOptions extends RngOptions {
  /** A genesis mark to start the provenance chain with. */
  genesis?: XIDGenesis | undefined;
}
/** Who signs the document's envelope: nobody, the inception key, or a given signer. */
type XIDSigning = "none" | "inception" | Signer;
/** Which signature `fromEnvelope` demands. */
type XIDVerifySignature = "none" | "inception";
/** What `XIDDocument.toEnvelope` takes. */
interface XIDEnvelopeOptions {
  /** How each key's private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
  /** How the provenance generator goes into the envelope; `"omit"` unless given. */
  generator?: XIDGeneratorOptions | undefined;
  /** Who signs; `"none"` unless given. */
  sign?: XIDSigning | undefined;
}
/** What `XIDDocument.fromEnvelope` takes. */
interface XIDParseOptions extends PasswordOptions {
  /** Which signature to demand; `"none"` unless given. */
  verify?: XIDVerifySignature | undefined;
}
/** What `XIDDocument.toSignedEnvelope` takes besides the signer. */
interface SignedEnvelopeOptions {
  /** How each key's private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
}
/** What `XIDDocument.addAttachment` takes. */
interface AttachmentInput {
  /** The payload, as anything an envelope is made from. */
  payload: EnvelopeInput;
  /** The vendor, a reverse domain name. */
  vendor: string;
  /** The URI of the format the payload conforms to. */
  conformsTo?: string | undefined;
}
/** What `nextProvenanceMark` takes. */
interface NextProvenanceMarkOptions extends PasswordOptions {
  /** The new mark's date; now unless given. */
  date?: Date | undefined;
  /** The new mark's info. */
  info?: Cbor | undefined;
  /**
   * A generator kept outside the document; refused when the document
   * holds one. When given, `password` is not used.
   */
  generator?: ProvenanceMarkGenerator | undefined;
}
/** The document's CBOR codec, with the tag it carries. */
interface XIDDocumentCodec extends CborCodec<XIDDocument> {
  /** The `xid` tag (40024). */
  readonly tags: readonly Tag[];
}
/**
 * A XID document: the keys, delegates, services, resolution methods,
 * provenance, attachments and edges published under an extensible
 * identifier. The document is mutable; its `keys`, `delegates` and
 * `services` are copied-out arrays of live values, and `attachments` and
 * `edges()` are the document's own containers.
 */
export declare class XIDDocument implements ToEnvelope, ToCbor, CborTagged, ToUR, Edgeable {
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
   * chain and keeps the generator in the document. A missing inception
   * key or a malformed genesis is a `TypeError`; a seed of the wrong
   * length is `ProvenanceMark`.
   */
  static from({ inceptionKey, genesis }: XIDDocumentInput): XIDDocument;
  /** A document with a random private key base as its inception key. */
  static random({ rng, genesis }?: XIDRandomOptions): XIDDocument;
  /** An empty document: just the XID. */
  static fromXid(xid: XID): XIDDocument;
  private static keyFor;
  private static genesisFor;
  /** A `ProvenanceSeed` from bytes; the wrong length is `ProvenanceMark`. */
  private static seedOf;
  /** The XID. */
  get xid(): XID;
  /** The XID's reference. */
  get reference(): Reference;
  /** No keys, delegates, services, resolution methods, provenance, attachments, edges or extra assertions. */
  get isEmpty(): boolean;
  /** Assertions the parser did not recognise, kept as they were (a copy). */
  get extraAssertions(): readonly Envelope[];
  /** The resolution methods (a copy). */
  get resolutionMethods(): ReadonlySet<URI>;
  /** Adds a resolution method, as a URI or its text (a components error for text that is not a URI). */
  addResolutionMethod(method: URI | string): void;
  /** Removes a resolution method; whether it was there. */
  removeResolutionMethod(method: URI | string): boolean;
  /** The keys (a copied-out array of live keys). */
  get keys(): readonly Key[];
  /** Adds a key; `Duplicate` when the public keys are already there. */
  addKey(key: Key): void;
  /** The key with these public keys. */
  key(publicKeys: PublicKeys): Key | undefined;
  /** The key with this reference. */
  keyByReference(reference: Reference): Key | undefined;
  /**
   * Removes and returns the key; `StillReferenced` when a service names
   * it, `NotFound` when it is not there.
   */
  removeKey(publicKeys: PublicKeys): Key;
  /** Removes and returns the key without checking services; `undefined` when absent. */
  takeKey(publicKeys: PublicKeys): Key | undefined;
  /** The key with these public keys; `KeyNotFoundInDocument` unless it is there. */
  expectKey(publicKeys: PublicKeys): Key;
  /** Whether the XID derives from this signing key. */
  isInceptionSigningKey(signingPublicKey: SigningPublicKey): boolean;
  /** The key whose signing key the XID derives from. */
  get inceptionKey(): Key | undefined;
  /** The inception key's private keys, when held in the clear. */
  get inceptionPrivateKeys(): PrivateKeys | undefined;
  /** The inception key's signing key. */
  get inceptionSigningKey(): SigningPublicKey | undefined;
  /** The inception key's signing key, else the first key's. */
  get verificationKey(): SigningPublicKey | undefined;
  /** The inception key's encapsulation key, else the first key's. */
  get encryptionKey(): EncapsulationPublicKey | undefined;
  /** Removes and returns the inception key, if there is one. */
  removeInceptionKey(): Key | undefined;
  /** Sets the key's nickname; `NotFound` unless the key is there. */
  setNameForKey(publicKeys: PublicKeys, name: string): void;
  /** The private keys of a key as an envelope (see `Key.privateKeyEnvelope`). */
  privateKeyEnvelopeForKey(publicKeys: PublicKeys, options?: PasswordOptions): Envelope | undefined;
  /** The inception key's private keys of a parsed envelope, unlocked with the password. */
  static inceptionPrivateKeysFromEnvelope(envelope: Envelope, { password }?: PasswordOptions): PrivateKeys | undefined;
  /** The delegates (a copied-out array of live delegates). */
  get delegates(): readonly Delegate[];
  /** Adds a delegate; `Duplicate` when a delegate with that XID is already there. */
  addDelegate(delegate: Delegate): void;
  /** The delegate with this XID. */
  delegate(xid: XID): Delegate | undefined;
  /** The delegate whose XID has this reference. */
  delegateByReference(reference: Reference): Delegate | undefined;
  /** Removes and returns the delegate; `StillReferenced` when a service names it, `NotFound` when absent. */
  removeDelegate(xid: XID): Delegate;
  /** Removes and returns the delegate without checking services; `undefined` when absent. */
  takeDelegate(xid: XID): Delegate | undefined;
  /** The delegate with this XID; `DelegateNotFoundInDocument` unless it is there. */
  expectDelegate(xid: XID): Delegate;
  /** The services (a copied-out array of live services). */
  get services(): readonly Service[];
  /** The service at this URI. */
  service(uri: URI | string): Service | undefined;
  /** Adds a service; `Duplicate` when a service at that URI is already there. */
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
  /** Whether any service references this key. */
  servicesReferenceKey(publicKeys: PublicKeys): boolean;
  /** Whether any service references this delegate. */
  servicesReferenceDelegate(xid: XID): boolean;
  /** The attachments: the document's own container. */
  get attachments(): Attachments;
  /** Whether there are attachments. */
  get hasAttachments(): boolean;
  /** Adds an attachment. */
  addAttachment({ payload, vendor, conformsTo }: AttachmentInput): void;
  /** The attachment with this digest. */
  attachment(digest: Digest): Envelope | undefined;
  /** Removes and returns the attachment with this digest. */
  removeAttachment(digest: Digest): Envelope | undefined;
  /** Removes every attachment. */
  clearAttachments(): void;
  /** The edges: the document's own container (envelope's `Edgeable`). */
  edges(): Edges;
  /** The same container as `edges()` (envelope's `Edgeable` names both). */
  edgesMut(): Edges;
  /** Whether there are edges (envelope's `Edgeable`). */
  hasEdges(): boolean;
  /** Adds an edge envelope. */
  addEdge(edgeEnvelope: Envelope): void;
  /** The edge with this digest. */
  edge(digest: Digest): Envelope | undefined;
  /** `edge(digest)` under the name envelope's `Edgeable` uses. */
  getEdge(digest: Digest): Envelope | undefined;
  /** Removes and returns the edge with this digest. */
  removeEdge(digest: Digest): Envelope | undefined;
  /** Removes every edge. */
  clearEdges(): void;
  /** The current provenance mark. */
  get provenance(): ProvenanceMark | undefined;
  /** The generator when the document holds it in the clear. */
  get provenanceGenerator(): ProvenanceMarkGenerator | undefined;
  /** Sets (or clears) the mark, dropping any generator. */
  setProvenance(provenance: ProvenanceMark | undefined): void;
  /** Sets the mark and the generator that continues its chain. */
  setProvenanceWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): void;
  /**
   * Advances the chain: with the document's own generator (unlocked with
   * the password when locked), or with a provided one when the document
   * has none. The generator must continue the current mark's chain at
   * the next sequence number. `NoProvenanceMark` without a mark,
   * `NoGenerator`/`GeneratorConflict` for the wrong choice,
   * `ChainIdMismatch`/`SequenceMismatch` for a generator that does not
   * continue the mark; an invalid date is a `TypeError`.
   */
  nextProvenanceMark({ date, info, password, generator }?: NextProvenanceMarkOptions): void;
  /**
   * The XID as the subject; `'dereferenceVia'`, `'key'`, `'delegate'`,
   * `'service'`, `'provenance'`, the extra assertions, attachments and
   * edges; then signed per `sign` (`MissingInceptionKey` when the
   * inception key or its private keys are missing). An unknown option
   * is a `TypeError`.
   */
  toEnvelope({ privateKeys, generator, sign: signing }?: XIDEnvelopeOptions): Envelope;
  /** The `sign` option checked: one of the two names, or a signer. */
  private static signerOf;
  /** `toEnvelope` signed by `signer`, the generator omitted. */
  toSignedEnvelope(signer: Signer, { privateKeys }?: SignedEnvelopeOptions): Envelope;
  /**
   * A document from its envelope. With `verify: "inception"` the envelope
   * must be signed by the document's own inception key
   * (`EnvelopeNotSigned`, `SignatureVerificationFailed`, `InvalidXid`);
   * otherwise a wrapped (signed) subject is unwrapped and read as it is.
   * The password unlocks locked private keys and generators. Every
   * failure is an `XIDError`: a sibling error inside the parser is
   * wrapped with the reference's code. An unknown `verify` is a
   * `TypeError`.
   */
  static fromEnvelope(envelope: Envelope, { password, verify }?: XIDParseOptions): XIDDocument;
  private static parse;
  /** An empty document is its XID's bytes; otherwise the envelope's tagged CBOR. */
  untaggedCbor(): Cbor;
  /** Tag `xid` (40024) over `untaggedCbor`. */
  toCbor(): Cbor;
  /** The tags this document's CBOR carries: `xid` (40024). */
  cborTags(): Tag[];
  /** The tagged-CBOR codec: `decode` is `fromCbor`, the tag required. */
  static get codec(): XIDDocumentCodec;
  /**
   * A document from its tagged CBOR: the `xid` tag (40024) over the
   * untagged form. A missing or different tag, or a form the untagged
   * decoder rejects, is `Cbor` with the dcbor error's message.
   */
  static fromCbor(cborValue: Cbor): XIDDocument;
  /**
   * A document from its untagged CBOR: a 32-byte string is the XID of an
   * empty document; anything else is a document envelope. A tagged value
   * is rejected (the envelope tag is expected), as the reference's
   * `from_untagged_cbor` rejects it. A rejection is `Cbor`: the dcbor
   * error's message, or the document error's (`envelope parsing error`,
   * …) when the envelope decodes but the document does not.
   */
  static fromUntaggedCbor(cborValue: Cbor): XIDDocument;
  /** `ur:xid/…` over `untaggedCbor`. */
  toUR(): UR;
  /**
   * A document from a `ur:xid/…` UR. A UR of another type is `Cbor`
   * (`expected UR type xid, but found …`), as the reference's `from_ur`
   * reports it.
   */
  static fromUR(ur: UR): XIDDocument;
  /**
   * Same XID, resolution methods, keys (public and private material,
   * nickname, endpoints, permissions), delegates, services, provenance
   * (mark and generator), attachments, edges and extra assertions — as
   * the reference's equality.
   */
  equals(other: XIDDocument): boolean;
  /** A deep copy. */
  clone(): XIDDocument;
  /** `XIDDocument(<short XID>)`. */
  toString(): string;
}
//#endregion
export type { AttachmentInput, ChainIdMismatchDetails, DelegateInput, DelegateNotFoundDetails, DelegateParseOptions, EncryptOptions, HasPermissions, ItemDetails, KeyEnvelopeOptions, KeyInput, KeyNotFoundDetails, NextProvenanceMarkOptions, ParseXIDDocument, PasswordOptions, PermissionsInput, PlainDetails, Privilege, ProvenanceEnvelopeOptions, ProvenanceInput, SequenceMismatchDetails, ServiceDetails, ServiceInput, SignedEnvelopeOptions, UnexpectedPredicateDetails, UnknownReferenceDetails, WrappedDetails, XIDDocumentCodec, XIDDocumentInput, XIDDocumentLike, XIDEnvelopeOptions, XIDErrorCode, XIDErrorDetails, XIDErrorDetailsByCode, XIDErrorDetailsFor, XIDErrorTyped, XIDGeneratorOptions, XIDGenesis, XIDInceptionKey, XIDInceptionKeyPair, XIDParseOptions, XIDPrivateKeyOptions, XIDRandomOptions, XIDSigning, XIDVerifySignature };
//# sourceMappingURL=index.d.mts.map