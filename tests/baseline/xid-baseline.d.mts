import { EncapsulationPublicKey, KeyDerivationMethod, PrivateKeyBase, PrivateKeys, PublicKeys, Reference, Salt, Signature, Signer, SigningPrivateKey, SigningPublicKey, URI, Verifier, XID, XID as XID$1 } from "@blockchaincommons/components";
import { KnownValue } from "@blockchaincommons/known-values";
import { Attachments, Attachments as Attachments$1, Digest, Edgeable, Edgeable as Edgeable$1, Edges, Edges as Edges$1, Envelope, EnvelopeEncodable, EnvelopeEncodableValue } from "@blockchaincommons/envelope";
import { ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution } from "@blockchaincommons/provenance-mark";
import { Cbor } from "@blockchaincommons/dcbor-compat";
import { UR } from "@blockchaincommons/uniform-resources";
//#region src/error.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 *
 * XID Error Types
 *
 * Error types returned when operating on XID Documents.
 * Ported from bc-xid-rust/src/error.rs
 */
declare enum XIDErrorCode {
  DUPLICATE = "DUPLICATE",
  NOT_FOUND = "NOT_FOUND",
  STILL_REFERENCED = "STILL_REFERENCED",
  EMPTY_VALUE = "EMPTY_VALUE",
  UNKNOWN_PRIVILEGE = "UNKNOWN_PRIVILEGE",
  INVALID_XID = "INVALID_XID",
  MISSING_INCEPTION_KEY = "MISSING_INCEPTION_KEY",
  INVALID_RESOLUTION_METHOD = "INVALID_RESOLUTION_METHOD",
  MULTIPLE_PROVENANCE_MARKS = "MULTIPLE_PROVENANCE_MARKS",
  UNEXPECTED_PREDICATE = "UNEXPECTED_PREDICATE",
  UNEXPECTED_NESTED_ASSERTIONS = "UNEXPECTED_NESTED_ASSERTIONS",
  NO_PERMISSIONS = "NO_PERMISSIONS",
  NO_REFERENCES = "NO_REFERENCES",
  UNKNOWN_KEY_REFERENCE = "UNKNOWN_KEY_REFERENCE",
  UNKNOWN_DELEGATE_REFERENCE = "UNKNOWN_DELEGATE_REFERENCE",
  KEY_NOT_FOUND_IN_DOCUMENT = "KEY_NOT_FOUND_IN_DOCUMENT",
  DELEGATE_NOT_FOUND_IN_DOCUMENT = "DELEGATE_NOT_FOUND_IN_DOCUMENT",
  INVALID_PASSWORD = "INVALID_PASSWORD",
  ENVELOPE_NOT_SIGNED = "ENVELOPE_NOT_SIGNED",
  SIGNATURE_VERIFICATION_FAILED = "SIGNATURE_VERIFICATION_FAILED",
  NO_PROVENANCE_MARK = "NO_PROVENANCE_MARK",
  GENERATOR_CONFLICT = "GENERATOR_CONFLICT",
  NO_GENERATOR = "NO_GENERATOR",
  CHAIN_ID_MISMATCH = "CHAIN_ID_MISMATCH",
  SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH",
  ENVELOPE_PARSING = "ENVELOPE_PARSING",
  COMPONENT = "COMPONENT",
  CBOR = "CBOR",
  PROVENANCE_MARK = "PROVENANCE_MARK"
}
declare class XIDError extends Error {
  readonly code: XIDErrorCode;
  readonly cause?: Error;
  constructor(code: XIDErrorCode, message: string, cause?: Error);
  /**
   * Returned when attempting to add a duplicate item.
   */
  static duplicate(item: string): XIDError;
  /**
   * Returned when an item is not found.
   */
  static notFound(item: string): XIDError;
  /**
   * Returned when an item is still referenced by other items.
   */
  static stillReferenced(item: string): XIDError;
  /**
   * Returned when a value is invalid or empty.
   */
  static emptyValue(field: string): XIDError;
  /**
   * Returned when an unknown privilege is encountered.
   */
  static unknownPrivilege(): XIDError;
  /**
   * Returned when the XID is invalid.
   */
  static invalidXid(): XIDError;
  /**
   * Returned when the inception key is missing.
   */
  static missingInceptionKey(): XIDError;
  /**
   * Returned when the resolution method is invalid.
   */
  static invalidResolutionMethod(): XIDError;
  /**
   * Returned when multiple provenance marks are found.
   */
  static multipleProvenanceMarks(): XIDError;
  /**
   * Returned when an unexpected predicate is encountered.
   */
  static unexpectedPredicate(predicate: string): XIDError;
  /**
   * Returned when unexpected nested assertions are found.
   */
  static unexpectedNestedAssertions(): XIDError;
  /**
   * Returned when a service has no permissions.
   */
  static noPermissions(uri: string): XIDError;
  /**
   * Returned when a service has no key or delegate references.
   */
  static noReferences(uri: string): XIDError;
  /**
   * Returned when an unknown key reference is found in a service.
   */
  static unknownKeyReference(reference: string, uri: string): XIDError;
  /**
   * Returned when an unknown delegate reference is found in a service.
   */
  static unknownDelegateReference(reference: string, uri: string): XIDError;
  /**
   * Returned when a key is not found in the XID document.
   */
  static keyNotFoundInDocument(key: string): XIDError;
  /**
   * Returned when a delegate is not found in the XID document.
   */
  static delegateNotFoundInDocument(delegate: string): XIDError;
  /**
   * Returned when the password is invalid.
   */
  static invalidPassword(): XIDError;
  /**
   * Returned when the envelope is not signed.
   */
  static envelopeNotSigned(): XIDError;
  /**
   * Returned when signature verification fails.
   */
  static signatureVerificationFailed(): XIDError;
  /**
   * Returned when there is no provenance mark to advance.
   */
  static noProvenanceMark(): XIDError;
  /**
   * Returned when document already has generator but external generator was provided.
   */
  static generatorConflict(): XIDError;
  /**
   * Returned when document does not have generator but needs one.
   */
  static noGenerator(): XIDError;
  /**
   * Returned when generator chain ID doesn't match.
   */
  static chainIdMismatch(expected: Uint8Array, actual: Uint8Array): XIDError;
  /**
   * Returned when generator sequence doesn't match.
   */
  static sequenceMismatch(expected: number, actual: number): XIDError;
  /**
   * Envelope parsing error wrapper.
   */
  static envelopeParsing(cause?: Error): XIDError;
  /**
   * Component error wrapper.
   */
  static component(cause?: Error): XIDError;
  /**
   * CBOR error wrapper.
   */
  static cbor(cause?: Error): XIDError;
  /**
   * Provenance mark error wrapper.
   */
  static provenanceMark(cause?: Error): XIDError;
}
/**
 * Result type for XID operations.
 */
type XIDResult<T> = T;
//#endregion
//#region src/privilege.d.ts
/**
 * Enum representing XID privileges.
 */
declare enum Privilege {
  /** Allow all applicable XID operations */
  All = "All",
  /** Authenticate as the subject (e.g., log into services) */
  Auth = "Auth",
  /** Sign digital communications as the subject */
  Sign = "Sign",
  /** Encrypt messages from the subject */
  Encrypt = "Encrypt",
  /** Elide data under the subject's control */
  Elide = "Elide",
  /** Issue or revoke verifiable credentials on the subject's authority */
  Issue = "Issue",
  /** Access resources under the subject's control */
  Access = "Access",
  /** Delegate privileges to third parties */
  Delegate = "Delegate",
  /** Verify (update) the XID document */
  Verify = "Verify",
  /** Update service endpoints */
  Update = "Update",
  /** Remove the inception key from the XID document */
  Transfer = "Transfer",
  /** Add or remove other verifiers (rotate keys) */
  Elect = "Elect",
  /** Transition to a new provenance mark chain */
  Burn = "Burn",
  /** Revoke the XID entirely */
  Revoke = "Revoke"
}
/**
 * Convert a Privilege to its corresponding KnownValue.
 */
declare function privilegeToKnownValue(privilege: Privilege): KnownValue;
/**
 * Convert a KnownValue to its corresponding Privilege.
 */
declare function privilegeFromKnownValue(knownValue: KnownValue): Privilege;
/**
 * Convert a Privilege to an Envelope.
 */
declare function privilegeToEnvelope(privilege: Privilege): Envelope;
/**
 * Convert an Envelope to a Privilege.
 */
declare function privilegeFromEnvelope(envelope: Envelope): Privilege;
//#endregion
//#region src/permissions.d.ts
/**
 * Interface for types that have permissions.
 */
interface HasPermissions {
  /**
   * Get the permissions for this object.
   */
  permissions(): Permissions;
  /**
   * Get a mutable reference to the permissions.
   */
  permissionsMut(): Permissions;
}
/**
 * Helper methods for HasPermissions implementers.
 */
declare const HasPermissionsMixin: {
  /**
   * Get the set of allowed privileges.
   */
  allow(obj: HasPermissions): Set<Privilege>;
  /**
   * Get the set of denied privileges.
   */
  deny(obj: HasPermissions): Set<Privilege>;
  /**
   * Add an allowed privilege.
   */
  addAllow(obj: HasPermissions, privilege: Privilege): void;
  /**
   * Add a denied privilege.
   */
  addDeny(obj: HasPermissions, privilege: Privilege): void;
  /**
   * Remove an allowed privilege.
   */
  removeAllow(obj: HasPermissions, privilege: Privilege): void;
  /**
   * Remove a denied privilege.
   */
  removeDeny(obj: HasPermissions, privilege: Privilege): void;
  /**
   * Clear all permissions.
   */
  clearAllPermissions(obj: HasPermissions): void;
};
/**
 * Represents the permissions granted to a key or delegate.
 */
declare class Permissions implements HasPermissions {
  allow: Set<Privilege>;
  deny: Set<Privilege>;
  constructor(allow?: Set<Privilege>, deny?: Set<Privilege>);
  /**
   * Create a new empty Permissions object.
   */
  static new(): Permissions;
  /**
   * Create a new Permissions object that allows all privileges.
   */
  static newAllowAll(): Permissions;
  /**
   * Add permissions assertions to an envelope.
   */
  addToEnvelope(envelope: Envelope): Envelope;
  /**
   * Try to extract Permissions from an envelope.
   */
  static tryFromEnvelope(envelope: Envelope): Permissions;
  /**
   * Add an allowed privilege.
   */
  addAllow(privilege: Privilege): void;
  /**
   * Add a denied privilege.
   */
  addDeny(privilege: Privilege): void;
  /**
   * Check if a specific privilege is allowed.
   */
  isAllowed(privilege: Privilege): boolean;
  /**
   * Check if a specific privilege is denied.
   */
  isDenied(privilege: Privilege): boolean;
  permissions(): Permissions;
  permissionsMut(): Permissions;
  /**
   * Check equality with another Permissions object.
   */
  equals(other: Permissions): boolean;
  /**
   * Clone this Permissions object.
   */
  clone(): Permissions;
}
//#endregion
//#region src/name.d.ts
/**
 * Interface for types that have a nickname.
 */
interface HasNickname {
  /**
   * Get the nickname for this object.
   */
  nickname(): string;
  /**
   * Set the nickname for this object.
   */
  setNickname(name: string): void;
}
/**
 * Helper methods for HasNickname implementers.
 */
declare const HasNicknameMixin: {
  /**
   * Add a nickname, throwing if one already exists or is empty.
   */
  addNickname(obj: HasNickname, name: string): void;
};
//#endregion
//#region src/shared.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 *
 * Shared Reference Wrapper
 *
 * Provides a wrapper for shared references to objects.
 * In TypeScript, we don't have Arc/RwLock like Rust, but we can provide
 * a simple wrapper that allows shared access to a value.
 *
 * Ported from bc-xid-rust/src/shared.rs
 */
/**
 * A wrapper for shared references to objects.
 *
 * Unlike Rust's Arc<RwLock<T>>, JavaScript uses reference semantics for objects,
 * so this is primarily a type-safe wrapper that makes the sharing explicit.
 */
declare class Shared<T> {
  private readonly value;
  constructor(value: T);
  /**
   * Create a new Shared instance.
   */
  static new<T>(value: T): Shared<T>;
  /**
   * Get a read-only reference to the value.
   */
  read(): T;
  /**
   * Get a mutable reference to the value.
   */
  write(): T;
  /**
   * Check equality with another Shared instance.
   */
  equals(other: Shared<T>): boolean;
  /**
   * Clone this Shared instance.
   * Note: This creates a shallow copy in JS; for deep copy, implement on T.
   */
  clone(): Shared<T>;
}
//#endregion
//#region src/key.d.ts
/**
 * Options for handling private keys in envelopes.
 */
declare enum XIDPrivateKeyOptions {
  /** Omit the private key from the envelope (default). */
  Omit = "Omit",
  /** Include the private key in plaintext (with salt for decorrelation). */
  Include = "Include",
  /** Include the private key assertion but elide it (maintains digest tree). */
  Elide = "Elide",
  /** Include the private key encrypted with a password. */
  Encrypt = "Encrypt"
}
/**
 * Configuration for encrypting private keys.
 */
interface XIDPrivateKeyEncryptConfig {
  type: XIDPrivateKeyOptions.Encrypt;
  password: Uint8Array;
  method?: KeyDerivationMethod;
}
/**
 * Union type for all private key options.
 */
type XIDPrivateKeyOptionsValue = XIDPrivateKeyOptions.Omit | XIDPrivateKeyOptions.Include | XIDPrivateKeyOptions.Elide | XIDPrivateKeyEncryptConfig;
/**
 * Private key data that can be either decrypted or encrypted.
 */
type PrivateKeyData = {
  type: "decrypted";
  privateKeys: PrivateKeys;
} | {
  type: "encrypted";
  envelope: Envelope;
};
/**
 * Represents a key in an XID document.
 *
 * Mirrors `bc-xid-rust/src/key.rs`. The on-the-wire shape:
 *
 * ```
 * PublicKeys [
 *     {
 *         'privateKey': PrivateKeys     ← (or encrypted/elided)
 *     } [
 *         'salt': Salt
 *     ]
 *     'nickname': "..."
 *     'endpoint': URI(...)
 *     'allow': '...'
 * ]
 * ```
 *
 * Notably the private-key assertion is itself a node — the `'salt'`
 * lives nested under the assertion, not as a sibling on the parent
 * envelope. This is what `add_salt_instance(salt)` produces in Rust and
 * what `Envelope.prototype.addSaltInstance` produces in TS.
 */
declare class Key implements HasNickname, HasPermissions, EnvelopeEncodable, Verifier {
  private readonly _publicKeys;
  private readonly _privateKeyData;
  private _nickname;
  private readonly _endpoints;
  private readonly _permissions;
  private constructor();
  /**
   * Create a new Key with only public keys.
   */
  static new(publicKeys: PublicKeys): Key;
  /**
   * Create a new Key with public keys and allow-all permissions.
   */
  static newAllowAll(publicKeys: PublicKeys): Key;
  /**
   * Create a new Key with private keys.
   */
  static newWithPrivateKeys(privateKeys: PrivateKeys, publicKeys: PublicKeys): Key;
  /**
   * Create a new Key with private key base (derives keys from it).
   */
  static newWithPrivateKeyBase(privateKeyBase: PrivateKeyBase): Key;
  /**
   * Get the public keys.
   */
  publicKeys(): PublicKeys;
  /**
   * Get the private keys, if available and decrypted.
   */
  privateKeys(): PrivateKeys | undefined;
  /**
   * Check if this key has decrypted private keys.
   */
  hasPrivateKeys(): boolean;
  /**
   * Check if this key has encrypted private keys.
   */
  hasEncryptedPrivateKeys(): boolean;
  /**
   * Get the salt used for private key decorrelation.
   */
  privateKeySalt(): Salt | undefined;
  /**
   * Get the reference for this key (based on public keys tagged CBOR).
   */
  reference(): Reference;
  /**
   * Get the signing public key.
   */
  signingPublicKey(): SigningPublicKey;
  /**
   * Get the encapsulation public key.
   */
  encapsulationPublicKey(): EncapsulationPublicKey;
  /**
   * Verify a signature against a message.
   */
  verify(signature: Signature, message: Uint8Array): boolean;
  /**
   * Get the endpoints set. The set holds typed `URI` values (mirrors
   * Rust `HashSet<URI>`); use `.toString()` on a URI for a plain
   * string view.
   */
  endpoints(): Set<URI>;
  /**
   * Get the endpoints set for mutation.
   */
  endpointsMut(): Set<URI>;
  /**
   * Add an endpoint. Accepts either a URI value or a string (for
   * ergonomic test/REPL use). The URI is the canonical form.
   */
  addEndpoint(endpoint: URI | string): void;
  /**
   * Add a permission.
   */
  addPermission(privilege: Privilege): void;
  nickname(): string;
  setNickname(name: string): void;
  permissions(): Permissions;
  permissionsMut(): Permissions;
  /**
   * Build the nested salt-bearing assertion envelope:
   * ```
   * { 'privateKey': PrivateKeys } [ 'salt': Salt ]
   * ```
   * Mirrors Rust `Key::private_key_assertion_envelope()`.
   */
  private privateKeyAssertionEnvelope;
  /**
   * Convert to envelope with specified options.
   */
  intoEnvelopeOpt(privateKeyOptions?: XIDPrivateKeyOptionsValue): Envelope;
  intoEnvelope(): Envelope;
  /**
   * Try to extract a Key from an envelope, optionally with password for decryption.
   *
   * Mirrors Rust `Key::try_from_envelope` exactly:
   * - Subject must be a tagged-CBOR PublicKeys leaf.
   * - Optional private-key assertion follows the
   *   `{predicate: object} [ 'salt': Salt ]` shape.
   * - Endpoints are tagged URIs, not bare text.
   * - Missing salt under a present private-key assertion is an error.
   */
  static tryFromEnvelope(envelope: Envelope, password?: Uint8Array): Key;
  /**
   * Get the private key envelope, optionally decrypting it.
   *
   * Mirrors Rust `Key::private_key_envelope(password: Option<&[u8]>)`.
   * Password is bytes; the legacy `string` form is accepted as a
   * convenience for callers that have not yet migrated.
   */
  privateKeyEnvelope(password?: Uint8Array | string): Envelope | undefined;
  /**
   * Check equality with another Key.
   */
  equals(other: Key): boolean;
  /**
   * Get a hash key for use in Sets/Maps.
   */
  hashKey(): string;
  /**
   * Clone this Key.
   */
  clone(): Key;
}
//#endregion
//#region src/service.d.ts
/**
 * Represents a service endpoint in an XID document.
 */
declare class Service implements HasPermissions, EnvelopeEncodable {
  private readonly _uri;
  private _keyReferences;
  private _delegateReferences;
  private _permissions;
  private _capability;
  private _name;
  constructor(uri: URI | string);
  /**
   * Create a new Service with the given URI.
   */
  static new(uri: URI | string): Service;
  /**
   * Get the service URI as a typed value.
   */
  uri(): URI;
  /**
   * Get the service URI as a plain string.
   */
  uriString(): string;
  /**
   * Get the capability string.
   */
  capability(): string;
  /**
   * Set the capability string.
   */
  setCapability(capability: string): void;
  /**
   * Add a capability, throwing if one already exists or is empty.
   */
  addCapability(capability: string): void;
  /**
   * Get the key references as a Set of typed Reference values.
   */
  keyReferences(): Set<Reference>;
  /**
   * Get the underlying key-references Map for direct mutation.
   */
  keyReferencesMut(): Map<string, Reference>;
  /**
   * Add a key reference by hex string (back-compat alias).
   */
  addKeyReferenceHex(keyReferenceHex: string): void;
  /**
   * Add a key reference.
   */
  addKeyReference(keyReference: Reference): void;
  /**
   * Get the delegate references as a Set of typed Reference values.
   */
  delegateReferences(): Set<Reference>;
  /**
   * Get the underlying delegate-references Map for direct mutation.
   */
  delegateReferencesMut(): Map<string, Reference>;
  /**
   * Add a delegate reference by hex string (back-compat alias).
   */
  addDelegateReferenceHex(delegateReferenceHex: string): void;
  /**
   * Add a delegate reference.
   */
  addDelegateReference(delegateReference: Reference): void;
  /**
   * Add a key by its public keys provider (convenience method).
   * Matches Rust's `add_key(&mut self, key: &dyn PublicKeysProvider)`.
   */
  addKey(keyProvider: {
    publicKeys(): PublicKeys;
  }): void;
  /**
   * Add a delegate by its XID provider (convenience method).
   *
   * Mirrors Rust's `add_delegate(&mut self, delegate: &dyn XIDProvider)`,
   * which delegates to `xid.reference()` — i.e. the XID's 32 bytes used
   * directly as the Reference. The earlier port hashed the bytes with
   * SHA-256, producing a different reference that didn't round-trip
   * across implementations.
   */
  addDelegate(xidProvider: {
    xid(): XID$1;
  }): void;
  /**
   * Get the name.
   */
  name(): string;
  /**
   * Set the name, throwing if one already exists or is empty.
   */
  setName(name: string): void;
  permissions(): Permissions;
  permissionsMut(): Permissions;
  /**
   * Convert to envelope.
   */
  intoEnvelope(): Envelope;
  /**
   * Try to extract a Service from an envelope.
   *
   * Mirrors Rust `Service::try_from`:
   * - Subject must be a tagged-CBOR URI leaf.
   * - Each `'key'`/`'delegate'` object is a tagged Reference leaf.
   * - Nested assertions on any object are rejected.
   * - Unknown predicates are rejected.
   */
  static tryFromEnvelope(envelope: Envelope): Service;
  /**
   * Check equality with another Service (based on URI).
   */
  equals(other: Service): boolean;
  /**
   * Get a hash key for use in Sets/Maps.
   */
  hashKey(): string;
  /**
   * Clone this Service.
   */
  clone(): Service;
}
//#endregion
//#region src/delegate.d.ts
/**
 * Forward declaration interface for XIDDocument to avoid circular dependency.
 * The actual XIDDocument class implements this interface.
 */
interface XIDDocumentType {
  xid(): XID$1;
  intoEnvelope(): Envelope;
  clone(): XIDDocumentType;
}
/**
 * Register the XIDDocument class to avoid circular dependency issues.
 * Called by xid-document.ts when it loads.
 */
declare function registerXIDDocumentClass(cls: {
  tryFromEnvelope(envelope: Envelope): XIDDocumentType;
}): void;
/**
 * Represents a delegate in an XID document.
 */
declare class Delegate implements HasPermissions, EnvelopeEncodable {
  private readonly _controller;
  private readonly _permissions;
  private constructor();
  /**
   * Create a new Delegate with the given controller document.
   */
  static new(controller: XIDDocumentType): Delegate;
  /**
   * Get the controller document.
   */
  controller(): Shared<XIDDocumentType>;
  /**
   * Get the XID of the controller.
   */
  xid(): XID$1;
  /**
   * Get the reference for this delegate.
   *
   * Mirrors Rust `impl ReferenceProvider for Delegate`, which delegates
   * to `self.controller.read().xid().reference()` — i.e. the XID's
   * 32 bytes used directly as the Reference. The previous TS port
   * SHA-256-hashed the XID bytes, producing a different reference
   * value that did not round-trip across implementations.
   */
  reference(): Reference;
  permissions(): Permissions;
  permissionsMut(): Permissions;
  /**
   * Convert to envelope.
   */
  intoEnvelope(): Envelope;
  /**
   * Try to extract a Delegate from an envelope.
   */
  static tryFromEnvelope(envelope: Envelope): Delegate;
  /**
   * Check equality with another Delegate (based on controller XID).
   */
  equals(other: Delegate): boolean;
  /**
   * Get a hash key for use in Sets/Maps.
   */
  hashKey(): string;
  /**
   * Clone this Delegate.
   */
  clone(): Delegate;
}
//#endregion
//#region src/provenance.d.ts
/**
 * Options for handling generators in envelopes.
 */
declare enum XIDGeneratorOptions {
  /** Omit the generator from the envelope (default). */
  Omit = "Omit",
  /** Include the generator in plaintext (with salt for decorrelation). */
  Include = "Include",
  /** Include the generator assertion but elide it (maintains digest tree). */
  Elide = "Elide",
  /** Include the generator encrypted with a password. */
  Encrypt = "Encrypt"
}
/**
 * Configuration for encrypting generators.
 */
interface XIDGeneratorEncryptConfig {
  type: XIDGeneratorOptions.Encrypt;
  password: Uint8Array;
  method?: KeyDerivationMethod;
}
/**
 * Union type for all generator options.
 */
type XIDGeneratorOptionsValue = XIDGeneratorOptions.Omit | XIDGeneratorOptions.Include | XIDGeneratorOptions.Elide | XIDGeneratorEncryptConfig;
/**
 * Generator data that can be either decrypted or encrypted.
 */
type GeneratorData = {
  type: "decrypted";
  generator: ProvenanceMarkGenerator;
} | {
  type: "encrypted";
  envelope: Envelope;
};
/**
 * Represents provenance information in an XID document.
 */
declare class Provenance implements EnvelopeEncodable {
  private _mark;
  private _generator;
  private constructor();
  /**
   * Create a new Provenance with just a mark.
   */
  static new(mark: ProvenanceMark): Provenance;
  /**
   * Create a new Provenance with a generator and mark.
   */
  static newWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): Provenance;
  /**
   * Get the provenance mark.
   */
  mark(): ProvenanceMark;
  /**
   * Get the generator, if available and decrypted.
   */
  generator(): ProvenanceMarkGenerator | undefined;
  /**
   * Check if this provenance has a decrypted generator.
   */
  hasGenerator(): boolean;
  /**
   * Check if this provenance has an encrypted generator.
   */
  hasEncryptedGenerator(): boolean;
  /**
   * Get the salt used for generator decorrelation.
   */
  generatorSalt(): Salt | undefined;
  /**
   * Update the provenance mark.
   */
  setMark(mark: ProvenanceMark): void;
  /**
   * Set or replace the generator.
   */
  setGenerator(generator: ProvenanceMarkGenerator): void;
  /**
   * Take and remove the generator.
   */
  takeGenerator(): {
    data: GeneratorData;
    salt: Salt;
  } | undefined;
  /**
   * Get a mutable reference to the generator, decrypting if necessary.
   */
  generatorMut(password?: Uint8Array): ProvenanceMarkGenerator | undefined;
  /**
   * Build the salted assertion envelope:
   * ```
   * { 'provenanceGenerator': <generator> } [ 'salt': Salt ]
   * ```
   * Mirrors Rust `Provenance::generator_assertion_envelope()`.
   */
  private generatorAssertionEnvelope;
  /**
   * Get the generator envelope, optionally decrypting it.
   *
   * Mirrors Rust `Provenance::generator_envelope(password)`. The
   * unencrypted variant returns the same structured envelope produced
   * by `ProvenanceMarkGenerator::into_envelope()` — never the legacy
   * JSON-bytes form.
   */
  generatorEnvelope(password?: Uint8Array | string): Envelope | undefined;
  /**
   * Convert to envelope with specified options.
   */
  intoEnvelopeOpt(generatorOptions?: XIDGeneratorOptionsValue): Envelope;
  intoEnvelope(): Envelope;
  /**
   * Try to extract a Provenance from an envelope, optionally with password for decryption.
   *
   * Mirrors Rust `Provenance::try_from_envelope`:
   * - Subject is a tagged-CBOR ProvenanceMark leaf.
   * - The optional generator assertion follows the
   *   `{ predicate: object } [ 'salt': Salt ]` shape.
   * - Missing salt under a present generator assertion is an error.
   */
  static tryFromEnvelope(envelope: Envelope, password?: Uint8Array): Provenance;
  /**
   * Check equality with another Provenance.
   */
  equals(other: Provenance): boolean;
  /**
   * Clone this Provenance.
   * Note: ProvenanceMark is immutable so we can use the same instance.
   */
  clone(): Provenance;
}
//#endregion
//#region src/xid-document.d.ts
/**
 * Options for creating the inception key.
 */
type XIDInceptionKeyOptions = {
  type: "default";
} | {
  type: "publicKeys";
  publicKeys: PublicKeys;
} | {
  type: "privateKeyBase";
  privateKeyBase: PrivateKeyBase;
} | {
  type: "privateKeys";
  privateKeys: PrivateKeys;
  publicKeys: PublicKeys;
};
/**
 * Options for creating the genesis mark.
 */
type XIDGenesisMarkOptions = {
  type: "none";
} | {
  type: "passphrase";
  passphrase: string;
  resolution?: ProvenanceMarkResolution;
  date?: Date;
  info?: Cbor;
} | {
  type: "seed";
  seed: Uint8Array;
  resolution?: ProvenanceMarkResolution;
  date?: Date;
  info?: Cbor;
};
/**
 * Options for signing an envelope.
 */
type XIDSigningOptions = {
  type: "none";
} | {
  type: "inception";
} | {
  type: "privateKeys";
  privateKeys: PrivateKeys;
} | {
  type: "signingPrivateKey";
  signingPrivateKey: SigningPrivateKey;
};
/**
 * Options for verifying the signature on an envelope when loading.
 */
declare enum XIDVerifySignature {
  /** Do not verify the signature (default). */
  None = "None",
  /** Verify that the envelope is signed with the inception key. */
  Inception = "Inception"
}
/**
 * Represents an XID document.
 */
declare class XIDDocument implements EnvelopeEncodable, Edgeable$1 {
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
   * Create a new XIDDocument with the given options.
   */
  static new(keyOptions?: XIDInceptionKeyOptions, markOptions?: XIDGenesisMarkOptions): XIDDocument;
  private static inceptionKeyForOptions;
  private static genesisMarkWithOptions;
  /**
   * Create an XIDDocument from just an XID.
   */
  static fromXid(xid: XID$1): XIDDocument;
  /**
   * Get the XID.
   */
  xid(): XID$1;
  /**
   * Get the resolution methods as a Set of typed URI values.
   *
   * Mirrors Rust `&HashSet<URI>`. Use `.toString()` on a URI for the
   * plain-string form.
   */
  resolutionMethods(): Set<URI>;
  /**
   * Add a resolution method. Accepts either a typed URI value or a
   * string (the latter is converted via `URI.from`).
   */
  addResolutionMethod(method: URI | string): void;
  /**
   * Remove a resolution method.
   */
  removeResolutionMethod(method: URI | string): boolean;
  /**
   * Get all keys.
   */
  keys(): Key[];
  /**
   * Add a key.
   */
  addKey(key: Key): void;
  /**
   * Find a key by its public keys.
   */
  findKeyByPublicKeys(publicKeys: PublicKeys): Key | undefined;
  /**
   * Find a key by its reference.
   */
  findKeyByReference(reference: Reference): Key | undefined;
  /**
   * Take and remove a key.
   */
  takeKey(publicKeys: PublicKeys): Key | undefined;
  /**
   * Remove a key.
   */
  removeKey(publicKeys: PublicKeys): void;
  /**
   * Check if the given signing public key is the inception signing key.
   * Matches Rust: `is_inception_signing_key(&self, signing_public_key: &SigningPublicKey) -> bool`
   */
  isInceptionSigningKey(signingPublicKey: SigningPublicKey): boolean;
  /**
   * Get the inception key, if it exists in the document.
   */
  inceptionKey(): Key | undefined;
  /**
   * Get the inception private keys, if available.
   */
  inceptionPrivateKeys(): PrivateKeys | undefined;
  /**
   * Get the encryption key (encapsulation public key) for this document.
   *
   * Prefers the inception key for encryption. If no inception key is available,
   * falls back to the first key in the document.
   */
  encryptionKey(): EncapsulationPublicKey | undefined;
  /**
   * Remove the inception key from the document.
   */
  removeInceptionKey(): Key | undefined;
  /**
   * Set the name (nickname) for a key identified by its public keys.
   */
  setNameForKey(publicKeys: PublicKeys, name: string): void;
  /**
   * Get the inception signing public key, if it exists.
   */
  inceptionSigningKey(): SigningPublicKey | undefined;
  /**
   * Get the verification (signing) key for this document.
   * Prefers the inception key. Falls back to the first key.
   */
  verificationKey(): SigningPublicKey | undefined;
  /**
   * Extract inception private keys from an envelope (convenience static method).
   */
  static extractInceptionPrivateKeysFromEnvelope(envelope: Envelope, password: Uint8Array): PrivateKeys | undefined;
  /**
   * Get the private key envelope for a specific key, optionally decrypting it.
   */
  privateKeyEnvelopeForKey(publicKeys: PublicKeys, password?: string): Envelope | undefined;
  /**
   * Check that the document contains a key with the given public keys.
   * Throws if not found.
   */
  checkContainsKey(publicKeys: PublicKeys): void;
  /**
   * Check that the document contains a delegate with the given XID.
   * Throws if not found.
   */
  checkContainsDelegate(xid: XID$1): void;
  /**
   * Get the attachments container.
   */
  getAttachments(): Attachments$1;
  /**
   * Add an attachment with the specified payload and metadata.
   */
  addAttachment(payload: EnvelopeEncodableValue, vendor: string, conformsTo?: string): void;
  /**
   * Check if the document has any attachments.
   */
  hasAttachments(): boolean;
  /**
   * Remove all attachments.
   */
  clearAttachments(): void;
  /**
   * Get an attachment by its digest.
   */
  getAttachment(digest: Digest): Envelope | undefined;
  /**
   * Remove an attachment by its digest.
   */
  removeAttachment(digest: Digest): Envelope | undefined;
  /**
   * Get the edges container (read-only).
   */
  edges(): Edges$1;
  /**
   * Get the edges container (mutable).
   */
  edgesMut(): Edges$1;
  /**
   * Add an edge envelope.
   */
  addEdge(edgeEnvelope: Envelope): void;
  /**
   * Get an edge by its digest.
   */
  getEdge(digest: Digest): Envelope | undefined;
  /**
   * Remove an edge by its digest.
   */
  removeEdge(digest: Digest): Envelope | undefined;
  /**
   * Remove all edges.
   */
  clearEdges(): void;
  /**
   * Check if the document has any edges.
   */
  hasEdges(): boolean;
  /**
   * Check if the document is empty: no resolution methods, keys, delegates,
   * services, provenance, attachments, edges, or extension assertions.
   *
   * Mirrors Rust `XIDDocument::is_empty`.
   */
  isEmpty(): boolean;
  /**
   * Get the preserved extension assertions — top-level assertions that are
   * not recognized as XID document fields and round-trip unchanged.
   *
   * Mirrors Rust `XIDDocument::extra_assertions(&self) -> &[Envelope]`.
   */
  extraAssertions(): Envelope[];
  /**
   * Get all delegates.
   */
  delegates(): Delegate[];
  /**
   * Add a delegate.
   */
  addDelegate(delegate: Delegate): void;
  /**
   * Find a delegate by XID.
   */
  findDelegateByXid(xid: XID$1): Delegate | undefined;
  /**
   * Find a delegate by reference.
   */
  findDelegateByReference(reference: Reference): Delegate | undefined;
  /**
   * Take and remove a delegate.
   */
  takeDelegate(xid: XID$1): Delegate | undefined;
  /**
   * Remove a delegate.
   */
  removeDelegate(xid: XID$1): void;
  /**
   * Get all services.
   */
  services(): Service[];
  /**
   * Find a service by URI.
   */
  findServiceByUri(uri: string): Service | undefined;
  /**
   * Add a service.
   */
  addService(service: Service): void;
  /**
   * Take and remove a service.
   */
  takeService(uri: string): Service | undefined;
  /**
   * Remove a service.
   */
  removeService(uri: string): void;
  /**
   * Check service consistency.
   */
  checkServicesConsistency(): void;
  /**
   * Check consistency of a single service.
   */
  checkServiceConsistency(service: Service): void;
  /**
   * Check if any service references the given key.
   */
  servicesReferenceKey(publicKeys: PublicKeys): boolean;
  /**
   * Check if any service references the given delegate.
   *
   * Mirrors Rust `services_reference_delegate(xid)` which uses
   * `xid.reference()` — the XID bytes used directly as the
   * Reference (no SHA-256 wrap), the same value used by
   * `Service::add_delegate(...)` on the producer side.
   */
  servicesReferenceDelegate(xid: XID$1): boolean;
  /**
   * Get the provenance mark.
   */
  provenance(): ProvenanceMark | undefined;
  /**
   * Get the provenance generator.
   */
  provenanceGenerator(): ProvenanceMarkGenerator | undefined;
  /**
   * Set the provenance.
   */
  setProvenance(provenance: ProvenanceMark | undefined): void;
  /**
   * Set provenance with generator.
   */
  setProvenanceWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): void;
  /**
   * Advance the provenance mark using the embedded generator.
   */
  nextProvenanceMarkWithEmbeddedGenerator(password?: Uint8Array, date?: Date, info?: Cbor): void;
  /**
   * Advance the provenance mark using a provided generator.
   */
  nextProvenanceMarkWithProvidedGenerator(generator: ProvenanceMarkGenerator, date?: Date, info?: Cbor): void;
  /**
   * Convert to envelope with options.
   */
  toEnvelope(privateKeyOptions?: XIDPrivateKeyOptionsValue, generatorOptions?: XIDGeneratorOptionsValue, signingOptions?: XIDSigningOptions): Envelope;
  intoEnvelope(): Envelope;
  /**
   * Returns the untagged CBOR encoding for this document.
   *
   * Mirrors Rust `CBORTaggedEncodable for XIDDocument::untagged_cbor`:
   * empty docs serialize as the raw 32-byte XID byte string; non-empty
   * docs serialize as the envelope's tagged CBOR (tag 200).
   */
  untaggedCbor(): Cbor;
  /**
   * Returns the UR for this document.
   *
   * UR type is `xid` (matching `TAG_XID.name` and Rust). Body bytes are
   * `untaggedCbor()`.
   */
  ur(): UR;
  /**
   * Returns the `ur:xid/...` string representation of this document.
   *
   * Mirrors Rust `xid_document.ur_string()`. Round-trip with
   * {@link XIDDocument.fromURString} is byte-identical to Rust.
   */
  urString(): string;
  /**
   * Decode an XIDDocument from a UR.
   *
   * Mirrors Rust `CBORTaggedDecodable::from_untagged_cbor`:
   *   - if the body is a CBOR byte string (32 bytes), it's an empty
   *     XIDDocument carrying just the XID;
   *   - otherwise it's an envelope's tagged CBOR (tag 200), which we
   *     decode and feed through `fromEnvelope`.
   */
  static fromUR(ur: UR): XIDDocument;
  /**
   * Decode an XIDDocument from a `ur:xid/...` string.
   */
  static fromURString(urString: string): XIDDocument;
  /**
   * Decode an XIDDocument from untagged CBOR (the UR-body form).
   */
  static fromUntaggedCbor(cbor: Cbor): XIDDocument;
  /**
   * Extract an XIDDocument from an envelope.
   */
  static fromEnvelope(envelope: Envelope, password?: Uint8Array, verifySignature?: XIDVerifySignature): XIDDocument;
  private static fromEnvelopeInner;
  /**
   * Create a signed envelope.
   */
  toSignedEnvelope(signingKey: Signer): Envelope;
  /**
   * Create a signed envelope with private key options.
   */
  toSignedEnvelopeOpt(signingKey: Signer, privateKeyOptions?: XIDPrivateKeyOptionsValue): Envelope;
  /**
   * Get the reference for this document.
   *
   * Mirrors Rust `impl ReferenceProvider for XIDDocument` ↔
   * `XID::reference` which is `Reference::from_data(*self.data())` —
   * the XID's bytes used directly. The previous TS implementation
   * SHA-256-hashed the bytes, producing a different reference value.
   */
  reference(): Reference;
  /**
   * Check equality with another XIDDocument.
   */
  equals(other: XIDDocument): boolean;
  /**
   * Clone this XIDDocument.
   */
  clone(): XIDDocument;
  /**
   * Try to extract from envelope (alias for fromEnvelope with default options).
   */
  static tryFromEnvelope(envelope: Envelope): XIDDocument;
}
//#endregion
//#region src/index.d.ts
declare const VERSION = "1.0.0-alpha.3";
//#endregion
export { Attachments, Delegate, type Edgeable, Edges, type GeneratorData, type HasNickname, HasNicknameMixin, type HasPermissions, HasPermissionsMixin, Key, Permissions, type PrivateKeyData, Privilege, Provenance, Service, Shared, VERSION, XID, XIDDocument, type XIDDocumentType, XIDError, XIDErrorCode, type XIDGeneratorEncryptConfig, XIDGeneratorOptions, type XIDGeneratorOptionsValue, type XIDGenesisMarkOptions, type XIDInceptionKeyOptions, type XIDPrivateKeyEncryptConfig, XIDPrivateKeyOptions, type XIDPrivateKeyOptionsValue, type XIDResult, type XIDSigningOptions, XIDVerifySignature, privilegeFromEnvelope, privilegeFromKnownValue, privilegeToEnvelope, privilegeToKnownValue, registerXIDDocumentClass };
//# sourceMappingURL=index.d.mts.map