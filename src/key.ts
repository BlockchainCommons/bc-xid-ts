/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A key a XID document carries: its public keys, optionally its private
 * keys (in the clear or password-locked), a nickname, endpoints and
 * permissions.
 */

import { expectText } from "@blockchaincommons/dcbor";
import { Envelope, type EnvelopeInput } from "@blockchaincommons/envelope";
import {
  lockSubject,
  unlockSubject,
  isLockedWithPassword,
} from "@blockchaincommons/envelope/secret";
import { ENDPOINT, NICKNAME, PRIVATE_KEY, SALT } from "@blockchaincommons/known-values";
import {
  Salt,
  URI,
  type Reference,
  PublicKeys,
  PrivateKeys,
  type PrivateKeyBase,
  type SigningPublicKey,
  type EncapsulationPublicKey,
  type Verifier,
  type Signature,
} from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";

import { Permissions, type HasPermissions } from "./permissions";
import { type Privilege } from "./privilege";
import { XIDError } from "./error";
import {
  expectOneOf,
  extractObjectForPredicate,
  extractObjectForPredicateOr,
  guarded,
  leafAs,
  rejectNull,
} from "./domain";

/**
 * How a key's private keys go into an envelope: left out, included (with
 * a salt), elided (the digest of the included form), or locked with a
 * password (Argon2id unless `method` says otherwise).
 */
export type XIDPrivateKeyOptions = "omit" | "include" | "elide" | EncryptOptions;

/** The password-locked form of private keys or a generator. */
export interface EncryptOptions {
  /** The password, as text or bytes. */
  encrypt: Uint8Array | string;
  /** The key derivation method; Argon2id unless given. */
  method?: KeyDerivationMethod | undefined;
}

/** The private keys as held: in the clear, or the locked envelope as parsed. */
type PrivateKeyData =
  { type: "decrypted"; privateKeys: PrivateKeys } | { type: "encrypted"; envelope: Envelope };

/** What `Key.from` takes besides the public keys. */
export interface KeyInput {
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
export interface PasswordOptions {
  /** The password; absent means "leave locked material locked". */
  password?: Uint8Array | string | undefined;
}

/** What `Key.toEnvelope` takes. */
export interface KeyEnvelopeOptions {
  /** How the private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
}

/** @internal */
export const passwordBytes = (password: Uint8Array | string): Uint8Array =>
  typeof password === "string" ? new TextEncoder().encode(password) : password;

/** Locked envelopes compare by their bytes, as the reference compares their UR strings. @internal */
export const envelopeBytesEqual = (a: Envelope, b: Envelope): boolean => {
  const x = a.toCbor().toData();
  const y = b.toCbor().toData();
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
};

const privateKeyDataEquals = (
  a: { data: PrivateKeyData; salt: Salt } | undefined,
  b: { data: PrivateKeyData; salt: Salt } | undefined,
): boolean => {
  if (a === undefined || b === undefined) return a === b;
  if (!a.salt.equals(b.salt)) return false;
  if (a.data.type === "decrypted" && b.data.type === "decrypted") {
    return a.data.privateKeys.equals(b.data.privateKeys);
  }
  if (a.data.type === "encrypted" && b.data.type === "encrypted") {
    return envelopeBytesEqual(a.data.envelope, b.data.envelope);
  }
  return false;
};

/** @internal */
export const kdfOf = (o: { method?: KeyDerivationMethod | undefined }): KeyDerivationMethod =>
  o.method ?? KeyDerivationMethod.Argon2id;

const PRIVATE_KEY_OPTION_NAMES = ["omit", "include", "elide"] as const;

/** A private-key option, checked: one of the three names or an `encrypt` object. @internal */
export function expectPrivateKeyOptions(value: unknown, name: string): XIDPrivateKeyOptions {
  if (typeof value === "object" && value !== null && "encrypt" in value) {
    return value as XIDPrivateKeyOptions;
  }
  return expectOneOf(value, PRIVATE_KEY_OPTION_NAMES, name);
}

/**
 * A key of a XID document: public keys, optionally private keys (in the
 * clear or password-locked), a nickname, endpoints and permissions.
 */
export class Key implements HasPermissions, Verifier {
  private readonly _publicKeys: PublicKeys;
  private readonly _privateKeyData: { data: PrivateKeyData; salt: Salt } | undefined;
  private _nickname: string;
  private readonly _endpoints: Map<string, URI>;
  private readonly _permissions: Permissions;

  private constructor(
    publicKeys: PublicKeys,
    privateKeyData: { data: PrivateKeyData; salt: Salt } | undefined,
    nickname: string,
    endpoints: Map<string, URI>,
    permissions: Permissions,
  ) {
    this._publicKeys = publicKeys;
    this._privateKeyData = privateKeyData;
    this._nickname = nickname;
    this._endpoints = endpoints;
    this._permissions = permissions;
  }

  /**
   * A key from its public keys; no permissions unless private keys or
   * `permissions` are given. A `null` `privateKeys` is a `TypeError`:
   * absent private keys are `undefined`.
   */
  static from(
    publicKeys: PublicKeys,
    { privateKeys, nickname = "", endpoints, permissions }: KeyInput = {},
  ): Key {
    rejectNull(privateKeys, "privateKeys");
    const data =
      privateKeys === undefined
        ? undefined
        : { data: { type: "decrypted" as const, privateKeys }, salt: Salt.random({ length: 32 }) };
    const key = new Key(
      publicKeys,
      data,
      nickname,
      new Map(),
      permissions ?? (privateKeys === undefined ? Permissions.from() : Permissions.allowAll()),
    );
    for (const e of endpoints ?? []) key.addEndpoint(e);
    return key;
  }

  /** A public key allowed `All`. */
  static allowAll(publicKeys: PublicKeys): Key {
    return new Key(publicKeys, undefined, "", new Map(), Permissions.allowAll());
  }

  /** The Schnorr and X25519 keys of a base, private keys included, allowed `All`. */
  static fromPrivateKeyBase(privateKeyBase: PrivateKeyBase): Key {
    return Key.from(privateKeyBase.schnorrPublicKeys(), {
      privateKeys: privateKeyBase.schnorrPrivateKeys(),
    });
  }

  /** The public keys. */
  get publicKeys(): PublicKeys {
    return this._publicKeys;
  }

  /** The private keys when held in the clear. */
  get privateKeys(): PrivateKeys | undefined {
    return this._privateKeyData?.data.type === "decrypted"
      ? this._privateKeyData.data.privateKeys
      : undefined;
  }

  /** Whether the private keys are held in the clear. */
  get hasPrivateKeys(): boolean {
    return this._privateKeyData?.data.type === "decrypted";
  }

  /** Whether the private keys are held locked (parsed without the password). */
  get hasEncryptedPrivateKeys(): boolean {
    return this._privateKeyData?.data.type === "encrypted";
  }

  /** The salt the `'privateKey'` assertion carries. */
  get privateKeySalt(): Salt | undefined {
    return this._privateKeyData?.salt;
  }

  /** The reference of the public keys. */
  get reference(): Reference {
    return this._publicKeys.reference();
  }

  /** The signing public key. */
  get signingPublicKey(): SigningPublicKey {
    return this._publicKeys.signingPublicKey;
  }

  /** The encapsulation public key. */
  encapsulationPublicKey(): EncapsulationPublicKey {
    return this._publicKeys.encapsulationPublicKey();
  }

  /** Whether `signature` is the public keys' signature of `message`. */
  verify(signature: Signature, message: Uint8Array): boolean {
    return this._publicKeys.verify(signature, message);
  }

  /** The endpoints (a copy). */
  get endpoints(): ReadonlySet<URI> {
    return new Set(this._endpoints.values());
  }

  /** Adds an endpoint, as a URI or its text (a components error for text that is not a URI). */
  addEndpoint(endpoint: URI | string): void {
    const uri = endpoint instanceof URI ? endpoint : URI.from(endpoint);
    this._endpoints.set(uri.toString(), uri);
  }

  /** The nickname; empty when there is none. */
  get nickname(): string {
    return this._nickname;
  }

  /** Sets (or clears, with `""`) the nickname. */
  setNickname(name: string): void {
    this._nickname = name;
  }

  /** Sets the nickname once: `Duplicate` when set, `EmptyValue` when empty. */
  addNickname(name: string): void {
    if (this._nickname !== "") throw XIDError.duplicate("nickname");
    if (name === "") throw XIDError.emptyValue("nickname");
    this._nickname = name;
  }

  /** The permissions (live). */
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

  private privateKeyAssertionEnvelope(): Envelope {
    if (this._privateKeyData === undefined) {
      throw new Error("privateKeyAssertionEnvelope called with no private key data");
    }
    const { data, salt } = this._privateKeyData;
    const object: EnvelopeInput = data.type === "decrypted" ? data.privateKeys : data.envelope;
    return Envelope.assertion(PRIVATE_KEY, object).addSalt({ salt });
  }

  /**
   * The public keys as the subject, the private keys per `privateKeys`
   * (a locked key stays locked), then `'nickname'`, `'endpoint'`s and
   * the permissions. An unknown option is a `TypeError`.
   */
  toEnvelope({ privateKeys = "omit" }: KeyEnvelopeOptions = {}): Envelope {
    const option = expectPrivateKeyOptions(privateKeys, "privateKeys");
    let envelope = Envelope.from(this._publicKeys);
    if (this._privateKeyData !== undefined) {
      const { data, salt } = this._privateKeyData;
      if (data.type === "encrypted") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope());
      } else if (option === "include") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope());
      } else if (option === "elide") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope().elide());
      } else if (typeof option === "object") {
        const locked = lockSubject(
          Envelope.from(data.privateKeys),
          kdfOf(option),
          passwordBytes(option.encrypt),
        );
        envelope = envelope.addAssertionEnvelope(
          Envelope.assertion(PRIVATE_KEY, locked).addSalt({ salt }),
        );
      }
    }
    if (this._nickname !== "") envelope = envelope.addAssertion(NICKNAME, this._nickname);
    for (const endpoint of this._endpoints.values()) {
      envelope = envelope.addAssertion(ENDPOINT, endpoint);
    }
    return this._permissions.addToEnvelope(envelope);
  }

  /**
   * A key from its envelope. A locked `'privateKey'` is unlocked with the
   * password when one is given and it fits; otherwise it is kept locked.
   * Every failure is an `XIDError`: a subject or leaf of the wrong type
   * is `Cbor`; a missing or repeated `'salt'`, a second `'nickname'` or
   * one that is not text are `EnvelopeParsing`; a permission that is not
   * a known value is `EnvelopeParsing`, one that names no privilege is
   * `UnknownPrivilege`.
   */
  static fromEnvelope(envelope: Envelope, { password }: PasswordOptions = {}): Key {
    const publicKeys = leafAs(envelope.subject(), (c) => PublicKeys.fromCbor(c));
    const privateKeyData = Key.privateKeyDataOf(envelope, password);
    const nickname = extractObjectForPredicateOr(envelope, NICKNAME, expectText, "");
    const endpoints = new Map<string, URI>();
    for (const assertion of envelope.assertionsWithPredicate(ENDPOINT)) {
      const object = guarded(() => assertion.expectObject().subject());
      const uri = leafAs(object, (c) => URI.fromCbor(c));
      endpoints.set(uri.toString(), uri);
    }
    return new Key(
      publicKeys,
      privateKeyData,
      nickname,
      endpoints,
      Permissions.fromEnvelope(envelope),
    );
  }

  private static privateKeyDataOf(
    envelope: Envelope,
    password: Uint8Array | string | undefined,
  ): { data: PrivateKeyData; salt: Salt } | undefined {
    const privateKeyAssertion = guarded(() => envelope.optionalAssertionWithPredicate(PRIVATE_KEY));
    if (privateKeyAssertion === undefined) return undefined;
    const privateKeyObject = guarded(() => privateKeyAssertion.subject().expectObject());
    const salt = extractObjectForPredicate(privateKeyAssertion, SALT, (c) => Salt.fromCbor(c));
    if (isLockedWithPassword(privateKeyObject)) {
      if (password === undefined) {
        return { data: { type: "encrypted", envelope: privateKeyObject }, salt };
      }
      let decrypted: Envelope;
      try {
        decrypted = unlockSubject(privateKeyObject, passwordBytes(password));
      } catch {
        // A wrong password leaves the keys locked.
        return { data: { type: "encrypted", envelope: privateKeyObject }, salt };
      }
      const privateKeys = leafAs(decrypted.subject(), (c) => PrivateKeys.fromCbor(c));
      return { data: { type: "decrypted", privateKeys }, salt };
    }
    const privateKeys = leafAs(privateKeyObject, (c) => PrivateKeys.fromCbor(c));
    return { data: { type: "decrypted", privateKeys }, salt };
  }

  /**
   * The private keys as an envelope: in the clear when held so, unlocked
   * with the password when locked (an `InvalidPassword` error when it
   * does not fit), or the locked envelope itself without a password.
   */
  privateKeyEnvelope({ password }: PasswordOptions = {}): Envelope | undefined {
    if (this._privateKeyData === undefined) return undefined;
    const { data } = this._privateKeyData;
    if (data.type === "decrypted") return Envelope.from(data.privateKeys);
    if (password === undefined) return data.envelope;
    try {
      return unlockSubject(data.envelope, passwordBytes(password));
    } catch {
      throw XIDError.invalidPassword();
    }
  }

  /**
   * Same public keys, private material (in the clear or locked, with its
   * salt), nickname, endpoints and permissions — as the reference's
   * equality; a key parsed from an envelope that omitted its private
   * keys is not equal to the original.
   */
  equals(other: Key): boolean {
    if (!this._publicKeys.equals(other._publicKeys)) return false;
    if (!privateKeyDataEquals(this._privateKeyData, other._privateKeyData)) return false;
    if (this._nickname !== other._nickname) return false;
    if (this._endpoints.size !== other._endpoints.size) return false;
    for (const k of this._endpoints.keys()) if (!other._endpoints.has(k)) return false;
    return this._permissions.equals(other._permissions);
  }

  /** A copy: the private material shared, the endpoints and permissions copied. */
  clone(): Key {
    return new Key(
      this._publicKeys,
      this._privateKeyData === undefined
        ? undefined
        : { data: this._privateKeyData.data, salt: this._privateKeyData.salt },
      this._nickname,
      new Map(this._endpoints),
      this._permissions.clone(),
    );
  }
}
