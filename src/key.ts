/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A key a XID document carries: its public keys, optionally its private
 * keys (in the clear or password-locked), a nickname, endpoints and
 * permissions.
 */

// Ported from bc-xid-rust/src/key.rs

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

/**
 * How a key's private keys go into an envelope: left out, included (with
 * a salt), elided (the digest of the included form), or locked with a
 * password (Argon2id unless `method` says otherwise).
 */
export type XIDPrivateKeyOptions =
  | "omit"
  | "include"
  | "elide"
  | { encrypt: Uint8Array | string; method?: KeyDerivationMethod | undefined };

/** Private keys as held: decrypted, or the locked envelope as parsed. */
export type PrivateKeyData =
  { type: "decrypted"; privateKeys: PrivateKeys } | { type: "encrypted"; envelope: Envelope };

/** What `Key.from` takes besides the public keys. */
export interface KeyInput {
  /** With private keys the key is allowed `All` unless `permissions` says otherwise. */
  privateKeys?: PrivateKeys | undefined;
  nickname?: string | undefined;
  endpoints?: Iterable<URI | string> | undefined;
  permissions?: Permissions | undefined;
}

export interface PasswordOptions {
  password?: Uint8Array | string | undefined;
}

export interface KeyEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
}

export const passwordBytes = (password: Uint8Array | string): Uint8Array =>
  typeof password === "string" ? new TextEncoder().encode(password) : password;

/** Locked envelopes compare by their bytes, as the reference compares their UR strings. */
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

export const kdfOf = (o: { method?: KeyDerivationMethod | undefined }): KeyDerivationMethod =>
  o.method ?? KeyDerivationMethod.Argon2id;

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

  /** A key from its public keys; no permissions unless private keys or `permissions` are given. */
  static from(
    publicKeys: PublicKeys,
    { privateKeys, nickname = "", endpoints, permissions }: KeyInput = {},
  ): Key {
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

  get publicKeys(): PublicKeys {
    return this._publicKeys;
  }

  /** The private keys when held in the clear. */
  get privateKeys(): PrivateKeys | undefined {
    return this._privateKeyData?.data.type === "decrypted"
      ? this._privateKeyData.data.privateKeys
      : undefined;
  }

  get hasPrivateKeys(): boolean {
    return this._privateKeyData?.data.type === "decrypted";
  }

  get hasEncryptedPrivateKeys(): boolean {
    return this._privateKeyData?.data.type === "encrypted";
  }

  /** The salt the `'privateKey'` assertion carries. */
  get privateKeySalt(): Salt | undefined {
    return this._privateKeyData?.salt;
  }

  get reference(): Reference {
    return this._publicKeys.reference();
  }

  get signingPublicKey(): SigningPublicKey {
    return this._publicKeys.signingPublicKey;
  }

  encapsulationPublicKey(): EncapsulationPublicKey {
    return this._publicKeys.encapsulationPublicKey();
  }

  verify(signature: Signature, message: Uint8Array): boolean {
    return this._publicKeys.verify(signature, message);
  }

  get endpoints(): ReadonlySet<URI> {
    return new Set(this._endpoints.values());
  }

  addEndpoint(endpoint: URI | string): void {
    const uri = endpoint instanceof URI ? endpoint : URI.from(endpoint);
    this._endpoints.set(uri.toString(), uri);
  }

  get nickname(): string {
    return this._nickname;
  }

  setNickname(name: string): void {
    this._nickname = name;
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
   * the permissions.
   */
  toEnvelope({ privateKeys = "omit" }: KeyEnvelopeOptions = {}): Envelope {
    let envelope = Envelope.from(this._publicKeys);
    if (this._privateKeyData !== undefined) {
      const { data, salt } = this._privateKeyData;
      if (data.type === "encrypted") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope());
      } else if (privateKeys === "include") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope());
      } else if (privateKeys === "elide") {
        envelope = envelope.addAssertionEnvelope(this.privateKeyAssertionEnvelope().elide());
      } else if (typeof privateKeys === "object") {
        const locked = lockSubject(
          Envelope.from(data.privateKeys),
          kdfOf(privateKeys),
          passwordBytes(privateKeys.encrypt),
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
   */
  static fromEnvelope(envelope: Envelope, { password }: PasswordOptions = {}): Key {
    const publicKeys = PublicKeys.fromCbor(envelope.subject().expectLeaf());
    let privateKeyData: { data: PrivateKeyData; salt: Salt } | undefined;
    const privateKeyAssertion = envelope.optionalAssertionWithPredicate(PRIVATE_KEY);
    if (privateKeyAssertion !== undefined) {
      const privateKeyObject = privateKeyAssertion.subject().expectObject();
      const saltAssertion = privateKeyAssertion.optionalAssertionWithPredicate(SALT);
      if (saltAssertion === undefined) {
        throw XIDError.envelopeParsing(new Error("missing 'salt' assertion on private-key node"));
      }
      const salt = Salt.fromCbor(saltAssertion.expectObject().expectLeaf());
      if (isLockedWithPassword(privateKeyObject)) {
        privateKeyData = { data: { type: "encrypted", envelope: privateKeyObject }, salt };
        if (password !== undefined) {
          try {
            const decrypted = unlockSubject(privateKeyObject, passwordBytes(password));
            const privateKeys = PrivateKeys.fromCbor(decrypted.subject().expectLeaf());
            privateKeyData = { data: { type: "decrypted", privateKeys }, salt };
          } catch {
            // A wrong password leaves the keys locked.
          }
        }
      } else {
        const privateKeys = PrivateKeys.fromCbor(privateKeyObject.expectLeaf());
        privateKeyData = { data: { type: "decrypted", privateKeys }, salt };
      }
    }
    let nickname = "";
    try {
      nickname = envelope.objectForPredicate(NICKNAME).asText() ?? "";
    } catch {
      // No nickname.
    }
    const endpoints = new Map<string, URI>();
    for (const assertion of envelope.assertionsWithPredicate(ENDPOINT)) {
      const uri = URI.fromCbor(assertion.expectObject().expectLeaf());
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
