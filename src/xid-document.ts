/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A XID document: the keys, delegates, services, resolution methods,
 * provenance, attachments and edges published under an extensible
 * identifier, and its envelope, CBOR and UR forms.
 */

// Ported from bc-xid-rust/src/xid_document.rs

import {
  type Cbor,
  type CborCodec,
  type CborTagged,
  type Tag,
  type ToCbor,
  asBytes,
  asTaggedValue,
  cbor,
  taggedValue,
} from "@blockchaincommons/dcbor";
import { Envelope, type ToEnvelope } from "@blockchaincommons/envelope";
import { Attachments } from "@blockchaincommons/envelope/attachment";
import { Edges, type Edgeable } from "@blockchaincommons/envelope/edge";
import { sign, hasSignatureFrom } from "@blockchaincommons/envelope/signature";
import {
  KEY,
  DELEGATE,
  SERVICE,
  PROVENANCE,
  DEREFERENCE_VIA,
  ATTACHMENT,
  EDGE,
} from "@blockchaincommons/known-values";
import {
  type Reference,
  URI,
  XID,
  type Digest,
  type PublicKeys,
  PrivateKeyBase,
  type PrivateKeys,
  type Signer,
  type EncapsulationPublicKey,
  type SigningPublicKey,
} from "@blockchaincommons/components";
import { XID as XID_TAG } from "@blockchaincommons/tags";
import { type ToUR, type UR, decodeURWith, urFor } from "@blockchaincommons/uniform-resources";
import { type RngOptions } from "@blockchaincommons/rand";
import {
  type ProvenanceMark,
  ProvenanceMarkGenerator,
  type ProvenanceMarkResolution,
  ProvenanceSeed,
} from "@blockchaincommons/provenance-mark";

import { Key, type XIDPrivateKeyOptions, type PasswordOptions, passwordBytes } from "./key";
import { Service } from "./service";
import { Delegate } from "./delegate";
import { Provenance, type XIDGeneratorOptions } from "./provenance";
import { XIDError } from "./error";

/**
 * The inception key of a new document: public keys only, a private key
 * base (Schnorr keys, private keys held), or a public/private pair.
 */
export type XIDInceptionKey =
  PublicKeys | PrivateKeyBase | { publicKeys: PublicKeys; privateKeys: PrivateKeys };

/** The genesis provenance mark of a new document, from a passphrase or a seed. */
export interface XIDGenesis {
  passphrase?: string | undefined;
  /** 32 bytes (longer input is cut to 32). */
  seed?: Uint8Array | undefined;
  resolution?: ProvenanceMarkResolution | undefined;
  date?: Date | undefined;
  info?: Cbor | undefined;
}

/** What `XIDDocument.from` takes. */
export interface XIDDocumentInput {
  inceptionKey: XIDInceptionKey;
  genesis?: XIDGenesis | undefined;
}

/** Who signs the document's envelope: nobody, the inception key, or a given signer. */
export type XIDSigning = "none" | "inception" | Signer;

/** Which signature `fromEnvelope` demands. */
export type XIDVerifySignature = "none" | "inception";

export interface XIDEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
  generator?: XIDGeneratorOptions | undefined;
  sign?: XIDSigning | undefined;
}

export interface XIDParseOptions extends PasswordOptions {
  verify?: XIDVerifySignature | undefined;
}

export interface SignedEnvelopeOptions {
  privateKeys?: XIDPrivateKeyOptions | undefined;
}

/** What `nextProvenanceMark` takes. */
export interface NextProvenanceMarkOptions extends PasswordOptions {
  date?: Date | undefined;
  info?: Cbor | undefined;
  /** A generator kept outside the document; refused when the document holds one. */
  generator?: ProvenanceMarkGenerator | undefined;
}

let CODEC: (CborCodec<XIDDocument> & { readonly tags: readonly Tag[] }) | undefined;

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

export class XIDDocument implements ToEnvelope, ToCbor, CborTagged, ToUR, Edgeable {
  private readonly _xid: XID;
  private readonly _resolutionMethods: Map<string, URI>;
  private readonly _keys: Map<string, Key>;
  private readonly _delegates: Map<string, Delegate>;
  private readonly _services: Map<string, Service>;
  private _provenance: Provenance | undefined;
  private _attachments: Attachments;
  private _edges: Edges;
  private _extraAssertions: Envelope[];

  private constructor(
    xid: XID,
    resolutionMethods = new Map<string, URI>(),
    keys = new Map<string, Key>(),
    delegates = new Map<string, Delegate>(),
    services = new Map<string, Service>(),
    provenance?: Provenance,
  ) {
    this._xid = xid;
    this._resolutionMethods = resolutionMethods;
    this._keys = keys;
    this._delegates = delegates;
    this._services = services;
    this._provenance = provenance;
    this._attachments = new Attachments();
    this._edges = new Edges();
    this._extraAssertions = [];
  }

  // Construction --------------------------------------------------------------

  /**
   * A document whose XID derives from the inception key's signing key;
   * the key is added allowed `All`. A genesis mark starts the provenance
   * chain and keeps the generator in the document.
   */
  static from({ inceptionKey, genesis }: XIDDocumentInput): XIDDocument {
    const key = XIDDocument.keyFor(inceptionKey);
    const provenance = XIDDocument.genesisFor(genesis);
    const doc = new XIDDocument(
      XID.fromSigningPublicKey(key.publicKeys.signingPublicKey),
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      provenance,
    );
    doc.addKey(key);
    return doc;
  }

  /** A document with a random private key base as its inception key. */
  static random({ rng }: RngOptions = {}, genesis?: XIDGenesis): XIDDocument {
    return XIDDocument.from({
      inceptionKey: PrivateKeyBase.random(rng === undefined ? {} : { rng }),
      genesis,
    });
  }

  /** An empty document: just the XID. */
  static fromXid(xid: XID): XIDDocument {
    return new XIDDocument(xid);
  }

  private static keyFor(inceptionKey: XIDInceptionKey): Key {
    if (inceptionKey instanceof PrivateKeyBase) return Key.fromPrivateKeyBase(inceptionKey);
    if ("privateKeys" in inceptionKey) {
      return Key.from(inceptionKey.publicKeys, { privateKeys: inceptionKey.privateKeys });
    }
    return Key.allowAll(inceptionKey);
  }

  private static genesisFor(genesis: XIDGenesis | undefined): Provenance | undefined {
    if (genesis === undefined) return undefined;
    const res = genesis.resolution ?? "high";
    const generator =
      genesis.passphrase !== undefined
        ? ProvenanceMarkGenerator.fromPassphrase(res, genesis.passphrase)
        : ProvenanceMarkGenerator.from({
            res,
            seed: ProvenanceSeed.from((genesis.seed ?? new Uint8Array(0)).subarray(0, 32)),
          });
    const mark = generator.next(genesis.date ?? new Date(), { info: genesis.info });
    return Provenance.from(mark, { generator });
  }

  // Identity ------------------------------------------------------------------

  get xid(): XID {
    return this._xid;
  }

  get reference(): Reference {
    return this._xid.reference();
  }

  /** No keys, delegates, services, resolution methods, provenance, attachments, edges or extra assertions. */
  get isEmpty(): boolean {
    return (
      this._resolutionMethods.size === 0 &&
      this._keys.size === 0 &&
      this._delegates.size === 0 &&
      this._provenance === undefined &&
      this._services.size === 0 &&
      !this.hasAttachments &&
      !this.hasEdges() &&
      this._extraAssertions.length === 0
    );
  }

  /** Assertions the parser did not recognise, kept as they were. */
  get extraAssertions(): readonly Envelope[] {
    return this._extraAssertions;
  }

  // Resolution methods --------------------------------------------------------

  get resolutionMethods(): ReadonlySet<URI> {
    return new Set(this._resolutionMethods.values());
  }

  addResolutionMethod(method: URI | string): void {
    const uri = method instanceof URI ? method : URI.from(method);
    this._resolutionMethods.set(uri.toString(), uri);
  }

  /** Whether it was there. */
  removeResolutionMethod(method: URI | string): boolean {
    return this._resolutionMethods.delete(method instanceof URI ? method.toString() : method);
  }

  // Keys ----------------------------------------------------------------------

  get keys(): readonly Key[] {
    return Array.from(this._keys.values());
  }

  /** `Duplicate` when the public keys are already there. */
  addKey(key: Key): void {
    const id = key.reference.toHex();
    if (this._keys.has(id)) throw XIDError.duplicate("key");
    this._keys.set(id, key);
  }

  key(publicKeys: PublicKeys): Key | undefined {
    return this._keys.get(publicKeys.reference().toHex());
  }

  keyByReference(reference: Reference): Key | undefined {
    for (const key of this._keys.values()) if (key.reference.equals(reference)) return key;
    return undefined;
  }

  /**
   * Removes and returns the key; `StillReferenced` when a service names
   * it, `NotFound` when it is not there.
   */
  removeKey(publicKeys: PublicKeys): Key {
    if (this.servicesReferenceKey(publicKeys)) throw XIDError.stillReferenced("key");
    const id = publicKeys.reference().toHex();
    const key = this._keys.get(id);
    if (key === undefined) throw XIDError.notFound("key");
    this._keys.delete(id);
    return key;
  }

  /** Removes and returns the key without checking services; `undefined` when absent. */
  takeKey(publicKeys: PublicKeys): Key | undefined {
    const id = publicKeys.reference().toHex();
    const key = this._keys.get(id);
    if (key !== undefined) this._keys.delete(id);
    return key;
  }

  /** `KeyNotFoundInDocument` unless the key is there. */
  expectKey(publicKeys: PublicKeys): Key {
    const key = this.key(publicKeys);
    if (key === undefined) throw XIDError.keyNotFoundInDocument(publicKeys.toString());
    return key;
  }

  isInceptionSigningKey(signingPublicKey: SigningPublicKey): boolean {
    return this._xid.validate(signingPublicKey);
  }

  /** The key whose signing key the XID derives from. */
  get inceptionKey(): Key | undefined {
    for (const key of this._keys.values()) {
      if (this.isInceptionSigningKey(key.publicKeys.signingPublicKey)) return key;
    }
    return undefined;
  }

  get inceptionPrivateKeys(): PrivateKeys | undefined {
    return this.inceptionKey?.privateKeys;
  }

  get inceptionSigningKey(): SigningPublicKey | undefined {
    return this.inceptionKey?.publicKeys.signingPublicKey;
  }

  /** The inception key's signing key, else the first key's. */
  get verificationKey(): SigningPublicKey | undefined {
    return (this.inceptionKey ?? this._keys.values().next().value)?.publicKeys.signingPublicKey;
  }

  /** The inception key's encapsulation key, else the first key's. */
  get encryptionKey(): EncapsulationPublicKey | undefined {
    return (
      this.inceptionKey ?? this._keys.values().next().value
    )?.publicKeys.encapsulationPublicKey();
  }

  /** Removes and returns the inception key, if there is one. */
  removeInceptionKey(): Key | undefined {
    const key = this.inceptionKey;
    if (key !== undefined) this._keys.delete(key.reference.toHex());
    return key;
  }

  /** `NotFound` unless the key is there. */
  setNameForKey(publicKeys: PublicKeys, name: string): void {
    const key = this.key(publicKeys);
    if (key === undefined) throw XIDError.notFound("key");
    key.setNickname(name);
  }

  /** The private keys of a key as an envelope (see `Key.privateKeyEnvelope`). */
  privateKeyEnvelopeForKey(
    publicKeys: PublicKeys,
    options: PasswordOptions = {},
  ): Envelope | undefined {
    return this.key(publicKeys)?.privateKeyEnvelope(options);
  }

  /** The inception key's private keys of a parsed envelope, unlocked with the password. */
  static inceptionPrivateKeysFromEnvelope(
    envelope: Envelope,
    password: Uint8Array | string,
  ): PrivateKeys | undefined {
    return XIDDocument.fromEnvelope(envelope, { password }).inceptionPrivateKeys;
  }

  // Delegates -----------------------------------------------------------------

  get delegates(): readonly Delegate[] {
    return Array.from(this._delegates.values());
  }

  /** `Duplicate` when a delegate with that XID is already there. */
  addDelegate(delegate: Delegate): void {
    const id = delegate.xid.toHex();
    if (this._delegates.has(id)) throw XIDError.duplicate("delegate");
    this._delegates.set(id, delegate);
  }

  delegate(xid: XID): Delegate | undefined {
    return this._delegates.get(xid.toHex());
  }

  delegateByReference(reference: Reference): Delegate | undefined {
    for (const d of this._delegates.values()) if (d.reference.equals(reference)) return d;
    return undefined;
  }

  /** Removes and returns the delegate; `StillReferenced` when a service names it, `NotFound` when absent. */
  removeDelegate(xid: XID): Delegate {
    if (this.servicesReferenceDelegate(xid)) throw XIDError.stillReferenced("delegate");
    const id = xid.toHex();
    const delegate = this._delegates.get(id);
    if (delegate === undefined) throw XIDError.notFound("delegate");
    this._delegates.delete(id);
    return delegate;
  }

  /** Removes and returns the delegate without checking services; `undefined` when absent. */
  takeDelegate(xid: XID): Delegate | undefined {
    const id = xid.toHex();
    const delegate = this._delegates.get(id);
    if (delegate !== undefined) this._delegates.delete(id);
    return delegate;
  }

  /** `DelegateNotFoundInDocument` unless the delegate is there. */
  expectDelegate(xid: XID): Delegate {
    const delegate = this.delegate(xid);
    if (delegate === undefined) throw XIDError.delegateNotFoundInDocument(xid.toString());
    return delegate;
  }

  // Services ------------------------------------------------------------------

  get services(): readonly Service[] {
    return Array.from(this._services.values());
  }

  service(uri: URI | string): Service | undefined {
    return this._services.get(uri.toString());
  }

  /** `Duplicate` when a service at that URI is already there. */
  addService(service: Service): void {
    const id = service.uri.toString();
    if (this._services.has(id)) throw XIDError.duplicate("service");
    this._services.set(id, service);
  }

  /** Removes and returns the service; `undefined` when absent. */
  takeService(uri: URI | string): Service | undefined {
    const id = uri.toString();
    const service = this._services.get(id);
    if (service !== undefined) this._services.delete(id);
    return service;
  }

  /** Removes and returns the service; `NotFound` when absent. */
  removeService(uri: URI | string): Service {
    const id = uri.toString();
    const service = this._services.get(id);
    if (service === undefined) throw XIDError.notFound("service");
    this._services.delete(id);
    return service;
  }

  /** Every service references known keys and delegates and allows something. */
  expectServicesConsistent(): void {
    for (const service of this._services.values()) this.expectServiceConsistent(service);
  }

  /**
   * `NoReferences` without any key or delegate reference,
   * `UnknownKeyReference`/`UnknownDelegateReference` for one the document
   * lacks, `NoPermissions` without an allowed privilege.
   */
  expectServiceConsistent(service: Service): void {
    const uri = service.uri.toString();
    if (service.keyReferences.size === 0 && service.delegateReferences.size === 0) {
      throw XIDError.noReferences(uri);
    }
    for (const ref of service.keyReferences) {
      if (this.keyByReference(ref) === undefined)
        throw XIDError.unknownKeyReference(ref.toHex(), uri);
    }
    for (const ref of service.delegateReferences) {
      if (this.delegateByReference(ref) === undefined) {
        throw XIDError.unknownDelegateReference(ref.toHex(), uri);
      }
    }
    if (service.permissions.allow.size === 0) throw XIDError.noPermissions(uri);
  }

  servicesReferenceKey(publicKeys: PublicKeys): boolean {
    const ref = publicKeys.reference();
    for (const service of this._services.values()) if (service.hasKeyReference(ref)) return true;
    return false;
  }

  servicesReferenceDelegate(xid: XID): boolean {
    const ref = xid.reference();
    for (const service of this._services.values()) {
      if (service.hasDelegateReference(ref)) return true;
    }
    return false;
  }

  // Attachments and edges -----------------------------------------------------

  get attachments(): Attachments {
    return this._attachments;
  }

  get hasAttachments(): boolean {
    return !this._attachments.isEmpty();
  }

  addAttachment(
    payload: Parameters<Attachments["add"]>[0],
    vendor: string,
    conformsTo?: string,
  ): void {
    this._attachments.add(payload, vendor, conformsTo);
  }

  attachment(digest: Digest): Envelope | undefined {
    return this._attachments.get(digest);
  }

  removeAttachment(digest: Digest): Envelope | undefined {
    return this._attachments.remove(digest);
  }

  clearAttachments(): void {
    this._attachments.clear();
  }

  edges(): Edges {
    return this._edges;
  }

  edgesMut(): Edges {
    return this._edges;
  }

  hasEdges(): boolean {
    return !this._edges.isEmpty();
  }

  addEdge(edgeEnvelope: Envelope): void {
    this._edges.add(edgeEnvelope);
  }

  edge(digest: Digest): Envelope | undefined {
    return this._edges.get(digest);
  }

  getEdge(digest: Digest): Envelope | undefined {
    return this.edge(digest);
  }

  removeEdge(digest: Digest): Envelope | undefined {
    return this._edges.remove(digest);
  }

  clearEdges(): void {
    this._edges.clear();
  }

  // Provenance ----------------------------------------------------------------

  /** The current provenance mark. */
  get provenance(): ProvenanceMark | undefined {
    return this._provenance?.mark;
  }

  /** The generator when the document holds it in the clear. */
  get provenanceGenerator(): ProvenanceMarkGenerator | undefined {
    return this._provenance?.generator;
  }

  /** Sets (or clears) the mark, dropping any generator. */
  setProvenance(provenance: ProvenanceMark | undefined): void {
    this._provenance = provenance === undefined ? undefined : Provenance.from(provenance);
  }

  setProvenanceWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): void {
    this._provenance = Provenance.from(mark, { generator });
  }

  /**
   * Advances the chain: with the document's own generator (unlocked with
   * the password when locked), or with a provided one when the document
   * has none. The generator must continue the current mark's chain at
   * the next sequence number. `NoProvenanceMark` without a mark,
   * `NoGenerator`/`GeneratorConflict` for the wrong choice.
   */
  nextProvenanceMark({ date, info, password, generator }: NextProvenanceMarkOptions = {}): void {
    if (this._provenance === undefined) throw XIDError.noProvenanceMark();
    const currentMark = this._provenance.mark;
    let gen: ProvenanceMarkGenerator;
    if (generator !== undefined) {
      if (this._provenance.hasGenerator || this._provenance.hasEncryptedGenerator) {
        throw XIDError.generatorConflict();
      }
      gen = generator;
    } else {
      const own = this._provenance.unlockGenerator({ password });
      if (own === undefined) throw XIDError.noGenerator();
      gen = own;
    }
    if (!bytesEqual(gen.chainId, currentMark.chainId)) {
      throw XIDError.chainIdMismatch(currentMark.chainId, gen.chainId);
    }
    const expectedSeq = currentMark.seq + 1;
    if (gen.nextSeq !== expectedSeq) throw XIDError.sequenceMismatch(expectedSeq, gen.nextSeq);
    this._provenance.setMark(gen.next(date ?? new Date(), { info }));
  }

  // Envelope ------------------------------------------------------------------

  /**
   * The XID as the subject; `'dereferenceVia'`, `'key'`, `'delegate'`,
   * `'service'`, `'provenance'`, the extra assertions, attachments and
   * edges; then signed per `sign` (`MissingInceptionKey` when the
   * inception key or its private keys are missing).
   */
  toEnvelope({
    privateKeys = "omit",
    generator = "omit",
    sign: signing = "none",
  }: XIDEnvelopeOptions = {}): Envelope {
    let envelope = Envelope.from(this._xid);
    for (const method of this._resolutionMethods.values()) {
      envelope = envelope.addAssertion(DEREFERENCE_VIA, method);
    }
    for (const key of this._keys.values()) {
      envelope = envelope.addAssertion(KEY, key.toEnvelope({ privateKeys }));
    }
    for (const delegate of this._delegates.values()) {
      envelope = envelope.addAssertion(DELEGATE, delegate.toEnvelope());
    }
    for (const service of this._services.values()) {
      envelope = envelope.addAssertion(SERVICE, service.toEnvelope());
    }
    if (this._provenance !== undefined) {
      envelope = envelope.addAssertion(PROVENANCE, this._provenance.toEnvelope({ generator }));
    }
    envelope = envelope.addAssertionEnvelopes(this._extraAssertions);
    envelope = this._attachments.addToEnvelope(envelope);
    envelope = this._edges.addToEnvelope(envelope);
    if (signing === "inception") {
      const privateKeys = this.inceptionKey?.privateKeys;
      if (privateKeys === undefined) throw XIDError.missingInceptionKey();
      envelope = sign(envelope, privateKeys);
    } else if (signing !== "none") {
      envelope = sign(envelope, signing);
    }
    return envelope;
  }

  /** `toEnvelope` signed by `signer`, the generator omitted. */
  toSignedEnvelope(signer: Signer, { privateKeys = "omit" }: SignedEnvelopeOptions = {}): Envelope {
    return sign(this.toEnvelope({ privateKeys }), signer);
  }

  /**
   * A document from its envelope. With `verify: "inception"` the envelope
   * must be signed by the document's own inception key
   * (`EnvelopeNotSigned`, `SignatureVerificationFailed`, `InvalidXid`);
   * otherwise a wrapped (signed) subject is unwrapped and read as it is.
   * The password unlocks locked private keys and generators.
   */
  static fromEnvelope(
    envelope: Envelope,
    { password, verify = "none" }: XIDParseOptions = {},
  ): XIDDocument {
    if (verify === "none") {
      const subject = envelope.subject();
      const toParse = subject.isWrapped() ? subject.unwrap() : envelope;
      return XIDDocument.parse(toParse, password);
    }
    if (!envelope.subject().isWrapped()) throw XIDError.envelopeNotSigned();
    const unwrapped = envelope.unwrap();
    const doc = XIDDocument.parse(unwrapped, password);
    const inceptionKey = doc.inceptionKey;
    if (inceptionKey === undefined) throw XIDError.missingInceptionKey();
    if (!hasSignatureFrom(envelope, inceptionKey.publicKeys)) {
      throw XIDError.signatureVerificationFailed();
    }
    if (!doc.isInceptionSigningKey(inceptionKey.publicKeys.signingPublicKey)) {
      throw XIDError.invalidXid();
    }
    return doc;
  }

  private static parse(envelope: Envelope, password: Uint8Array | string | undefined): XIDDocument {
    const subject = envelope.case.type === "node" ? envelope.subject() : envelope;
    const leaf = subject.asLeaf();
    if (leaf === undefined) throw XIDError.invalidXid();
    const doc = XIDDocument.fromXid(XID.fromCbor(leaf));
    const pw = password === undefined ? undefined : passwordBytes(password);
    for (const assertion of envelope.assertions()) {
      const c = assertion.case;
      if (c.type !== "assertion") {
        doc._extraAssertions.push(assertion);
        continue;
      }
      const predicateCase = c.assertion.predicate().case;
      if (predicateCase.type !== "knownValue") {
        doc._extraAssertions.push(assertion);
        continue;
      }
      const object = c.assertion.object();
      switch (predicateCase.value.value) {
        case DEREFERENCE_VIA.value: {
          let uri: URI;
          try {
            uri = URI.fromCbor(object.expectLeaf());
          } catch {
            throw XIDError.invalidResolutionMethod();
          }
          doc.addResolutionMethod(uri);
          break;
        }
        case KEY.value:
          doc.addKey(Key.fromEnvelope(object, { password: pw }));
          break;
        case DELEGATE.value:
          doc.addDelegate(Delegate.fromEnvelope(object, (e) => XIDDocument.fromEnvelope(e)));
          break;
        case SERVICE.value:
          doc.addService(Service.fromEnvelope(object));
          break;
        case PROVENANCE.value:
          if (doc._provenance !== undefined) throw XIDError.multipleProvenanceMarks();
          doc._provenance = Provenance.fromEnvelope(object, { password: pw });
          break;
        case ATTACHMENT.value:
        case EDGE.value:
          break;
        default:
          doc._extraAssertions.push(assertion);
          break;
      }
    }
    doc._attachments = Attachments.fromEnvelope(envelope);
    doc._edges = Edges.fromEnvelope(envelope);
    doc.expectServicesConsistent();
    return doc;
  }

  // CBOR and UR ---------------------------------------------------------------

  /** An empty document is its XID's bytes; otherwise the envelope's tagged CBOR. */
  untaggedCbor(): Cbor {
    return this.isEmpty ? cbor(this._xid.bytes) : this.toEnvelope().toCbor();
  }

  /** Tag `xid` (40024) over `untaggedCbor`. */
  toCbor(): Cbor {
    return XIDDocument.codec.encode(this);
  }

  cborTags(): Tag[] {
    return [XID_TAG];
  }

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): CborCodec<XIDDocument> & { readonly tags: readonly Tag[] } {
    return (CODEC ??= {
      tags: Object.freeze([XID_TAG]),
      encode: (value) => taggedValue(XID_TAG, value.untaggedCbor()),
      decode: (value) => XIDDocument.fromUntaggedCbor(value),
    });
  }

  private static fromUntaggedCbor(cborValue: Cbor): XIDDocument {
    const tv = asTaggedValue(cborValue);
    const value = tv !== undefined && tv[0].value === XID_TAG.value ? tv[1] : cborValue;
    const bytes = asBytes(value);
    if (bytes !== undefined) return XIDDocument.fromXid(XID.from(bytes));
    return XIDDocument.fromEnvelope(Envelope.fromCbor(value));
  }

  /** `ur:xid/…` over `untaggedCbor`. */
  toUR(): UR {
    return urFor(this);
  }

  static fromUR(ur: UR): XIDDocument {
    return decodeURWith(ur, XIDDocument.codec);
  }

  // Comparison ----------------------------------------------------------------

  /**
   * Same XID, resolution methods, keys (public and private material,
   * nickname, endpoints, permissions), delegates, services, provenance
   * (mark and generator), attachments, edges and extra assertions — as
   * the reference's equality.
   */
  equals(other: XIDDocument): boolean {
    if (!this._xid.equals(other._xid)) return false;
    if (this._resolutionMethods.size !== other._resolutionMethods.size) return false;
    for (const key of this._resolutionMethods.keys()) {
      if (!other._resolutionMethods.has(key)) return false;
    }
    if (this._keys.size !== other._keys.size) return false;
    for (const [id, key] of this._keys) {
      const otherKey = other._keys.get(id);
      if (otherKey === undefined || !key.equals(otherKey)) return false;
    }
    if (this._delegates.size !== other._delegates.size) return false;
    for (const [id, delegate] of this._delegates) {
      const otherDelegate = other._delegates.get(id);
      if (otherDelegate === undefined || !delegate.equals(otherDelegate)) return false;
    }
    if (this._services.size !== other._services.size) return false;
    for (const [id, service] of this._services) {
      const otherService = other._services.get(id);
      if (otherService === undefined || !service.equals(otherService)) return false;
    }
    if ((this._provenance === undefined) !== (other._provenance === undefined)) return false;
    if (
      this._provenance !== undefined &&
      other._provenance !== undefined &&
      !this._provenance.equals(other._provenance)
    ) {
      return false;
    }
    if (!this._attachments.equals(other._attachments)) return false;
    if (!this._edges.equals(other._edges)) return false;
    if (this._extraAssertions.length !== other._extraAssertions.length) return false;
    for (let i = 0; i < this._extraAssertions.length; i++) {
      if (!this._extraAssertions[i].isEquivalentTo(other._extraAssertions[i])) return false;
    }
    return true;
  }

  clone(): XIDDocument {
    const doc = new XIDDocument(
      this._xid,
      new Map(this._resolutionMethods),
      new Map(Array.from(this._keys.entries()).map(([k, v]) => [k, v.clone()])),
      new Map(Array.from(this._delegates.entries()).map(([k, v]) => [k, v.clone()])),
      new Map(Array.from(this._services.entries()).map(([k, v]) => [k, v.clone()])),
      this._provenance?.clone(),
    );
    for (const [, env] of this._attachments.iter()) doc._attachments.addEnvelope(env);
    for (const [, env] of this._edges.iter()) doc._edges.add(env);
    doc._extraAssertions = [...this._extraAssertions];
    return doc;
  }

  toString(): string {
    return `XIDDocument(${this._xid.shortDescription()})`;
  }
}
