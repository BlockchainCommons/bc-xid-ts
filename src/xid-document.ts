/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A XID document: the keys, delegates, services, resolution methods,
 * provenance, attachments and edges published under an extensible
 * identifier, and its envelope, CBOR and UR forms.
 */

import {
  type Cbor,
  type CborCodec,
  type CborTagged,
  type Tag,
  type ToCbor,
  CborError,
  asBytes,
  cbor,
  extractTaggedContent,
  taggedValue,
  validateTag,
} from "@blockchaincommons/dcbor";
import { Envelope, type EnvelopeInput, type ToEnvelope } from "@blockchaincommons/envelope";
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
  PublicKeys,
  PrivateKeyBase,
  PrivateKeys,
  type Signer,
  type EncapsulationPublicKey,
  type SigningPublicKey,
} from "@blockchaincommons/components";
import { TAG_XID } from "@blockchaincommons/tags";
import { type ToUR, type UR, decodeURWith, urFor } from "@blockchaincommons/uniform-resources";
import { type RngOptions } from "@blockchaincommons/rand";
import {
  type DateInput,
  ProvenanceMark,
  ProvenanceMarkGenerator,
  type ProvenanceMarkResolution,
  PROVENANCE_MARK_RESOLUTIONS,
  ProvenanceSeed,
} from "@blockchaincommons/provenance-mark";

import {
  Key,
  type XIDPrivateKeyOptions,
  type PasswordOptions,
  expectPrivateKeyOptions,
  passwordBytes,
} from "./key";
import { Service } from "./service";
import { Delegate, setDefaultDocumentParser } from "./delegate";
import { Provenance, type XIDGeneratorOptions } from "./provenance";
import { XIDError } from "./error";
import {
  cborErrorOf,
  expectDateInput,
  expectInstance,
  expectOneOf,
  guarded,
  leafAs,
  wrapForeign,
} from "./domain";

/**
 * The inception key of a new document: public keys only, a private key
 * base (Schnorr keys, private keys held), or a public/private pair.
 */
export type XIDInceptionKey = PublicKeys | PrivateKeyBase | XIDInceptionKeyPair;

/** An inception key given as a public/private pair. */
export interface XIDInceptionKeyPair {
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
export interface XIDGenesis {
  /** The passphrase the chain's seed derives from. */
  passphrase?: string | undefined;
  /** The chain's seed: a `ProvenanceSeed` or exactly 32 bytes. */
  seed?: Uint8Array | ProvenanceSeed | undefined;
  /** The chain's resolution; `"high"` unless given. */
  resolution?: ProvenanceMarkResolution | undefined;
  /** The genesis mark's date, a `Date` or a `CborDate`; now unless given. */
  date?: DateInput | undefined;
  /** The genesis mark's info. */
  info?: Cbor | undefined;
}

/** What `XIDDocument.from` takes. */
export interface XIDDocumentInput {
  /** The inception key, whose signing key the XID derives from. */
  inceptionKey: XIDInceptionKey;
  /** A genesis mark to start the provenance chain with. */
  genesis?: XIDGenesis | undefined;
}

/** What `XIDDocument.random` takes. */
export interface XIDRandomOptions extends RngOptions {
  /** A genesis mark to start the provenance chain with. */
  genesis?: XIDGenesis | undefined;
}

/** Who signs the document's envelope: nobody, the inception key, or a given signer. */
export type XIDSigning = "none" | "inception" | Signer;

/** Which signature `fromEnvelope` demands. */
export type XIDVerifySignature = "none" | "inception";

/** What `XIDDocument.toEnvelope` takes. */
export interface XIDEnvelopeOptions {
  /** How each key's private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
  /** How the provenance generator goes into the envelope; `"omit"` unless given. */
  generator?: XIDGeneratorOptions | undefined;
  /** Who signs; `"none"` unless given. */
  sign?: XIDSigning | undefined;
}

/** What `XIDDocument.fromEnvelope` takes. */
export interface XIDParseOptions extends PasswordOptions {
  /** Which signature to demand; `"none"` unless given. */
  verify?: XIDVerifySignature | undefined;
}

/** What `XIDDocument.toSignedEnvelope` takes besides the signer. */
export interface SignedEnvelopeOptions {
  /** How each key's private keys go into the envelope; `"omit"` unless given. */
  privateKeys?: XIDPrivateKeyOptions | undefined;
}

/** What `XIDDocument.addAttachment` takes. */
export interface AttachmentInput {
  /** The payload, as anything an envelope is made from. */
  payload: EnvelopeInput;
  /** The vendor, a reverse domain name. */
  vendor: string;
  /** The URI of the format the payload conforms to. */
  conformsTo?: string | undefined;
}

/** What `nextProvenanceMarkWithEmbeddedGenerator` takes. */
export interface NextProvenanceMarkOptions extends PasswordOptions {
  /** The new mark's date, a `Date` or a `CborDate`; now unless given. */
  date?: DateInput | undefined;
  /** The new mark's info. */
  info?: Cbor | undefined;
}

/** What `nextProvenanceMarkWithProvidedGenerator` takes besides the generator. */
export interface ProvidedGeneratorOptions {
  /** The new mark's date, a `Date` or a `CborDate`; now unless given. */
  date?: DateInput | undefined;
  /** The new mark's info. */
  info?: Cbor | undefined;
}

/** The document's CBOR codec, with the tag it carries. */
export interface XIDDocumentCodec extends CborCodec<XIDDocument> {
  /** The `xid` tag (40024). */
  readonly tags: readonly Tag[];
}

let CODEC: XIDDocumentCodec | undefined;

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

const VERIFY_NAMES = ["none", "inception"] as const;

/**
 * A XID document: the keys, delegates, services, resolution methods,
 * provenance, attachments and edges published under an extensible
 * identifier. The document is mutable; its `keys`, `delegates` and
 * `services` are copied-out arrays of live values, and `attachments` and
 * `edges()` are the document's own containers.
 */
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
   * chain and keeps the generator in the document. A missing inception
   * key or a malformed genesis is a `TypeError`; a seed of the wrong
   * length is `ProvenanceMark`.
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
  static random({ rng, genesis }: XIDRandomOptions = {}): XIDDocument {
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
    if (inceptionKey instanceof PublicKeys) return Key.allowAll(inceptionKey);
    if (inceptionKey instanceof PrivateKeyBase) return Key.fromPrivateKeyBase(inceptionKey);
    if (
      typeof inceptionKey === "object" &&
      inceptionKey !== null &&
      "privateKeys" in inceptionKey
    ) {
      return Key.from(
        expectInstance(inceptionKey.publicKeys, PublicKeys, "inceptionKey.publicKeys"),
        {
          privateKeys: expectInstance(
            inceptionKey.privateKeys,
            PrivateKeys,
            "inceptionKey.privateKeys",
          ),
        },
      );
    }
    throw new TypeError(
      "inceptionKey must be PublicKeys, a PrivateKeyBase or { publicKeys, privateKeys }",
    );
  }

  private static genesisFor(genesis: XIDGenesis | undefined): Provenance | undefined {
    if (genesis === undefined) return undefined;
    if (typeof genesis !== "object" || genesis === null) {
      throw new TypeError("genesis must be an object with a passphrase or a seed");
    }
    const { passphrase, seed, resolution, date, info } = genesis;
    if ((passphrase === undefined) === (seed === undefined)) {
      throw new TypeError("genesis needs exactly one of passphrase or seed");
    }
    const res =
      resolution === undefined
        ? "high"
        : expectOneOf(resolution, PROVENANCE_MARK_RESOLUTIONS, "genesis.resolution");
    const at = date === undefined ? new Date() : expectDateInput(date, "genesis.date");
    const generator =
      passphrase !== undefined
        ? ProvenanceMarkGenerator.fromPassphrase(res, passphrase)
        : ProvenanceMarkGenerator.from({ res, seed: XIDDocument.seedOf(seed) });
    const mark = guarded(() => generator.next(at, info));
    return Provenance.from(mark, { generator });
  }

  /** A `ProvenanceSeed` from bytes; the wrong length is `ProvenanceMark`. */
  private static seedOf(seed: Uint8Array | ProvenanceSeed | undefined): ProvenanceSeed {
    if (seed instanceof ProvenanceSeed) return seed;
    if (!(seed instanceof Uint8Array)) {
      throw new TypeError("genesis.seed must be a ProvenanceSeed or 32 bytes");
    }
    return guarded(() => ProvenanceSeed.from(seed));
  }

  // Identity ------------------------------------------------------------------

  /** The XID. */
  get xid(): XID {
    return this._xid;
  }

  /** The XID's reference. */
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

  /** Assertions the parser did not recognise, kept as they were (a copy). */
  get extraAssertions(): readonly Envelope[] {
    return [...this._extraAssertions];
  }

  // Resolution methods --------------------------------------------------------

  /** The resolution methods (a copy). */
  get resolutionMethods(): ReadonlySet<URI> {
    return new Set(this._resolutionMethods.values());
  }

  /** Adds a resolution method, as a URI or its text (a components error for text that is not a URI). */
  addResolutionMethod(method: URI | string): void {
    const uri = method instanceof URI ? method : URI.from(method);
    this._resolutionMethods.set(uri.toString(), uri);
  }

  /** Removes and returns a resolution method; `undefined` when it was not there. */
  removeResolutionMethod(method: URI | string): URI | undefined {
    const key = method.toString();
    const uri = this._resolutionMethods.get(key);
    if (uri !== undefined) this._resolutionMethods.delete(key);
    return uri;
  }

  // Keys ----------------------------------------------------------------------

  /** The keys (a copied-out array of live keys). */
  get keys(): readonly Key[] {
    return Array.from(this._keys.values());
  }

  /** Adds a key; `Duplicate` when the public keys are already there. */
  addKey(key: Key): void {
    expectInstance(key, Key, "key");
    const id = key.reference.toHex();
    if (this._keys.has(id)) throw XIDError.duplicate("key");
    this._keys.set(id, key);
  }

  /** The key with these public keys. */
  findKeyByPublicKeys(publicKeys: PublicKeys): Key | undefined {
    return this._keys.get(publicKeys.reference().toHex());
  }

  /** The key with this reference. */
  findKeyByReference(reference: Reference): Key | undefined {
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

  /** `KeyNotFoundInDocument` unless the key with these public keys is there. */
  checkContainsKey(publicKeys: PublicKeys): void {
    if (this.findKeyByPublicKeys(publicKeys) === undefined) {
      throw XIDError.keyNotFoundInDocument(publicKeys.toString());
    }
  }

  /** Whether the XID derives from this signing key. */
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

  /** The inception key's private keys, when held in the clear. */
  get inceptionPrivateKeys(): PrivateKeys | undefined {
    return this.inceptionKey?.privateKeys;
  }

  /** The inception key's signing key. */
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

  /** Sets the key's nickname; `NotFound` unless the key is there. */
  setNameForKey(publicKeys: PublicKeys, name: string): void {
    const key = this.findKeyByPublicKeys(publicKeys);
    if (key === undefined) throw XIDError.notFound("key");
    key.setNickname(name);
  }

  /** The private keys of a key as an envelope (see `Key.privateKeyEnvelope`). */
  privateKeyEnvelopeForKey(
    publicKeys: PublicKeys,
    options: PasswordOptions = {},
  ): Envelope | undefined {
    return this.findKeyByPublicKeys(publicKeys)?.privateKeyEnvelope(options);
  }

  /** The inception key's private keys of a parsed envelope, unlocked with the password. */
  static extractInceptionPrivateKeysFromEnvelope(
    envelope: Envelope,
    { password }: PasswordOptions = {},
  ): PrivateKeys | undefined {
    return XIDDocument.fromEnvelope(envelope, { password }).inceptionPrivateKeys;
  }

  // Delegates -----------------------------------------------------------------

  /** The delegates (a copied-out array of live delegates). */
  get delegates(): readonly Delegate[] {
    return Array.from(this._delegates.values());
  }

  /** Adds a delegate; `Duplicate` when a delegate with that XID is already there. */
  addDelegate(delegate: Delegate): void {
    expectInstance(delegate, Delegate, "delegate");
    const id = delegate.xid.toHex();
    if (this._delegates.has(id)) throw XIDError.duplicate("delegate");
    this._delegates.set(id, delegate);
  }

  /** The delegate with this XID. */
  findDelegateByXid(xid: XID): Delegate | undefined {
    return this._delegates.get(xid.toHex());
  }

  /** The delegate whose XID has this reference. */
  findDelegateByReference(reference: Reference): Delegate | undefined {
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

  /** `DelegateNotFoundInDocument` unless the delegate with this XID is there. */
  checkContainsDelegate(xid: XID): void {
    if (this.findDelegateByXid(xid) === undefined) {
      throw XIDError.delegateNotFoundInDocument(xid.toString());
    }
  }

  // Services ------------------------------------------------------------------

  /** The services (a copied-out array of live services). */
  get services(): readonly Service[] {
    return Array.from(this._services.values());
  }

  /** The service at this URI. */
  findServiceByUri(uri: URI | string): Service | undefined {
    return this._services.get(uri.toString());
  }

  /** Adds a service; `Duplicate` when a service at that URI is already there. */
  addService(service: Service): void {
    expectInstance(service, Service, "service");
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
  checkServicesConsistency(): void {
    for (const service of this._services.values()) this.checkServiceConsistency(service);
  }

  /**
   * `NoReferences` without any key or delegate reference,
   * `UnknownKeyReference`/`UnknownDelegateReference` for one the document
   * lacks, `NoPermissions` without an allowed privilege.
   */
  checkServiceConsistency(service: Service): void {
    const uri = service.uri.toString();
    if (service.keyReferences.size === 0 && service.delegateReferences.size === 0) {
      throw XIDError.noReferences(uri);
    }
    for (const ref of service.keyReferences) {
      if (this.findKeyByReference(ref) === undefined) {
        throw XIDError.unknownKeyReference(ref.toString(), uri);
      }
    }
    for (const ref of service.delegateReferences) {
      if (this.findDelegateByReference(ref) === undefined) {
        throw XIDError.unknownDelegateReference(ref.toString(), uri);
      }
    }
    if (service.permissions.allow.size === 0) throw XIDError.noPermissions(uri);
  }

  /** Whether any service references this key. */
  servicesReferenceKey(publicKeys: PublicKeys): boolean {
    const ref = publicKeys.reference();
    for (const service of this._services.values()) if (service.hasKeyReference(ref)) return true;
    return false;
  }

  /** Whether any service references this delegate. */
  servicesReferenceDelegate(xid: XID): boolean {
    const ref = xid.reference();
    for (const service of this._services.values()) {
      if (service.hasDelegateReference(ref)) return true;
    }
    return false;
  }

  // Attachments and edges -----------------------------------------------------

  /** The attachments: the document's own container. */
  get attachments(): Attachments {
    return this._attachments;
  }

  /** Whether there are attachments. */
  get hasAttachments(): boolean {
    return this._attachments.size > 0;
  }

  /** Adds an attachment. */
  addAttachment({ payload, vendor, conformsTo }: AttachmentInput): void {
    this._attachments.add(payload, vendor, conformsTo);
  }

  /** The attachment with this digest. */
  getAttachment(digest: Digest): Envelope | undefined {
    return this._attachments.get(digest);
  }

  /** Removes and returns the attachment with this digest. */
  removeAttachment(digest: Digest): Envelope | undefined {
    return this._attachments.remove(digest);
  }

  /** Removes every attachment. */
  clearAttachments(): void {
    this._attachments.clear();
  }

  /** The edges: the document's own container (envelope's `Edgeable`). */
  edges(): Edges {
    return this._edges;
  }

  /** The same container as `edges()` (envelope's `Edgeable` names both). */
  edgesMut(): Edges {
    return this._edges;
  }

  /** Whether there are edges (envelope's `Edgeable`). */
  hasEdges(): boolean {
    return this._edges.size > 0;
  }

  /** Adds an edge envelope. */
  addEdge(edgeEnvelope: Envelope): void {
    this._edges.add(edgeEnvelope);
  }

  /** The edge with this digest (envelope's `Edgeable`). */
  getEdge(digest: Digest): Envelope | undefined {
    return this._edges.get(digest);
  }

  /** Removes and returns the edge with this digest. */
  removeEdge(digest: Digest): Envelope | undefined {
    return this._edges.remove(digest);
  }

  /** Removes every edge. */
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
    this._provenance =
      provenance === undefined
        ? undefined
        : Provenance.from(expectInstance(provenance, ProvenanceMark, "provenance"));
  }

  /** Sets the mark and the generator that continues its chain. */
  setProvenanceWithGenerator(generator: ProvenanceMarkGenerator, mark: ProvenanceMark): void {
    this._provenance = Provenance.from(expectInstance(mark, ProvenanceMark, "mark"), {
      generator: expectInstance(generator, ProvenanceMarkGenerator, "generator"),
    });
  }

  /**
   * Advances the chain with the document's own generator, unlocked with
   * the password when it is locked; the generator stays in the document.
   * `NoProvenanceMark` without a mark, `NoGenerator` without a generator,
   * `InvalidPassword` when it is locked and the password is missing or
   * wrong, `ChainIdMismatch`/`SequenceMismatch` when the generator does
   * not continue the mark at the next sequence number; a `Date` without a
   * time is `ProvenanceMark[InvalidDate]`; a date of another kind is a
   * `TypeError`.
   */
  nextProvenanceMarkWithEmbeddedGenerator({
    password,
    date,
    info,
  }: NextProvenanceMarkOptions = {}): void {
    const at = date === undefined ? new Date() : expectDateInput(date, "date");
    if (this._provenance === undefined) throw XIDError.noProvenanceMark();
    const generator = this._provenance.unlockGenerator({ password });
    if (generator === undefined) throw XIDError.noGenerator();
    this.advance(this._provenance, generator, at, info);
  }

  /**
   * Advances the chain with a generator the caller keeps; the generator
   * is advanced in place and not stored. `NoProvenanceMark` without a
   * mark, `GeneratorConflict` when the document holds a generator (in the
   * clear or locked), `ChainIdMismatch`/`SequenceMismatch` when the
   * generator does not continue the mark at the next sequence number; a
   * `Date` without a time is `ProvenanceMark[InvalidDate]`; a generator or
   * date of another kind is a `TypeError`.
   */
  nextProvenanceMarkWithProvidedGenerator(
    generator: ProvenanceMarkGenerator,
    { date, info }: ProvidedGeneratorOptions = {},
  ): void {
    expectInstance(generator, ProvenanceMarkGenerator, "generator");
    const at = date === undefined ? new Date() : expectDateInput(date, "date");
    if (this._provenance === undefined) throw XIDError.noProvenanceMark();
    if (this._provenance.hasGenerator || this._provenance.hasEncryptedGenerator) {
      throw XIDError.generatorConflict();
    }
    this.advance(this._provenance, generator, at, info);
  }

  /** The checks and the step both forms share. */
  private advance(
    provenance: Provenance,
    generator: ProvenanceMarkGenerator,
    at: DateInput,
    info: Cbor | undefined,
  ): void {
    const currentMark = provenance.mark;
    if (!bytesEqual(generator.chainId, currentMark.chainId)) {
      throw XIDError.chainIdMismatch(currentMark.chainId, generator.chainId);
    }
    const expectedSeq = currentMark.seq + 1;
    if (generator.nextSeq !== expectedSeq) {
      throw XIDError.sequenceMismatch(expectedSeq, generator.nextSeq);
    }
    provenance.setMark(guarded(() => generator.next(at, info)));
  }

  // Envelope ------------------------------------------------------------------

  /**
   * The XID as the subject; `'dereferenceVia'`, `'key'`, `'delegate'`,
   * `'service'`, `'provenance'`, the extra assertions, attachments and
   * edges; then signed per `sign` (`MissingInceptionKey` when the
   * inception key or its private keys are missing). An unknown option
   * is a `TypeError`.
   */
  toEnvelope({
    privateKeys = "omit",
    generator = "omit",
    sign: signing = "none",
  }: XIDEnvelopeOptions = {}): Envelope {
    const privateKeyOption = expectPrivateKeyOptions(privateKeys, "privateKeys");
    const generatorOption = expectPrivateKeyOptions(generator, "generator");
    const signer = XIDDocument.signerOf(signing);
    let envelope = Envelope.from(this._xid);
    for (const method of this._resolutionMethods.values()) {
      envelope = envelope.addAssertion(DEREFERENCE_VIA, method);
    }
    for (const key of this._keys.values()) {
      envelope = envelope.addAssertion(KEY, key.toEnvelope({ privateKeys: privateKeyOption }));
    }
    for (const delegate of this._delegates.values()) {
      envelope = envelope.addAssertion(DELEGATE, delegate.toEnvelope());
    }
    for (const service of this._services.values()) {
      envelope = envelope.addAssertion(SERVICE, service.toEnvelope());
    }
    if (this._provenance !== undefined) {
      envelope = envelope.addAssertion(
        PROVENANCE,
        this._provenance.toEnvelope({ generator: generatorOption }),
      );
    }
    envelope = envelope.addAssertionEnvelopes(this._extraAssertions);
    envelope = this._attachments.addToEnvelope(envelope);
    envelope = this._edges.addToEnvelope(envelope);
    if (signer === "inception") {
      const inceptionPrivateKeys = this.inceptionKey?.privateKeys;
      if (inceptionPrivateKeys === undefined) throw XIDError.missingInceptionKey();
      envelope = sign(envelope, inceptionPrivateKeys);
    } else if (signer !== "none") {
      envelope = sign(envelope, signer);
    }
    return envelope;
  }

  /** The `sign` option checked: one of the two names, or a signer. */
  private static signerOf(signing: unknown): XIDSigning {
    if (typeof signing === "object" && signing !== null && "sign" in signing) {
      return signing as Signer;
    }
    return expectOneOf(signing, ["none", "inception"] as const, "sign");
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
   * The password unlocks locked private keys and generators. Every
   * failure is an `XIDError`: a sibling error inside the parser is
   * wrapped with the reference's code. An unknown `verify` is a
   * `TypeError`.
   */
  static fromEnvelope(
    envelope: Envelope,
    { password, verify = "none" }: XIDParseOptions = {},
  ): XIDDocument {
    const mode = expectOneOf(verify, VERIFY_NAMES, "verify");
    if (mode === "none") {
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
    // The attachments and edges first, as the reference reads them.
    const attachments = guarded(() => Attachments.fromEnvelope(envelope));
    const edges = guarded(() => Edges.fromEnvelope(envelope));
    const doc = XIDDocument.fromXid(leafAs(envelope.subject(), (c) => XID.fromCbor(c)));
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
          const leaf = guarded(() => object.expectLeaf());
          let uri: URI;
          try {
            uri = URI.fromCbor(leaf);
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
          doc.addDelegate(Delegate.fromEnvelope(object));
          break;
        case SERVICE.value:
          doc.addService(Service.fromEnvelope(object));
          break;
        case PROVENANCE.value: {
          const provenance = Provenance.fromEnvelope(object, { password: pw });
          if (doc._provenance !== undefined) throw XIDError.multipleProvenanceMarks();
          doc._provenance = provenance;
          break;
        }
        case ATTACHMENT.value:
        case EDGE.value:
          break;
        default:
          doc._extraAssertions.push(assertion);
          break;
      }
    }
    doc._attachments = attachments;
    doc._edges = edges;
    doc.checkServicesConsistency();
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

  /** The tags this document's CBOR carries: `xid` (40024). */
  cborTags(): Tag[] {
    return [TAG_XID];
  }

  /** The tagged-CBOR codec: `decode` is `fromCbor`, the tag required. */
  static get codec(): XIDDocumentCodec {
    return (CODEC ??= {
      tags: Object.freeze([TAG_XID]),
      encode: (value) => taggedValue(TAG_XID, value.untaggedCbor()),
      decode: (value) => XIDDocument.fromCbor(value),
    });
  }

  /**
   * A document from its tagged CBOR: the `xid` tag (40024) over the
   * untagged form. A missing or different tag, or a form the untagged
   * decoder rejects, is `Cbor` with the dcbor error's message.
   */
  static fromCbor(cborValue: Cbor): XIDDocument {
    let untagged: Cbor;
    try {
      validateTag(cborValue, [TAG_XID]);
      untagged = extractTaggedContent(cborValue);
    } catch (error) {
      throw XIDError.cborDecode(cborErrorOf(error));
    }
    return XIDDocument.fromUntaggedCbor(untagged);
  }

  /**
   * A document from its untagged CBOR: a 32-byte string is the XID of an
   * empty document; anything else is a document envelope. A tagged value
   * is rejected (the envelope tag is expected), as the reference's
   * `from_untagged_cbor` rejects it. A rejection is `Cbor`: the dcbor
   * error's message, or the document error's (`envelope parsing error`,
   * …) when the envelope decodes but the document does not.
   */
  static fromUntaggedCbor(cborValue: Cbor): XIDDocument {
    const bytes = asBytes(cborValue);
    if (bytes !== undefined) {
      try {
        return XIDDocument.fromXid(XID.from(bytes));
      } catch (error) {
        throw XIDError.cborDecode(cborErrorOf(error));
      }
    }
    let envelope: Envelope;
    try {
      envelope = Envelope.fromCbor(cborValue);
    } catch (error) {
      throw XIDError.cborDecode(cborErrorOf(error));
    }
    try {
      return XIDDocument.fromEnvelope(envelope);
    } catch (error) {
      const wrapped = wrapForeign(error);
      if (!XIDError.isXIDError(wrapped)) throw wrapped;
      if (wrapped.code === "Cbor" && CborError.isCborError(wrapped.cause)) {
        throw XIDError.cborDecode(wrapped.cause);
      }
      throw XIDError.cborDecode(CborError.custom(wrapped.message));
    }
  }

  /** `ur:xid/…` over `untaggedCbor`. */
  toUR(): UR {
    return urFor(this);
  }

  /**
   * A document from a `ur:xid/…` UR. A UR of another type is `Cbor`
   * (`expected UR type xid, but found …`), as the reference's `from_ur`
   * reports it.
   */
  static fromUR(ur: UR): XIDDocument {
    try {
      return decodeURWith(ur, XIDDocument.codec);
    } catch (error) {
      if (CborError.isCborError(error)) throw XIDError.cborDecode(error);
      throw error;
    }
  }

  // Comparison ----------------------------------------------------------------

  /**
   * Same XID, resolution methods, keys (public and private material,
   * nickname, endpoints, permissions), delegates, services, provenance
   * (mark and generator), attachments, edges and extra assertions — as
   * the reference's equality.
   */
  equals(other: XIDDocument): boolean {
    expectInstance(other, XIDDocument, "other", "an XIDDocument");
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

  /** A deep copy. */
  clone(): XIDDocument {
    const doc = new XIDDocument(
      this._xid,
      new Map(this._resolutionMethods),
      new Map(Array.from(this._keys.entries()).map(([k, v]) => [k, v.clone()])),
      new Map(Array.from(this._delegates.entries()).map(([k, v]) => [k, v.clone()])),
      new Map(Array.from(this._services.entries()).map(([k, v]) => [k, v.clone()])),
      this._provenance?.clone(),
    );
    for (const env of this._attachments) doc._attachments.addEnvelope(env);
    for (const env of this._edges) doc._edges.add(env);
    doc._extraAssertions = [...this._extraAssertions];
    return doc;
  }

  /** `XIDDocument(<short XID>)`. */
  toString(): string {
    return `XIDDocument(${this._xid.shortDescription()})`;
  }
}

setDefaultDocumentParser((envelope) => XIDDocument.fromEnvelope(envelope));
