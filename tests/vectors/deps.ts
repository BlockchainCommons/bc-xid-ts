/**
 * The module objects and sibling operations the adapters drive: the frozen
 * bundle (the siblings it inlines), or the working tree with the current
 * siblings.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { PrivateKeyBase, Salt, URI } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { CborDate, cbor } from "@blockchaincommons/dcbor";
import { Envelope } from "@blockchaincommons/envelope";
import { format } from "@blockchaincommons/envelope/format";
import { sign } from "@blockchaincommons/envelope/signature";
import { IS_A, SOURCE, TARGET } from "@blockchaincommons/known-values";
import {
  ProvenanceMarkGenerator,
  ProvenanceSeed,
  registerTags,
} from "@blockchaincommons/provenance-mark";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { hex, unhex, type Scheme, type SiblingDeps } from "./recipes";

const KDF: Record<string, string> = {
  hkdf: "HKDF",
  pbkdf2: "PBKDF2",
  scrypt: "Scrypt",
  argon2id: "Argon2id",
};
const pubOf = (p: any, scheme: Scheme | undefined): any =>
  scheme === "schnorr"
    ? p.schnorrPublicKeys()
    : scheme === "ecdsa"
      ? p.ecdsaPublicKeys()
      : p.ed25519PublicKeys();
const privOf = (p: any, scheme: Scheme | undefined): any =>
  scheme === "schnorr"
    ? p.schnorrPrivateKeys()
    : scheme === "ecdsa"
      ? p.ecdsaPrivateKeys()
      : p.ed25519PrivateKeys();
export async function baselineModule(): Promise<any> {
  const m: any = await import("../baseline/xid-baseline.mjs");
  // The bundle's own envelope and provenance-mark summarisers, as the test setup registers them.
  m.baselineRegisterTags();
  return m;
}

/**
 * Sibling operations over the frozen bundle's inlined siblings (the classes
 * the bundle's own code checks against), through the same API the working
 * tree's siblings expose.
 */
export function baselineDeps(m: any): SiblingDeps {
  return {
    pkbFromSeed: (seed) => m.PrivateKeyBase.from(unhex(seed)),
    pub: pubOf,
    priv: privOf,
    kdf: (k) => (k === undefined ? {} : { method: m.KeyDerivationMethod[KDF[k]] }),
    cborText: (s) => m.baselineCbor(s),
    envelopeFrom: (x) => m.Envelope.from(x),
    edgeEnvelope: (e) =>
      m.Envelope.from(e.subject)
        .addAssertion(m.IS_A, e.isA)
        .addAssertion(m.SOURCE, m.Envelope.from(e.source))
        .addAssertion(m.TARGET, m.Envelope.from(e.target)),
    format: (e) => m.formatEnvelope(e),
    cborHex: (e) => hex(e.toCbor().toData()),
    urString: (e) => e.toUR().toString(),
    digestHex: (e) => e.digest().toHex(),
    envelopeFromUR: (ur) => m.decodeURWith(m.UR.parse(ur), m.Envelope.codec),
    referenceHex: (r) => hex(r.bytes),
    xidHex: (x) => x.toHex(),
    kvName: (kv) => kv.name,
    kvValue: (kv) => String(kv.value),
    seed: (bytes) => m.ProvenanceSeed.from(bytes),
    resolution: (r) => r ?? "high",
    generatorFromPassphrase: (res, passphrase) =>
      m.ProvenanceMarkGenerator.fromPassphrase(res, passphrase),
    generatorFromSeed: (res, seed) => m.ProvenanceMarkGenerator.from({ res, seed }),
    markNext: (g, date, info) => g.next(date, info === undefined ? {} : { info }),
    markUR: (mark) => mark.toUR().toString(),
    generatorNextSeq: (g) => g.nextSeq,
    knownValueEnvelope: (value) => m.Envelope.knownValue(value),
    uri: (s) => m.URI.from(s),
    bytesValue: (bytes) => bytes,
    salt: (bytes) => m.Salt.from(bytes),
    assertionEnvelope: (p, o) => m.Envelope.assertion(p, o),
    addAssertionEnvelope: (e, a) => e.addAssertionEnvelope(a),
    wrap: (e) => e.wrap(),
    elide: (e) => e.elide(),
    sign: (e, privateKeys) => m.signEnvelope(e, privateKeys),
    generatorEnvelope: (g) => g.toEnvelope(),
    parseUR: (s) => m.UR.parse(s),
  };
}

/**
 * The working tree. Registers envelope's and provenance-mark's tags and
 * summarisers first, as the reference's tests call
 * `bc_envelope::register_tags()` and `provenance_mark::register_tags()`.
 */
export async function currentModule(): Promise<any> {
  registerTags();
  return await import("../../src");
}

/** Sibling operations over the working tree's siblings. */
export const currentDeps: SiblingDeps = {
  pkbFromSeed: (seed) => PrivateKeyBase.from(unhex(seed)),
  pub: pubOf,
  priv: privOf,
  kdf: (k) => (k === undefined ? {} : { method: (KeyDerivationMethod as any)[KDF[k]] }),
  cborText: (s) => cbor(s),
  envelopeFrom: (x) => Envelope.from(x),
  edgeEnvelope: (e) =>
    Envelope.from(e.subject)
      .addAssertion(IS_A, e.isA)
      .addAssertion(SOURCE, Envelope.from(e.source))
      .addAssertion(TARGET, Envelope.from(e.target)),
  format: (e) => format(e),
  cborHex: (e) => hex(e.toCbor().toData()),
  urString: (e) => e.toUR().toString(),
  digestHex: (e) => e.digest().toHex(),
  envelopeFromUR: (ur) => decodeURWith(UR.parse(ur), Envelope.codec),
  referenceHex: (r) => hex(r.bytes),
  xidHex: (x) => x.toHex(),
  kvName: (kv) => kv.name,
  kvValue: (kv) => String(kv.value),
  seed: (bytes) => ProvenanceSeed.from(bytes),
  resolution: (r) => r ?? "high",
  generatorFromPassphrase: (res, passphrase) =>
    ProvenanceMarkGenerator.fromPassphrase(res, passphrase),
  generatorFromSeed: (res, seed) => ProvenanceMarkGenerator.from({ res, seed }),
  markNext: (g, date, info) => g.next(date, info),
  markUR: (mark) => mark.toUR().toString(),
  generatorNextSeq: (g) => g.nextSeq,
  knownValueEnvelope: (value) => Envelope.knownValue(value),
  uri: (s) => URI.from(s),
  bytesValue: (bytes) => bytes,
  salt: (bytes) => Salt.from(bytes),
  assertionEnvelope: (p, o) => Envelope.assertion(p, o),
  addAssertionEnvelope: (e, a) => e.addAssertionEnvelope(a),
  wrap: (e) => e.wrap(),
  elide: (e) => e.elide(),
  sign: (e, privateKeys) => sign(e, privateKeys),
  generatorEnvelope: (g) => g.toEnvelope(),
  parseUR: (s) => UR.parse(s),
  cborDate: (s) => CborDate.fromString(s),
};
