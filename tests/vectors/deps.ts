/**
 * The module objects and sibling operations the adapters drive: the frozen
 * bundle (published pre-redesign siblings, inlined), or the working tree
 * with the redesigned siblings.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { PrivateKeyBase } from "@blockchaincommons/components";
import { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { cbor } from "@blockchaincommons/dcbor";
import { Envelope } from "@blockchaincommons/envelope";
import { format } from "@blockchaincommons/envelope/format";
import { IS_A, SOURCE, TARGET } from "@blockchaincommons/known-values";
import { ProvenanceMarkGenerator, ProvenanceSeed } from "@blockchaincommons/provenance-mark";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { hex, unhex, type EdgeSpec, type Scheme, type SiblingDeps } from "./recipes";

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
const RES_NAME: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  quartile: "Quartile",
  high: "High",
};

export async function baselineModule(): Promise<any> {
  return await import("../baseline/xid-baseline.mjs");
}

/** Sibling operations over the frozen bundle's inlined pre-redesign siblings. */
export function baselineDeps(m: any): SiblingDeps {
  const edge = (e: EdgeSpec): any =>
    m.Envelope.new(e.subject)
      .addAssertion(m.IS_A, e.isA)
      .addAssertion(m.SOURCE, m.Envelope.new(e.source))
      .addAssertion(m.TARGET, m.Envelope.new(e.target));
  return {
    pkbFromSeed: (seed) => m.PrivateKeyBase.fromData(unhex(seed)),
    pub: pubOf,
    priv: privOf,
    kdf: (k) => (k === undefined ? {} : { method: m.KeyDerivationMethod[KDF[k]] }),
    cborText: (s) => m.baselineCbor(s),
    envelopeFrom: (x) => m.Envelope.new(x),
    edgeEnvelope: edge,
    format: (e) => e.format(),
    cborHex: (e) => hex(e.taggedCborData()),
    urString: (e) => e.urString(),
    digestHex: (e) => e.digest().hex(),
    envelopeFromUR: (ur) => m.Envelope.fromURString(ur),
    referenceHex: (r) => hex(r.data()),
    xidHex: (x) => x.toHex(),
    kvName: (kv) => kv.name(),
    kvValue: (kv) => String(kv.value()),
    seed: (bytes) => m.ProvenanceSeed.fromBytes(bytes),
    resolution: (r) => m.ProvenanceMarkResolution[RES_NAME[r ?? "high"]],
    generatorFromPassphrase: (res, passphrase) =>
      m.ProvenanceMarkGenerator.newWithPassphrase(res, passphrase),
    generatorFromSeed: (res, seed) => m.ProvenanceMarkGenerator.newWithSeed(res, seed),
    markNext: (g, date, info) => g.next(date, info),
    markUR: (mark) => mark.urString(),
    generatorNextSeq: (g) => g.nextSeq(),
  };
}

export async function currentModule(): Promise<any> {
  return await import("../../src");
}

/** Sibling operations over the redesigned siblings. */
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
  markNext: (g, date, info) => g.next(date, info === undefined ? {} : { info }),
  markUR: (mark) => mark.toUR().toString(),
  generatorNextSeq: (g) => g.nextSeq,
};
