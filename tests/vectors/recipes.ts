/**
 * Vector recipes: a document recipe language (inception key, genesis mark,
 * resolution methods, keys, delegates, services, attachments, edges,
 * custom assertions) rendered with every private-key, generator and
 * signing option; documents decoded from a UR with each verification
 * mode; mutation scripts; single keys and provenance values; the
 * privilege table; hand-assembled envelopes, CBOR and URs fed to every
 * decoder; the nickname adders; construction-time inputs; and the
 * JavaScript input domain. `materialize` runs a recipe through a
 * `VectorApi` and returns one outcome string, so the same recipe drives
 * the golden file, the differential and the Rust harness.
 *
 * A rejection renders as `throw:<code>[<inner code>]|<message>`: the
 * error's code (its class name when it has none), the code of the error
 * it wraps for the codes whose reference variant wraps one, and the
 * message. The Rust harness renders the reference's errors the same way.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

export type Resolution = "low" | "medium" | "quartile" | "high";
export type Scheme = "ed25519" | "schnorr" | "ecdsa";
export type PrivilegeName =
  | "All"
  | "Auth"
  | "Sign"
  | "Encrypt"
  | "Elide"
  | "Issue"
  | "Access"
  | "Delegate"
  | "Verify"
  | "Update"
  | "Transfer"
  | "Elect"
  | "Burn"
  | "Revoke";
export const PRIVILEGES: readonly PrivilegeName[] = [
  "All",
  "Auth",
  "Sign",
  "Encrypt",
  "Elide",
  "Issue",
  "Access",
  "Delegate",
  "Verify",
  "Update",
  "Transfer",
  "Elect",
  "Burn",
  "Revoke",
];

export interface KeySpec {
  /** 32 bytes of hex: the PrivateKeyBase seed. */
  seed: string;
  scheme?: Scheme;
  /** Carry the private keys in the Key. */
  private?: boolean;
  nickname?: string;
  allow?: PrivilegeName[];
  deny?: PrivilegeName[];
  endpoints?: string[];
}
export interface ServiceSpec {
  uri: string;
  capability?: string;
  name?: string;
  /** Indices into `keys`; -1 is the inception key. */
  keys?: number[];
  /** Indices into `delegates`. */
  delegates?: number[];
  allow?: PrivilegeName[];
  deny?: PrivilegeName[];
}
export interface DelegateSpec {
  /** A resolved delegate: a nested document. */
  doc?: DocSpec;
  /** An unresolved delegate: the XID of a document with this inception seed. */
  xidSeed?: string;
  allow?: PrivilegeName[];
  deny?: PrivilegeName[];
  /**
   * Resolution methods added to the source document after the delegate
   * is built from it; the delegate's own copy does not see them.
   */
  laterResolution?: string[];
}
export interface AttachmentSpec {
  payload: string;
  vendor: string;
  conformsTo?: string;
}
export interface EdgeSpec {
  subject: string;
  isA: string;
  source: string;
  target: string;
}
export interface GenesisSpec {
  passphrase?: string;
  seed?: string;
  res?: Resolution;
  /** ISO 8601 UTC. */
  date?: string;
  info?: string;
}
export interface DocSpec {
  inception: {
    kind: "publicKeys" | "privateKeyBase" | "privateKeys" | "xid";
    seed: string;
    scheme?: Scheme;
    /** For `privateKeys`: the private keys come from this seed instead (a mismatched pair). */
    privateSeed?: string;
  };
  genesis?: GenesisSpec;
  resolution?: string[];
  keys?: KeySpec[];
  delegates?: DelegateSpec[];
  services?: ServiceSpec[];
  attachments?: AttachmentSpec[];
  edges?: EdgeSpec[];
  /** Extra assertions added on the envelope and preserved through parsing. */
  custom?: [string, string][];
}
export type Kdf = "hkdf" | "pbkdf2" | "scrypt" | "argon2id";
/** `encrypt` locks with a password; the KDF is the default (Argon2id) unless given. */
export type PrivOpt = "omit" | "include" | "elide" | { encrypt: string; method?: Kdf };
export type GenOpt = PrivOpt;
export type SignOpt = "none" | "inception" | { seed: string };
export interface OutputSpec {
  priv?: PrivOpt;
  gen?: GenOpt;
  sign?: SignOpt;
}
export type Verify = "none" | "inception";
export type Op =
  | ["removeKey", number]
  | ["takeKey", number]
  | ["removeInceptionKey"]
  | ["setNameForKey", number, string]
  | ["addKey", KeySpec]
  | ["addResolution", string]
  | ["removeResolution", string]
  | ["addService", ServiceSpec]
  | ["removeService", string]
  | ["takeService", string]
  | ["removeDelegate", number]
  | ["takeDelegate", number]
  | ["checkContainsKey", number]
  | ["checkContainsDelegate", number]
  | ["checkServices"]
  | ["clearAttachments"]
  | ["removeAttachment", number]
  | ["clearEdges"]
  | ["removeEdge", number]
  | ["nextMark", { date: string; info?: string; password?: string }]
  /**
   * The provided-generator form: a generator built from the document's
   * genesis (or the given one), kept across the script and advanced in
   * place; `fresh` uses a new one at the genesis mark instead.
   */
  | ["nextMarkProvided", { date: string; info?: string; genesis?: GenesisSpec; fresh?: boolean }]
  /** Keeps the mark, drops the generator (`setProvenance(mark)`). */
  | ["dropGenerator"]
  /** `removeEndpoint` on the key at this index (-1 the inception key). */
  | ["removeEndpoint", number, string]
  /** `removeKeyReference` on the service at this URI, of the key at this index. */
  | ["removeKeyReference", string, number]
  /** `removeDelegateReference` on the service at this URI, of the delegate at this index. */
  | ["removeDelegateReference", string, number]
  | ["clearProvenance"]
  | ["clone"];

/** The known values a hand-assembled envelope names, by name and value. */
export const KNOWN_VALUES: Record<string, number> = {
  isA: 1,
  note: 4,
  key: 8,
  dereferenceVia: 9,
  name: 11,
  salt: 15,
  nickname: 24,
  attachment: 50,
  allow: 60,
  deny: 61,
  endpoint: 62,
  delegate: 63,
  provenance: 64,
  privateKey: 65,
  service: 66,
  capability: 67,
  provenanceGenerator: 68,
  edge: 701,
  All: 70,
  Sign: 72,
};
export type KnownName = keyof typeof KNOWN_VALUES;

/**
 * An envelope assembled by hand: a leaf, a known value, a sibling value
 * built from a seed, a node with assertions, a wrapped, elided or signed
 * envelope, or a document's envelope.
 */
export type Obj =
  | { t: "text"; v: string }
  | { t: "int"; v: number }
  | { t: "kv"; name: KnownName }
  | { t: "uri"; v: string }
  | { t: "bytes"; hex: string }
  /** The XID of the document whose inception seed this is. */
  | { t: "xid"; seed: string }
  /** The reference of the public keys of this seed. */
  | { t: "ref"; seed: string; scheme?: Scheme }
  /** The reference of the XID of this seed's document. */
  | { t: "xidRef"; seed: string }
  | { t: "pub"; seed: string; scheme?: Scheme }
  | { t: "priv"; seed: string; scheme?: Scheme }
  | { t: "salt"; hex: string }
  | { t: "mark"; genesis: GenesisSpec }
  /** The envelope of the generator that produced a genesis mark. */
  | { t: "generatorEnv"; genesis: GenesisSpec }
  /** A document's envelope (private keys and generator omitted, unsigned). */
  | { t: "doc"; doc: DocSpec }
  | { t: "node"; subject: Obj; assertions: AssertionSpec[] }
  | { t: "wrapped"; inner: Obj }
  | { t: "elided"; inner: Obj }
  /** `inner.sign(privateKeys)`: wrapped, with a signature by this seed's Schnorr keys. */
  | { t: "signed"; inner: Obj; seed: string };
export interface AssertionSpec {
  pred: Obj;
  obj: Obj;
  /** Assertions on the assertion envelope itself (a `'salt'` beside a `'privateKey'`). */
  with?: AssertionSpec[];
  /** The assertion is added elided. */
  elide?: boolean;
}

export type DomainClass = "J1" | "J2" | "J3" | "J4";

export type Recipe =
  | { k: "doc"; doc: DocSpec; out?: OutputSpec }
  | { k: "decode"; ur: string; verify: Verify; password?: string }
  | { k: "mutate"; doc: DocSpec; ops: Op[] }
  | { k: "key"; key: KeySpec; priv: PrivOpt }
  /** With `take`, the generator is taken from the parsed value and what came out is reported. */
  | { k: "provenance"; genesis: GenesisSpec; gen: GenOpt; password?: string; take?: boolean }
  | { k: "privileges" }
  /**
   * A document envelope assembled by hand and parsed: the `base`
   * document's envelope (or a bare `subject`), the `assertions` added,
   * signed by each of `sign`'s Schnorr keys in turn, wrapped once more, the
   * `outer` assertions added, then `fromEnvelope` with `verify` and `password`.
   */
  | {
      k: "docEnvelope";
      base?: DocSpec;
      subject?: Obj;
      assertions?: AssertionSpec[];
      sign?: string[];
      wrap?: boolean;
      outer?: AssertionSpec[];
      verify?: Verify;
      password?: string;
    }
  | { k: "keyEnvelope"; subject: Obj; assertions?: AssertionSpec[]; password?: string }
  | { k: "serviceEnvelope"; subject: Obj; assertions?: AssertionSpec[] }
  | { k: "provenanceEnvelope"; subject: Obj; assertions?: AssertionSpec[]; password?: string }
  /** CBOR bytes given to the tagged decoder, the untagged decoder or the codec. */
  | { k: "cbor"; hex: string; via: "tagged" | "untagged" | "codec" }
  /** A UR string parsed and given to `fromUR`. */
  | { k: "ur"; s: string }
  /** `addNickname`/`setNickname` in sequence on a fresh key. */
  | { k: "nickname"; ops: ["add" | "set", string][] }
  /** A caller's input to a constructor, outside any decoder. */
  | { k: "construct"; op: "service" | "resolution" | "endpoint"; v: string }
  /** The JavaScript input domain; the reference has no analogue (`js-only`). */
  | { k: "domain"; case: string; cls: DomainClass };
export type Outcome = string;

/** What one rendered document reports, in a fixed order. */
export interface DocOutputs {
  format: string;
  /** Tagged CBOR hex, UR and digest hex; empty when the output draws randomness. */
  cbor: string;
  ur: string;
  digest: string;
  xid: string;
  reference: string;
  isEmpty: string;
  keys: string;
  inception: string;
  resolution: string;
  services: string;
  delegates: string;
  attachments: string;
  edges: string;
  provenance: string;
  generator: string;
  /** `fromEnvelope` of the output (with the password) equals the document. */
  roundtrip: string;
  /** `fromEnvelope` with inception-key verification: ok, or the error. */
  verify: string;
}

export interface VectorApi {
  doc(spec: DocSpec, out: OutputSpec): DocOutputs;
  decode(ur: string, verify: Verify, password: string | undefined): string;
  mutate(spec: DocSpec, ops: Op[]): string;
  key(spec: KeySpec, priv: PrivOpt): string;
  provenance(
    genesis: GenesisSpec,
    gen: GenOpt,
    password: string | undefined,
    take: boolean,
  ): string;
  privileges(): string;
  docEnvelope(r: Extract<Recipe, { k: "docEnvelope" }>): string;
  keyEnvelope(r: Extract<Recipe, { k: "keyEnvelope" }>): string;
  serviceEnvelope(r: Extract<Recipe, { k: "serviceEnvelope" }>): string;
  provenanceEnvelope(r: Extract<Recipe, { k: "provenanceEnvelope" }>): string;
  cbor(hex: string, via: "tagged" | "untagged" | "codec"): string;
  ur(s: string): string;
  nickname(ops: ["add" | "set", string][]): string;
  construct(op: Extract<Recipe, { k: "construct" }>["op"], v: string): string;
  domain(name: string): string;
  /** The error's code, with the wrapped error's code in brackets where the reference wraps one. */
  errorCode(e: unknown): string;
  errorMessage(e: unknown): string;
}

export const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");
export const unhex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const optName = (o: PrivOpt | undefined): string =>
  o === undefined
    ? "omit"
    : typeof o === "string"
      ? o
      : `encrypt(${o.encrypt}${o.method ? ` ${o.method}` : ""})`;
const signName = (o: SignOpt | undefined): string =>
  o === undefined ? "none" : typeof o === "string" ? o : `sign(${o.seed.slice(0, 8)})`;
export const docName = (d: DocSpec): string =>
  `${d.inception.kind}:${d.inception.seed.slice(0, 8)}${d.inception.privateSeed ? `+${d.inception.privateSeed.slice(0, 8)}` : ""}${d.inception.scheme ? `/${d.inception.scheme}` : ""}` +
  (d.genesis
    ? ` genesis(${d.genesis.res ?? "high"} ${d.genesis.passphrase !== undefined ? `"${d.genesis.passphrase}"` : d.genesis.seed?.slice(0, 8)}${d.genesis.date ? ` ${d.genesis.date}` : ""}${d.genesis.info ? " info" : ""})`
    : "") +
  (d.resolution?.length ? ` res×${d.resolution.length}` : "") +
  (d.keys?.length ? ` keys×${d.keys.length}` : "") +
  (d.delegates?.length ? ` delegates×${d.delegates.length}` : "") +
  (d.delegates?.some((x) => x.laterResolution?.length) ? " later" : "") +
  (d.services?.length ? ` services×${d.services.length}` : "") +
  (d.attachments?.length ? ` attachments×${d.attachments.length}` : "") +
  (d.edges?.length ? ` edges×${d.edges.length}` : "") +
  (d.custom?.length ? ` custom×${d.custom.length}` : "");

export const objName = (o: Obj): string => {
  switch (o.t) {
    case "text":
      return JSON.stringify(o.v);
    case "int":
      return String(o.v);
    case "kv":
      return `'${o.name}'`;
    case "uri":
      return `uri(${o.v})`;
    case "bytes":
      return `h'${o.hex.slice(0, 16)}${o.hex.length > 16 ? "…" : ""}'`;
    case "xid":
      return `xid(${o.seed.slice(0, 8)})`;
    case "ref":
      return `ref(${o.seed.slice(0, 8)}${o.scheme ? `/${o.scheme}` : ""})`;
    case "xidRef":
      return `xidRef(${o.seed.slice(0, 8)})`;
    case "pub":
      return `pub(${o.seed.slice(0, 8)}${o.scheme ? `/${o.scheme}` : ""})`;
    case "priv":
      return `priv(${o.seed.slice(0, 8)}${o.scheme ? `/${o.scheme}` : ""})`;
    case "salt":
      return `salt(${o.hex.slice(0, 8)})`;
    case "mark":
      return `mark(${o.genesis.res ?? "high"})`;
    case "generatorEnv":
      return `generator(${o.genesis.res ?? "high"})`;
    case "doc":
      return `doc(${docName(o.doc)})`;
    case "node":
      return `${objName(o.subject)}[${o.assertions.map(assertionName).join(",")}]`;
    case "wrapped":
      return `{${objName(o.inner)}}`;
    case "elided":
      return `elided(${objName(o.inner)})`;
    case "signed":
      return `signed(${objName(o.inner)},${o.seed.slice(0, 8)})`;
  }
};
export const assertionName = (a: AssertionSpec): string =>
  `${a.elide === true ? "elided " : ""}${objName(a.pred)}:${objName(a.obj)}` +
  (a.with === undefined ? "" : `[${a.with.map(assertionName).join(",")}]`);
const assertionsName = (as: AssertionSpec[] | undefined): string =>
  as === undefined || as.length === 0 ? "" : ` +${as.map(assertionName).join(",")}`;

export function recipeName(r: Recipe): string {
  switch (r.k) {
    case "doc":
      return `doc ${docName(r.doc)} [${optName(r.out?.priv)}/${optName(r.out?.gen)}/${signName(r.out?.sign)}]`;
    case "decode":
      return `decode ${r.verify}${r.password !== undefined ? " pw" : ""} ${r.ur.slice(0, 40)}`;
    case "mutate":
      return `mutate ${docName(r.doc)}: ${r.ops.map((o) => (o[0] === "nextMarkProvided" && o[1].fresh === true ? "nextMarkProvided(fresh)" : o[0])).join(",")}`;
    case "key":
      return `key ${r.key.seed.slice(0, 8)}${r.key.scheme ? `/${r.key.scheme}` : ""}${r.key.private ? " private" : ""} [${optName(r.priv)}]`;
    case "provenance":
      return `provenance ${r.genesis.res ?? "high"} ${r.genesis.passphrase !== undefined ? `"${r.genesis.passphrase}"` : r.genesis.seed?.slice(0, 8)} [${optName(r.gen)}]${r.password !== undefined ? " pw" : ""}${r.take === true ? " take" : ""}`;
    case "privileges":
      return "privileges";
    case "docEnvelope":
      return (
        `docEnvelope ${r.base !== undefined ? docName(r.base) : r.subject !== undefined ? objName(r.subject) : "?"}` +
        assertionsName(r.assertions) +
        (r.sign !== undefined ? ` signed(${r.sign.map((x) => x.slice(0, 8)).join(",")})` : "") +
        (r.wrap === true ? " wrapped" : "") +
        (r.outer !== undefined ? ` outer${assertionsName(r.outer)}` : "") +
        ` [${r.verify ?? "none"}${r.password !== undefined ? " pw" : ""}]`
      );
    case "keyEnvelope":
      return `keyEnvelope ${objName(r.subject)}${assertionsName(r.assertions)}${r.password !== undefined ? " [pw]" : ""}`;
    case "serviceEnvelope":
      return `serviceEnvelope ${objName(r.subject)}${assertionsName(r.assertions)}`;
    case "provenanceEnvelope":
      return `provenanceEnvelope ${objName(r.subject)}${assertionsName(r.assertions)}${r.password !== undefined ? " [pw]" : ""}`;
    case "cbor":
      return `cbor ${r.via} ${r.hex.slice(0, 24)}${r.hex.length > 24 ? "…" : ""}`;
    case "ur":
      return `ur ${r.s.slice(0, 40)}`;
    case "nickname":
      return `nickname ${r.ops.map(([op, v]) => `${op}(${JSON.stringify(v)})`).join(",")}`;
    case "construct":
      return `construct ${r.op}(${JSON.stringify(r.v)})`;
    case "domain":
      return `domain ${r.case} (${r.cls})`;
  }
}

const objUsesSalt = (o: Obj): boolean =>
  o.t === "salt" ||
  (o.t === "node" && (objUsesSalt(o.subject) || o.assertions.some(assertionUsesSalt))) ||
  ((o.t === "wrapped" || o.t === "elided" || o.t === "signed") && objUsesSalt(o.inner));
const assertionUsesSalt = (a: AssertionSpec): boolean =>
  objUsesSalt(a.pred) || objUsesSalt(a.obj) || (a.with ?? []).some(assertionUsesSalt);

/**
 * The frozen bundle cannot decode raw CBOR bytes, exports no `Salt` and has
 * no JavaScript-domain guards to compare.
 */
export const isBaselineSupported = (r: Recipe): boolean => r.k !== "domain";

export const render = (o: Record<string, string>): string =>
  Object.keys(o)
    .map((k) => `${k}=${o[k]}`)
    .join("\n");

export const thrown = (api: VectorApi, e: unknown): string =>
  `throw:${api.errorCode(e)}|${api.errorMessage(e)}`;

export function materialize(api: VectorApi, r: Recipe): Outcome {
  try {
    switch (r.k) {
      case "doc":
        return render(api.doc(r.doc, r.out ?? {}) as unknown as Record<string, string>);
      case "decode":
        return api.decode(r.ur, r.verify, r.password);
      case "mutate":
        return api.mutate(r.doc, r.ops);
      case "key":
        return api.key(r.key, r.priv);
      case "provenance":
        return api.provenance(r.genesis, r.gen, r.password, r.take === true);
      case "privileges":
        return api.privileges();
      case "docEnvelope":
        return api.docEnvelope(r);
      case "keyEnvelope":
        return api.keyEnvelope(r);
      case "serviceEnvelope":
        return api.serviceEnvelope(r);
      case "provenanceEnvelope":
        return api.provenanceEnvelope(r);
      case "cbor":
        return api.cbor(r.hex, r.via);
      case "ur":
        return api.ur(r.s);
      case "nickname":
        return api.nickname(r.ops);
      case "construct":
        return api.construct(r.op, r.v);
      case "domain":
        return api.domain(r.case);
    }
  } catch (e) {
    return thrown(api, e);
  }
}

/** `try` a step and report ok, a value, or the error. */
export const attempt = (api: VectorApi, f: () => string | undefined | void): string => {
  try {
    const v = f();
    return v === undefined ? "ok" : v;
  } catch (e) {
    return thrown(api, e);
  }
};

/**
 * The sibling operations an adapter needs, bound either to the frozen bundle
 * (the published siblings it inlines) or to the working tree's siblings.
 */
export interface SiblingDeps {
  pkbFromSeed(seed: string): any;
  pub(pkb: any, scheme: Scheme | undefined): any;
  priv(pkb: any, scheme: Scheme | undefined): any;
  kdf(method: Kdf | undefined): { method?: any };
  cborText(s: string): any;
  envelopeFrom(subject: any): any;
  edgeEnvelope(e: EdgeSpec): any;
  format(envelope: any): string;
  cborHex(envelope: any): string;
  urString(envelope: any): string;
  digestHex(envelope: any): string;
  envelopeFromUR(ur: string): any;
  referenceHex(ref: any): string;
  xidHex(xid: any): string;
  kvName(kv: any): string;
  kvValue(kv: any): string;
  seed(bytes: Uint8Array): any;
  resolution(r: Resolution | undefined): any;
  generatorFromPassphrase(res: any, passphrase: string): any;
  generatorFromSeed(res: any, seed: any): any;
  markNext(generator: any, date: Date, info: any | undefined): any;
  markUR(mark: any): string;
  generatorNextSeq(generator: any): number;
  /** Hand-assembled envelopes. */
  knownValueEnvelope(value: number): any;
  uri(s: string): any;
  bytesValue(bytes: Uint8Array): any;
  salt(bytes: Uint8Array): any;
  assertionEnvelope(predicate: any, object: any): any;
  addAssertionEnvelope(envelope: any, assertion: any): any;
  wrap(envelope: any): any;
  elide(envelope: any): any;
  sign(envelope: any, privateKeys: any): any;
  generatorEnvelope(generator: any): any;
  /** The UR string parsed into a UR value (the grammar step). */
  parseUR(s: string): any;
  /** A `CborDate` from its string. */
  cborDate?(s: string): any;
}
