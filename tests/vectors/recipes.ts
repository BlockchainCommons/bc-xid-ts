/**
 * Vector recipes (Phase 1.1): a document recipe language (inception key,
 * genesis mark, resolution methods, keys, delegates, services, attachments,
 * edges, custom assertions) rendered with every private-key, generator and
 * signing option; documents decoded from a UR with each verification mode;
 * mutation scripts; single keys and provenance values; the privilege
 * table. `materialize` runs a recipe through a `VectorApi` and returns one
 * outcome string, so the same recipe drives the golden file, the
 * differential and the Rust harness.
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
  | ["clearProvenance"]
  | ["clone"];

export type Recipe =
  | { k: "doc"; doc: DocSpec; out?: OutputSpec }
  | { k: "decode"; ur: string; verify: Verify; password?: string }
  | { k: "mutate"; doc: DocSpec; ops: Op[] }
  | { k: "key"; key: KeySpec; priv: PrivOpt }
  | { k: "provenance"; genesis: GenesisSpec; gen: GenOpt; password?: string }
  | { k: "privileges" };
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
  /** `fromEnvelope` with inception-key verification: ok, or the error code. */
  verify: string;
}

export interface VectorApi {
  doc(spec: DocSpec, out: OutputSpec): DocOutputs;
  decode(ur: string, verify: Verify, password: string | undefined): string;
  mutate(spec: DocSpec, ops: Op[]): string;
  key(spec: KeySpec, priv: PrivOpt): string;
  provenance(genesis: GenesisSpec, gen: GenOpt, password: string | undefined): string;
  privileges(): string;
  /** The error variant name. */
  errorCode(e: unknown): string | undefined;
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
  `${d.inception.kind}:${d.inception.seed.slice(0, 8)}${d.inception.scheme ? `/${d.inception.scheme}` : ""}` +
  (d.genesis
    ? ` genesis(${d.genesis.res ?? "high"} ${d.genesis.passphrase !== undefined ? `"${d.genesis.passphrase}"` : d.genesis.seed?.slice(0, 8)}${d.genesis.date ? ` ${d.genesis.date}` : ""}${d.genesis.info ? " info" : ""})`
    : "") +
  (d.resolution?.length ? ` res×${d.resolution.length}` : "") +
  (d.keys?.length ? ` keys×${d.keys.length}` : "") +
  (d.delegates?.length ? ` delegates×${d.delegates.length}` : "") +
  (d.services?.length ? ` services×${d.services.length}` : "") +
  (d.attachments?.length ? ` attachments×${d.attachments.length}` : "") +
  (d.edges?.length ? ` edges×${d.edges.length}` : "") +
  (d.custom?.length ? ` custom×${d.custom.length}` : "");

export function recipeName(r: Recipe): string {
  switch (r.k) {
    case "doc":
      return `doc ${docName(r.doc)} [${optName(r.out?.priv)}/${optName(r.out?.gen)}/${signName(r.out?.sign)}]`;
    case "decode":
      return `decode ${r.verify}${r.password !== undefined ? " pw" : ""} ${r.ur.slice(0, 40)}`;
    case "mutate":
      return `mutate ${docName(r.doc)}: ${r.ops.map((o) => o[0]).join(",")}`;
    case "key":
      return `key ${r.key.seed.slice(0, 8)}${r.key.scheme ? `/${r.key.scheme}` : ""}${r.key.private ? " private" : ""} [${optName(r.priv)}]`;
    case "provenance":
      return `provenance ${r.genesis.res ?? "high"} ${r.genesis.passphrase !== undefined ? `"${r.genesis.passphrase}"` : r.genesis.seed?.slice(0, 8)} [${optName(r.gen)}]${r.password !== undefined ? " pw" : ""}`;
    case "privileges":
      return "privileges";
  }
}

const render = (o: Record<string, string>): string =>
  Object.keys(o)
    .map((k) => `${k}=${o[k]}`)
    .join("\n");

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
        return api.provenance(r.genesis, r.gen, r.password);
      case "privileges":
        return api.privileges();
    }
  } catch (e) {
    return `throw:${api.errorCode(e) ?? engineNeutral(e)}`;
  }
}

/** `try` a step and report ok, a value, or the error code. */
export const attempt = (api: VectorApi, f: () => string | undefined | void): string => {
  try {
    const v = f();
    return v === undefined ? "ok" : v;
  } catch (e) {
    return `throw:${api.errorCode(e) ?? engineNeutral(e)}`;
  }
};

/** Engine errors (a TypeError from a bad recipe) word their messages per engine; report the name. */
const engineNeutral = (e: unknown): string =>
  e instanceof TypeError || e instanceof RangeError ? e.name : (e as Error).message;

/**
 * The sibling operations an adapter needs, bound either to the frozen bundle
 * (the published pre-redesign siblings) or to the redesigned siblings.
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
}

/**
 * Pre-redesign surface of this package (the working tree speaks it until
 * Phase 3 lands): `XIDDocument.new(inception, genesis)`, zero-argument
 * accessors, `toEnvelope(privOpt, genOpt, signOpt)`, enums for the options.
 */
export function baselineAdapterFor(m: any, d: SiblingDeps): VectorApi {
  const pkb = d.pkbFromSeed;
  const pub = d.pub;
  const priv = d.priv;
  const privilege = (n: PrivilegeName): any => m.Privilege[n];
  const permissions = (obj: any, allow?: PrivilegeName[], deny?: PrivilegeName[]): void => {
    for (const p of allow ?? []) obj.permissions().addAllow(privilege(p));
    for (const p of deny ?? []) obj.permissions().addDeny(privilege(p));
  };
  const genesis = (g: GenesisSpec | undefined): any => {
    if (g === undefined) return { type: "none" };
    const common = {
      resolution: d.resolution(g.res),
      ...(g.date !== undefined ? { date: new Date(g.date) } : {}),
      ...(g.info !== undefined ? { info: d.cborText(g.info) } : {}),
    };
    return g.passphrase !== undefined
      ? { type: "passphrase", passphrase: g.passphrase, ...common }
      : { type: "seed", seed: unhex(g.seed ?? ""), ...common };
  };
  const privOpt = (o: PrivOpt | undefined): any =>
    o === undefined || o === "omit"
      ? m.XIDPrivateKeyOptions.Omit
      : o === "include"
        ? m.XIDPrivateKeyOptions.Include
        : o === "elide"
          ? m.XIDPrivateKeyOptions.Elide
          : { type: m.XIDPrivateKeyOptions.Encrypt, password: utf8(o.encrypt), ...d.kdf(o.method) };
  const genOpt = (o: GenOpt | undefined): any =>
    o === undefined || o === "omit"
      ? m.XIDGeneratorOptions.Omit
      : o === "include"
        ? m.XIDGeneratorOptions.Include
        : o === "elide"
          ? m.XIDGeneratorOptions.Elide
          : { type: m.XIDGeneratorOptions.Encrypt, password: utf8(o.encrypt), ...d.kdf(o.method) };
  const signOpt = (o: SignOpt | undefined): any =>
    o === undefined || o === "none"
      ? { type: "none" }
      : o === "inception"
        ? { type: "inception" }
        : { type: "privateKeys", privateKeys: priv(pkb(o.seed), "schnorr") };
  const password = (out: OutputSpec): Uint8Array | undefined => {
    const p = out.priv;
    const g = out.gen;
    const pw = typeof p === "object" ? p.encrypt : typeof g === "object" ? g.encrypt : undefined;
    return pw === undefined ? undefined : utf8(pw);
  };
  const makeKey = (k: KeySpec): any => {
    const p = pkb(k.seed);
    const key = k.private
      ? m.Key.newWithPrivateKeys(priv(p, k.scheme), pub(p, k.scheme))
      : m.Key.new(pub(p, k.scheme));
    if (k.nickname !== undefined) key.setNickname(k.nickname);
    for (const e of k.endpoints ?? []) key.addEndpoint(e);
    permissions(key, k.allow, k.deny);
    return key;
  };
  const xidOf = (seed: string): any =>
    m.XIDDocument.new(
      { type: "publicKeys", publicKeys: pub(pkb(seed), undefined) },
      { type: "none" },
    ).xid();
  const build = (spec: DocSpec): { doc: any; delegates: any[] } => {
    const p = pkb(spec.inception.seed);
    const scheme = spec.inception.scheme;
    let doc: any;
    switch (spec.inception.kind) {
      case "publicKeys":
        doc = m.XIDDocument.new(
          { type: "publicKeys", publicKeys: pub(p, scheme) },
          genesis(spec.genesis),
        );
        break;
      case "privateKeyBase":
        doc = m.XIDDocument.new(
          { type: "privateKeyBase", privateKeyBase: p },
          genesis(spec.genesis),
        );
        break;
      case "privateKeys":
        doc = m.XIDDocument.new(
          { type: "privateKeys", privateKeys: priv(p, scheme), publicKeys: pub(p, scheme) },
          genesis(spec.genesis),
        );
        break;
      case "xid":
        doc = m.XIDDocument.fromXid(xidOf(spec.inception.seed));
        break;
    }
    for (const r of spec.resolution ?? []) doc.addResolutionMethod(r);
    for (const k of spec.keys ?? []) doc.addKey(makeKey(k));
    const delegates: any[] = [];
    for (const ds of spec.delegates ?? []) {
      const controller =
        ds.doc !== undefined ? build(ds.doc).doc : m.XIDDocument.fromXid(xidOf(ds.xidSeed ?? ""));
      const delegate = m.Delegate.new(controller);
      permissions(delegate, ds.allow, ds.deny);
      doc.addDelegate(delegate);
      delegates.push(delegate);
    }
    for (const s of spec.services ?? []) doc.addService(makeService(spec, s, delegates));
    for (const a of spec.attachments ?? []) doc.addAttachment(a.payload, a.vendor, a.conformsTo);
    for (const e of spec.edges ?? []) doc.addEdge(d.edgeEnvelope(e));
    if (spec.custom?.length) {
      let env = doc.toEnvelope(m.XIDPrivateKeyOptions.Omit, m.XIDGeneratorOptions.Omit, {
        type: "none",
      });
      for (const [k, v] of spec.custom) env = env.addAssertion(k, v);
      doc = m.XIDDocument.tryFromEnvelope(env);
    }
    return { doc, delegates };
  };
  const makeService = (spec: DocSpec, s: ServiceSpec, delegates: any[]): any => {
    const service = m.Service.new(s.uri);
    if (s.capability !== undefined) service.addCapability(s.capability);
    if (s.name !== undefined) service.setName(s.name);
    for (const i of s.keys ?? []) {
      const seed = i < 0 ? spec.inception.seed : (spec.keys?.[i]?.seed ?? spec.inception.seed);
      const scheme =
        i < 0
          ? spec.inception.kind === "privateKeyBase"
            ? "schnorr"
            : spec.inception.scheme
          : spec.keys?.[i]?.scheme;
      service.addKeyReference(pub(pkb(seed), scheme).reference());
    }
    for (const i of s.delegates ?? []) service.addDelegateReference(delegates[i].reference());
    permissions(service, s.allow, s.deny);
    return service;
  };
  const verifyOf = (o: SignOpt | undefined): any =>
    o === undefined || o === "none" ? m.XIDVerifySignature.None : m.XIDVerifySignature.Inception;
  const sortedUris = (set: Iterable<any>): string =>
    [...set]
      .map((u) => u.toString())
      .sort()
      .join(",");
  const omitEnvelope = (doc: any): any =>
    doc.toEnvelope(m.XIDPrivateKeyOptions.Omit, m.XIDGeneratorOptions.Omit, { type: "none" });
  const outputsFor = (doc: any, out: OutputSpec): DocOutputs => {
    const env = doc.toEnvelope(privOpt(out.priv), genOpt(out.gen), signOpt(out.sign));
    const deterministic =
      (out.priv ?? "omit") === "omit" &&
      (out.gen ?? "omit") === "omit" &&
      (out.sign ?? "none") === "none";
    const pw = password(out);
    const inception = doc.inceptionKey();
    const prov = doc.provenance();
    const gen = doc.provenanceGenerator();
    return {
      format: d.format(env),
      cbor: deterministic ? d.cborHex(env) : "",
      ur: deterministic ? d.urString(env) : "",
      digest: deterministic ? d.digestHex(env) : "",
      xid: d.xidHex(doc.xid()),
      reference: d.referenceHex(doc.reference()),
      isEmpty: String(doc.isEmpty()),
      keys: String(doc.keys().length),
      inception:
        inception === undefined
          ? "-"
          : `${d.referenceHex(inception.reference())}${inception.hasPrivateKeys() ? " private" : ""}`,
      resolution: sortedUris(doc.resolutionMethods()),
      services: doc
        .services()
        .map((s: any) => s.uriString())
        .sort()
        .join(","),
      delegates: doc
        .delegates()
        .map((x: any) => d.xidHex(x.xid()).slice(0, 8))
        .sort()
        .join(","),
      attachments: String(doc.getAttachments().len()),
      edges: String(doc.edges().len()),
      provenance: prov === undefined ? "-" : d.markUR(prov),
      generator: gen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(gen)}`,
      roundtrip: attempt(api, () =>
        String(m.XIDDocument.fromEnvelope(env, pw, verifyOf(out.sign)).equals(doc)),
      ),
      verify: attempt(api, () => {
        m.XIDDocument.fromEnvelope(env, pw, m.XIDVerifySignature.Inception);
      }),
    };
  };
  const api: VectorApi = {
    doc: (spec, out) => outputsFor(build(spec).doc, out),
    decode: (ur, verify, pw) => {
      const env = d.envelopeFromUR(ur);
      const doc = m.XIDDocument.fromEnvelope(
        env,
        pw === undefined ? undefined : utf8(pw),
        verify === "none" ? m.XIDVerifySignature.None : m.XIDVerifySignature.Inception,
      );
      return d.format(omitEnvelope(doc));
    },
    mutate: (spec, ops) => {
      const built = build(spec);
      let doc = built.doc;
      const inceptionScheme =
        spec.inception.kind === "privateKeyBase" ? "schnorr" : spec.inception.scheme;
      const keyPub = (i: number): any =>
        i < 0
          ? pub(pkb(spec.inception.seed), inceptionScheme)
          : pub(pkb(spec.keys?.[i]?.seed ?? spec.inception.seed), spec.keys?.[i]?.scheme);
      const lines: string[] = [];
      for (const op of ops) {
        const line = attempt(api, () => {
          switch (op[0]) {
            case "removeKey":
              doc.removeKey(keyPub(op[1]));
              return;
            case "takeKey": {
              const k = doc.takeKey(keyPub(op[1]));
              return k === undefined ? "undefined" : d.referenceHex(k.reference());
            }
            case "removeInceptionKey": {
              const k = doc.removeInceptionKey();
              return k === undefined ? "undefined" : d.referenceHex(k.reference());
            }
            case "setNameForKey":
              doc.setNameForKey(keyPub(op[1]), op[2]);
              return;
            case "addKey":
              doc.addKey(makeKey(op[1]));
              return;
            case "addResolution":
              doc.addResolutionMethod(op[1]);
              return;
            case "removeResolution":
              return String(doc.removeResolutionMethod(op[1]));
            case "addService":
              doc.addService(makeService(spec, op[1], built.delegates));
              return;
            case "removeService":
              doc.removeService(op[1]);
              return;
            case "takeService": {
              const s = doc.takeService(op[1]);
              return s === undefined ? "undefined" : s.uriString();
            }
            case "removeDelegate":
              doc.removeDelegate(built.delegates[op[1]].xid());
              return;
            case "takeDelegate": {
              const x = doc.takeDelegate(built.delegates[op[1]].xid());
              return x === undefined ? "undefined" : d.xidHex(x.xid()).slice(0, 8);
            }
            case "checkContainsKey":
              doc.checkContainsKey(keyPub(op[1]));
              return;
            case "checkContainsDelegate":
              doc.checkContainsDelegate(built.delegates[op[1]].xid());
              return;
            case "checkServices":
              doc.checkServicesConsistency();
              return;
            case "clearAttachments":
              doc.clearAttachments();
              return;
            case "removeAttachment": {
              const digests = [...doc.getAttachments().iter()].map((a: any) =>
                (Array.isArray(a) ? a[1] : a).digest(),
              );
              const removed = doc.removeAttachment(digests[op[1]]);
              return removed === undefined ? "undefined" : "removed";
            }
            case "clearEdges":
              doc.clearEdges();
              return;
            case "removeEdge": {
              const digests = [...doc.edges().iter()].map((e: any) =>
                (Array.isArray(e) ? e[1] : e).digest(),
              );
              const removed = doc.removeEdge(digests[op[1]]);
              return removed === undefined ? "undefined" : "removed";
            }
            case "nextMark":
              doc.nextProvenanceMarkWithEmbeddedGenerator(
                op[1].password === undefined ? undefined : utf8(op[1].password),
                new Date(op[1].date),
                op[1].info === undefined ? undefined : d.cborText(op[1].info),
              );
              return;
            case "clearProvenance":
              doc.setProvenance(undefined);
              return;
            case "clone":
              doc = doc.clone();
              return;
          }
        });
        lines.push(`${op[0]}=${line}`);
      }
      return `${lines.join("\n")}\n===\n${d.format(omitEnvelope(doc))}`;
    },
    key: (spec, privOption) => {
      const key = makeKey(spec);
      const env = key.intoEnvelopeOpt(privOpt(privOption));
      const pw = typeof privOption === "object" ? utf8(privOption.encrypt) : undefined;
      const back = m.Key.tryFromEnvelope(env, pw);
      const deterministic = privOption === "omit";
      return render({
        format: d.format(env),
        cbor: deterministic ? d.cborHex(env) : "",
        reference: d.referenceHex(key.reference()),
        roundtrip: String(key.equals(back)),
        private: String(back.hasPrivateKeys()),
        encrypted: String(back.hasEncryptedPrivateKeys()),
        nickname: back.nickname(),
        endpoints: sortedUris(back.endpoints()),
      });
    },
    provenance: (g, gen, pw) => {
      const res = d.resolution(g.res);
      const generator =
        g.passphrase !== undefined
          ? d.generatorFromPassphrase(res, g.passphrase)
          : d.generatorFromSeed(res, d.seed(unhex(g.seed ?? "")));
      const mark = d.markNext(
        generator,
        new Date(g.date ?? "2025-01-01T00:00:00Z"),
        g.info === undefined ? undefined : d.cborText(g.info),
      );
      const provenance = m.Provenance.newWithGenerator(generator, mark);
      const env = provenance.intoEnvelopeOpt(genOpt(gen));
      const back = m.Provenance.tryFromEnvelope(env, pw === undefined ? undefined : utf8(pw));
      const backGen = back.generator();
      return render({
        format: d.format(env),
        cbor: gen === "omit" ? d.cborHex(env) : "",
        mark: d.markUR(mark),
        roundtrip: String(provenance.equals(back)),
        generator: backGen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(backGen)}`,
        encrypted: String(back.hasEncryptedGenerator()),
      });
    },
    privileges: () =>
      PRIVILEGES.map((p) => {
        const kv = m.privilegeToKnownValue(privilege(p));
        return `${p}=${d.kvName(kv)}(${d.kvValue(kv)}) ${d.format(m.privilegeToEnvelope(privilege(p)))}`;
      }).join("\n"),
    errorCode: (e) => {
      const x: any = e;
      if (x?.name === "XIDError" || x?.constructor?.name === "XIDError") return String(x.code);
      return undefined;
    },
  };
  return api;
}

/**
 * Redesigned surface (Phase 3): `XIDDocument.from({ inceptionKey, genesis })`,
 * getters, `toEnvelope({ privateKeys, generator, sign })`,
 * `fromEnvelope(envelope, { password, verify })`, `Key.from`, `Service.from`,
 * `Delegate.from`, `Provenance.from`, string options, PascalCase error codes
 * (reported in the baseline's UPPER_SNAKE spelling).
 */
export function redesignedAdapterFor(m: any, d: SiblingDeps): VectorApi {
  if (typeof m.XIDDocument?.from !== "function") return baselineAdapterFor(m, d);
  const pkb = d.pkbFromSeed;
  const pub = d.pub;
  const priv = d.priv;
  const permissions = (obj: any, allow?: PrivilegeName[], deny?: PrivilegeName[]): void => {
    for (const p of allow ?? []) obj.allow(p);
    for (const p of deny ?? []) obj.deny(p);
  };
  const genesis = (g: GenesisSpec | undefined): any =>
    g === undefined
      ? undefined
      : {
          ...(g.passphrase !== undefined
            ? { passphrase: g.passphrase }
            : { seed: unhex(g.seed ?? "") }),
          resolution: d.resolution(g.res),
          ...(g.date !== undefined ? { date: new Date(g.date) } : {}),
          ...(g.info !== undefined ? { info: d.cborText(g.info) } : {}),
        };
  const opt = (o: PrivOpt | undefined): any =>
    o === undefined
      ? "omit"
      : typeof o === "string"
        ? o
        : { encrypt: o.encrypt, ...d.kdf(o.method) };
  const signOpt = (o: SignOpt | undefined): any =>
    o === undefined || o === "none"
      ? "none"
      : o === "inception"
        ? "inception"
        : priv(pkb(o.seed), "schnorr");
  const password = (out: OutputSpec): string | undefined => {
    const p = out.priv;
    const g = out.gen;
    return typeof p === "object" ? p.encrypt : typeof g === "object" ? g.encrypt : undefined;
  };
  const makeKey = (k: KeySpec): any => {
    const p = pkb(k.seed);
    const key = m.Key.from(pub(p, k.scheme), k.private ? { privateKeys: priv(p, k.scheme) } : {});
    if (k.nickname !== undefined) key.setNickname(k.nickname);
    for (const e of k.endpoints ?? []) key.addEndpoint(e);
    permissions(key, k.allow, k.deny);
    return key;
  };
  const xidOf = (seed: string): any =>
    m.XIDDocument.from({ inceptionKey: pub(pkb(seed), undefined) }).xid;
  const build = (spec: DocSpec): { doc: any; delegates: any[] } => {
    const p = pkb(spec.inception.seed);
    const scheme = spec.inception.scheme;
    let doc: any;
    switch (spec.inception.kind) {
      case "publicKeys":
        doc = m.XIDDocument.from({ inceptionKey: pub(p, scheme), genesis: genesis(spec.genesis) });
        break;
      case "privateKeyBase":
        doc = m.XIDDocument.from({ inceptionKey: p, genesis: genesis(spec.genesis) });
        break;
      case "privateKeys":
        doc = m.XIDDocument.from({
          inceptionKey: { publicKeys: pub(p, scheme), privateKeys: priv(p, scheme) },
          genesis: genesis(spec.genesis),
        });
        break;
      case "xid":
        doc = m.XIDDocument.fromXid(xidOf(spec.inception.seed));
        break;
    }
    for (const r of spec.resolution ?? []) doc.addResolutionMethod(r);
    for (const k of spec.keys ?? []) doc.addKey(makeKey(k));
    const delegates: any[] = [];
    for (const ds of spec.delegates ?? []) {
      const controller =
        ds.doc !== undefined ? build(ds.doc).doc : m.XIDDocument.fromXid(xidOf(ds.xidSeed ?? ""));
      const delegate = m.Delegate.from(controller);
      permissions(delegate, ds.allow, ds.deny);
      doc.addDelegate(delegate);
      delegates.push(delegate);
    }
    for (const s of spec.services ?? []) doc.addService(makeService(spec, s, delegates));
    for (const a of spec.attachments ?? []) doc.addAttachment(a.payload, a.vendor, a.conformsTo);
    for (const e of spec.edges ?? []) doc.addEdge(d.edgeEnvelope(e));
    if (spec.custom?.length) {
      let env = doc.toEnvelope();
      for (const [k, v] of spec.custom) env = env.addAssertion(k, v);
      doc = m.XIDDocument.fromEnvelope(env);
    }
    return { doc, delegates };
  };
  const makeService = (spec: DocSpec, s: ServiceSpec, delegates: any[]): any => {
    const service = m.Service.from(s.uri);
    if (s.capability !== undefined) service.addCapability(s.capability);
    if (s.name !== undefined) service.setName(s.name);
    for (const i of s.keys ?? []) {
      const seed = i < 0 ? spec.inception.seed : (spec.keys?.[i]?.seed ?? spec.inception.seed);
      const scheme =
        i < 0
          ? spec.inception.kind === "privateKeyBase"
            ? "schnorr"
            : spec.inception.scheme
          : spec.keys?.[i]?.scheme;
      service.addKeyReference(pub(pkb(seed), scheme).reference());
    }
    for (const i of s.delegates ?? []) service.addDelegateReference(delegates[i].reference);
    permissions(service, s.allow, s.deny);
    return service;
  };
  const verifyOf = (o: SignOpt | undefined): "none" | "inception" =>
    o === undefined || o === "none" ? "none" : "inception";
  const sortedUris = (set: Iterable<any>): string =>
    [...set]
      .map((u) => u.toString())
      .sort()
      .join(",");
  const outputsFor = (doc: any, out: OutputSpec): DocOutputs => {
    const env = doc.toEnvelope({
      privateKeys: opt(out.priv),
      generator: opt(out.gen),
      sign: signOpt(out.sign),
    });
    const deterministic =
      (out.priv ?? "omit") === "omit" &&
      (out.gen ?? "omit") === "omit" &&
      (out.sign ?? "none") === "none";
    const pw = password(out);
    const inception = doc.inceptionKey;
    const prov = doc.provenance;
    const gen = doc.provenanceGenerator;
    return {
      format: d.format(env),
      cbor: deterministic ? d.cborHex(env) : "",
      ur: deterministic ? d.urString(env) : "",
      digest: deterministic ? d.digestHex(env) : "",
      xid: d.xidHex(doc.xid),
      reference: d.referenceHex(doc.reference),
      isEmpty: String(doc.isEmpty),
      keys: String(doc.keys.length),
      inception:
        inception === undefined
          ? "-"
          : `${d.referenceHex(inception.reference)}${inception.hasPrivateKeys ? " private" : ""}`,
      resolution: sortedUris(doc.resolutionMethods),
      services: doc.services
        .map((s: any) => s.uri.toString())
        .sort()
        .join(","),
      delegates: doc.delegates
        .map((x: any) => d.xidHex(x.xid).slice(0, 8))
        .sort()
        .join(","),
      attachments: String(doc.attachments.len()),
      edges: String(doc.edges().len()),
      provenance: prov === undefined ? "-" : d.markUR(prov),
      generator: gen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(gen)}`,
      roundtrip: attempt(api, () =>
        String(
          m.XIDDocument.fromEnvelope(env, { password: pw, verify: verifyOf(out.sign) }).equals(doc),
        ),
      ),
      verify: attempt(api, () => {
        m.XIDDocument.fromEnvelope(env, { password: pw, verify: "inception" });
      }),
    };
  };
  const api: VectorApi = {
    doc: (spec, out) => outputsFor(build(spec).doc, out),
    decode: (ur, verify, pw) => {
      const doc = m.XIDDocument.fromEnvelope(d.envelopeFromUR(ur), { password: pw, verify });
      return d.format(doc.toEnvelope());
    },
    mutate: (spec, ops) => {
      const built = build(spec);
      let doc = built.doc;
      const inceptionScheme =
        spec.inception.kind === "privateKeyBase" ? "schnorr" : spec.inception.scheme;
      const keyPub = (i: number): any =>
        i < 0
          ? pub(pkb(spec.inception.seed), inceptionScheme)
          : pub(pkb(spec.keys?.[i]?.seed ?? spec.inception.seed), spec.keys?.[i]?.scheme);
      const lines: string[] = [];
      for (const op of ops) {
        const line = attempt(api, () => {
          switch (op[0]) {
            case "removeKey":
              doc.removeKey(keyPub(op[1]));
              return;
            case "takeKey": {
              const k = doc.takeKey(keyPub(op[1]));
              return k === undefined ? "undefined" : d.referenceHex(k.reference);
            }
            case "removeInceptionKey": {
              const k = doc.removeInceptionKey();
              return k === undefined ? "undefined" : d.referenceHex(k.reference);
            }
            case "setNameForKey":
              doc.setNameForKey(keyPub(op[1]), op[2]);
              return;
            case "addKey":
              doc.addKey(makeKey(op[1]));
              return;
            case "addResolution":
              doc.addResolutionMethod(op[1]);
              return;
            case "removeResolution":
              return String(doc.removeResolutionMethod(op[1]));
            case "addService":
              doc.addService(makeService(spec, op[1], built.delegates));
              return;
            case "removeService":
              doc.removeService(op[1]);
              return;
            case "takeService": {
              const s = doc.takeService(op[1]);
              return s === undefined ? "undefined" : s.uri.toString();
            }
            case "removeDelegate":
              doc.removeDelegate(built.delegates[op[1]].xid);
              return;
            case "takeDelegate": {
              const x = doc.takeDelegate(built.delegates[op[1]].xid);
              return x === undefined ? "undefined" : d.xidHex(x.xid).slice(0, 8);
            }
            case "checkContainsKey":
              doc.expectKey(keyPub(op[1]));
              return;
            case "checkContainsDelegate":
              doc.expectDelegate(built.delegates[op[1]].xid);
              return;
            case "checkServices":
              doc.expectServicesConsistent();
              return;
            case "clearAttachments":
              doc.clearAttachments();
              return;
            case "removeAttachment": {
              const digests = [...doc.attachments.iter()].map((a: any) => a[1].digest());
              return doc.removeAttachment(digests[op[1]]) === undefined ? "undefined" : "removed";
            }
            case "clearEdges":
              doc.clearEdges();
              return;
            case "removeEdge": {
              const digests = [...doc.edges().iter()].map((e: any) => e[1].digest());
              return doc.removeEdge(digests[op[1]]) === undefined ? "undefined" : "removed";
            }
            case "nextMark":
              doc.nextProvenanceMark({
                date: new Date(op[1].date),
                ...(op[1].info === undefined ? {} : { info: d.cborText(op[1].info) }),
                ...(op[1].password === undefined ? {} : { password: op[1].password }),
              });
              return;
            case "clearProvenance":
              doc.setProvenance(undefined);
              return;
            case "clone":
              doc = doc.clone();
              return;
          }
        });
        lines.push(`${op[0]}=${line}`);
      }
      return `${lines.join("\n")}\n===\n${d.format(doc.toEnvelope())}`;
    },
    key: (spec, privOption) => {
      const key = makeKey(spec);
      const env = key.toEnvelope({ privateKeys: opt(privOption) });
      const pw = typeof privOption === "object" ? privOption.encrypt : undefined;
      const back = m.Key.fromEnvelope(env, { password: pw });
      const deterministic = privOption === "omit";
      return render({
        format: d.format(env),
        cbor: deterministic ? d.cborHex(env) : "",
        reference: d.referenceHex(key.reference),
        roundtrip: String(key.equals(back)),
        private: String(back.hasPrivateKeys),
        encrypted: String(back.hasEncryptedPrivateKeys),
        nickname: back.nickname,
        endpoints: sortedUris(back.endpoints),
      });
    },
    provenance: (g, gen, pw) => {
      const res = d.resolution(g.res);
      const generator =
        g.passphrase !== undefined
          ? d.generatorFromPassphrase(res, g.passphrase)
          : d.generatorFromSeed(res, d.seed(unhex(g.seed ?? "")));
      const mark = d.markNext(
        generator,
        new Date(g.date ?? "2025-01-01T00:00:00Z"),
        g.info === undefined ? undefined : d.cborText(g.info),
      );
      const provenance = m.Provenance.from(mark, { generator });
      const env = provenance.toEnvelope({ generator: opt(gen) });
      const back = m.Provenance.fromEnvelope(env, { password: pw });
      const backGen = back.generator;
      return render({
        format: d.format(env),
        cbor: gen === "omit" ? d.cborHex(env) : "",
        mark: d.markUR(mark),
        roundtrip: String(provenance.equals(back)),
        generator: backGen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(backGen)}`,
        encrypted: String(back.hasEncryptedGenerator),
      });
    },
    privileges: () =>
      PRIVILEGES.map((p) => {
        const kv = m.privilegeKnownValue(p);
        return `${p}=${d.kvName(kv)}(${d.kvValue(kv)}) ${d.format(m.privilegeEnvelope(p))}`;
      }).join("\n"),
    errorCode: (e) => {
      const x: any = e;
      if (x?.name === "XIDError" || x?.constructor?.name === "XIDError")
        return String(x.code)
          .replace(/([a-z])([A-Z])/g, "$1_$2")
          .toUpperCase();
      return undefined;
    },
  };
  return api;
}
