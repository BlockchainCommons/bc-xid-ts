/**
 * The adapter over the working tree: every recipe kind materialised with
 * the package's own API. A thrown value renders from the error's own
 * `code` (or its class name), the `code` of its `cause` for the four
 * codes whose reference variant wraps another error, and its message.
 */
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion -- the recipe language is checked by its own type; a missing field is a corpus bug */
import { decodeCbor } from "@blockchaincommons/dcbor";
import {
  PRIVILEGES,
  KNOWN_VALUES,
  attempt,
  render,
  hex,
  unhex,
  type AssertionSpec,
  type DocOutputs,
  type DocSpec,
  type GenesisSpec,
  type GenOpt,
  type KeySpec,
  type Obj,
  type OutputSpec,
  type PrivilegeName,
  type PrivOpt,
  type ServiceSpec,
  type SiblingDeps,
  type SignOpt,
  type VectorApi,
} from "./recipes";

/**
 * The JavaScript input domain: inputs the reference's types cannot
 * express (J3) or a reference surface the port reaches differently (J4),
 * by case name. The outcome is what the port does with them.
 */
export const DOMAIN_CASES: readonly [string, "J1" | "J2" | "J3" | "J4"][] = [
  ["privateKeys.null", "J3"],
  ["genesis.empty", "J3"],
  ["genesis.seed.16", "J3"],
  ["genesis.seed.40", "J3"],
  ["genesis.date.invalid", "J3"],
  ["genesis.resolution.bogus", "J3"],
  ["nextMark.date.invalid", "J3"],
  ["verify.bogus", "J3"],
  ["privateKeys.bogus", "J3"],
  ["generator.bogus", "J3"],
  ["sign.bogus", "J3"],
  ["inceptionKey.undefined", "J3"],
  ["random.genesis", "J4"],
  ["genesis.date.cborDate", "J4"],
  ["nextMark.date.cborDate", "J4"],
  ["inceptionKey.plainObject", "J3"],
  ["inceptionKey.pair.plain", "J3"],
  ["addKey.plain", "J3"],
  ["addService.plain", "J3"],
  ["addDelegate.plain", "J3"],
  ["equals.plain", "J3"],
  ["provenance.equals.plain", "J3"],
  ["nextMark.generator.plain", "J3"],
  ["setProvenance.string", "J3"],
  ["provenance.from.plain", "J3"],
  ["setProvenanceWithGenerator.swapped", "J3"],
  ["provenance.equals.generator", "J4"],
];

const WRAPPING = new Set(["EnvelopeParsing", "Component", "Cbor", "ProvenanceMark"]);

export function workingTreeAdapterFor(m: any, d: SiblingDeps): VectorApi {
  const pkb = d.pkbFromSeed;
  const pub = d.pub;
  const priv = d.priv;
  // The carriers' own adders; the frozen bundle has them on `permissions` only.
  const permissions = (obj: any, allow?: PrivilegeName[], deny?: PrivilegeName[]): void => {
    const target = typeof obj.addAllow === "function" ? obj : obj.permissions;
    for (const p of allow ?? []) target.addAllow(p);
    for (const p of deny ?? []) target.addDeny(p);
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
          inceptionKey: {
            publicKeys: pub(p, scheme),
            privateKeys: priv(
              spec.inception.privateSeed === undefined ? p : pkb(spec.inception.privateSeed),
              scheme,
            ),
          },
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
      for (const r of ds.laterResolution ?? []) controller.addResolutionMethod(r);
      permissions(delegate, ds.allow, ds.deny);
      doc.addDelegate(delegate);
      delegates.push(delegate);
    }
    for (const s of spec.services ?? []) doc.addService(makeService(spec, s, delegates));
    for (const a of spec.attachments ?? []) {
      if (doc.addAttachment.length <= 1)
        doc.addAttachment({ payload: a.payload, vendor: a.vendor, conformsTo: a.conformsTo });
      else doc.addAttachment(a.payload, a.vendor, a.conformsTo);
    }
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
  const sortedPrivileges = (set: Iterable<any>): string => [...set].sort().join(",");
  const genesisGenerator = (g: GenesisSpec): { generator: any; mark: any } => {
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
    return { generator, mark };
  };
  /** A hand-assembled envelope. */
  const obj = (o: Obj): any => {
    switch (o.t) {
      case "text":
        return d.envelopeFrom(o.v);
      case "int":
        return d.envelopeFrom(o.v);
      case "kv":
        return d.knownValueEnvelope(KNOWN_VALUES[o.name]);
      case "uri":
        return d.envelopeFrom(d.uri(o.v));
      case "bytes":
        return d.envelopeFrom(d.bytesValue(unhex(o.hex)));
      case "xid":
        return d.envelopeFrom(xidOf(o.seed));
      case "ref":
        return d.envelopeFrom(pub(pkb(o.seed), o.scheme).reference());
      case "xidRef":
        return d.envelopeFrom(xidOf(o.seed).reference());
      case "pub":
        return d.envelopeFrom(pub(pkb(o.seed), o.scheme));
      case "priv":
        return d.envelopeFrom(priv(pkb(o.seed), o.scheme));
      case "salt":
        return d.envelopeFrom(d.salt(unhex(o.hex)));
      case "mark":
        return d.envelopeFrom(genesisGenerator(o.genesis).mark);
      case "generatorEnv":
        return d.generatorEnvelope(genesisGenerator(o.genesis).generator);
      case "doc":
        return build(o.doc).doc.toEnvelope();
      case "node": {
        let env = obj(o.subject);
        for (const a of o.assertions) env = d.addAssertionEnvelope(env, assertion(a));
        return env;
      }
      case "wrapped":
        return d.wrap(obj(o.inner));
      case "elided":
        return d.elide(obj(o.inner));
      case "signed":
        return d.sign(obj(o.inner), priv(pkb(o.seed), "schnorr"));
    }
  };
  const assertion = (a: AssertionSpec): any => {
    let env = d.assertionEnvelope(obj(a.pred), obj(a.obj));
    for (const w of a.with ?? []) env = d.addAssertionEnvelope(env, assertion(w));
    return a.elide === true ? d.elide(env) : env;
  };
  const withAssertions = (env: any, as: AssertionSpec[] | undefined): any => {
    let result = env;
    for (const a of as ?? []) result = d.addAssertionEnvelope(result, assertion(a));
    return result;
  };
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
      attachments: String(doc.attachments.size),
      edges: String(edgesOf(doc).size),
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
  const edgesOf = (doc: any): any => (typeof doc.edges === "function" ? doc.edges() : doc.edges);
  // The lookups; the frozen bundle has them under the short names.
  const findKey = (doc: any, publicKeys: any): any =>
    (doc.findKeyByPublicKeys ?? doc.key).call(doc, publicKeys);
  const findService = (doc: any, uri: string): any =>
    (doc.findServiceByUri ?? doc.service).call(doc, uri);
  // The two next-mark forms; the frozen bundle has one method with a `generator` option.
  const nextMark = (doc: any, options: any): void => {
    if (typeof doc.nextProvenanceMarkWithEmbeddedGenerator === "function")
      doc.nextProvenanceMarkWithEmbeddedGenerator(options);
    else doc.nextProvenanceMark(options);
  };
  const nextMarkProvided = (doc: any, generator: any, options: any): void => {
    if (typeof doc.nextProvenanceMarkWithProvidedGenerator === "function")
      doc.nextProvenanceMarkWithProvidedGenerator(generator, options);
    else doc.nextProvenanceMark({ ...options, generator });
  };
  const docFormat = (doc: any): string => d.format(doc.toEnvelope());
  const keyOutputs = (key: any): Record<string, string> => ({
    format: d.format(key.toEnvelope({ privateKeys: "include" })),
    private: String(key.hasPrivateKeys),
    encrypted: String(key.hasEncryptedPrivateKeys),
    nickname: key.nickname,
    endpoints: sortedUris(key.endpoints),
    allow: sortedPrivileges(key.permissions.allow),
    deny: sortedPrivileges(key.permissions.deny),
  });
  const domain = (name: string): string => {
    const alice = pkb("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed");
    const wolf = { passphrase: "wolf", resolution: "low", date: new Date("2025-01-01T00:00:00Z") };
    const docWith = (input: any): string => docFormat(m.XIDDocument.from(input));
    switch (name) {
      case "privateKeys.null": {
        const key = m.Key.from(alice.schnorrPublicKeys(), { privateKeys: null });
        return render({
          hasPrivateKeys: String(key.hasPrivateKeys),
          format: d.format(key.toEnvelope({ privateKeys: "include" })),
        });
      }
      case "genesis.empty":
        return docWith({ inceptionKey: alice, genesis: {} });
      case "genesis.seed.16":
        return docWith({
          inceptionKey: alice,
          genesis: { seed: new Uint8Array(16), resolution: "low", date: wolf.date },
        });
      case "genesis.seed.40":
        return docWith({
          inceptionKey: alice,
          genesis: { seed: new Uint8Array(40), resolution: "low", date: wolf.date },
        });
      case "genesis.date.invalid":
        return docWith({ inceptionKey: alice, genesis: { ...wolf, date: new Date(NaN) } });
      case "genesis.resolution.bogus":
        return docWith({ inceptionKey: alice, genesis: { ...wolf, resolution: "bogus" } });
      case "nextMark.date.invalid": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        return attempt(api, () => {
          nextMark(doc, { date: new Date(NaN) });
        });
      }
      case "verify.bogus": {
        const env = m.XIDDocument.from({ inceptionKey: alice }).toEnvelope();
        return docFormat(m.XIDDocument.fromEnvelope(env, { verify: "bogus" }));
      }
      case "privateKeys.bogus":
        return d.format(
          m.XIDDocument.from({ inceptionKey: alice }).toEnvelope({ privateKeys: "bogus" }),
        );
      case "generator.bogus":
        return d.format(
          m.XIDDocument.from({ inceptionKey: alice, genesis: wolf }).toEnvelope({
            generator: "bogus",
          }),
        );
      case "sign.bogus":
        return d.format(m.XIDDocument.from({ inceptionKey: alice }).toEnvelope({ sign: "bogus" }));
      case "inceptionKey.undefined":
        return docWith({ inceptionKey: undefined });
      case "random.genesis": {
        const doc = m.XIDDocument.random({ genesis: wolf });
        return render({
          keys: String(doc.keys.length),
          provenance: doc.provenance === undefined ? "-" : d.markUR(doc.provenance).slice(0, 14),
          generator: doc.provenanceGenerator === undefined ? "-" : "held",
        });
      }
      case "genesis.date.cborDate":
        return docWith({
          inceptionKey: alice,
          genesis: { ...wolf, date: d.cborDate?.("2025-01-01T00:00:00Z") },
        });
      case "nextMark.date.cborDate": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        return attempt(api, () => {
          nextMark(doc, { date: d.cborDate?.("2025-01-02T00:00:00Z") });
          return `seq=${doc.provenance.seq}`;
        });
      }
      case "inceptionKey.plainObject":
        return docWith({ inceptionKey: { foo: 1 } });
      case "inceptionKey.pair.plain":
        return docWith({ inceptionKey: { publicKeys: {}, privateKeys: {} } });
      case "addKey.plain":
      case "addService.plain":
      case "addDelegate.plain": {
        const doc = m.XIDDocument.from({ inceptionKey: alice });
        return attempt(api, () => {
          if (name === "addKey.plain") doc.addKey({});
          else if (name === "addService.plain") doc.addService({});
          else doc.addDelegate({});
        });
      }
      case "equals.plain":
        return attempt(api, () => String(m.XIDDocument.from({ inceptionKey: alice }).equals({})));
      case "provenance.equals.plain": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        const provenance = m.Provenance.from(doc.provenance);
        return attempt(api, () => String(provenance.equals({})));
      }
      case "nextMark.generator.plain": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        doc.setProvenance(doc.provenance);
        return attempt(api, () => {
          nextMarkProvided(doc, {}, { date: new Date("2025-01-02T00:00:00Z") });
        });
      }
      case "setProvenance.string": {
        const doc = m.XIDDocument.from({ inceptionKey: alice });
        return attempt(api, () => {
          doc.setProvenance("x");
          return typeof doc.provenance;
        });
      }
      case "provenance.from.plain":
        return attempt(api, () => typeof m.Provenance.from({}).mark);
      case "setProvenanceWithGenerator.swapped": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        return attempt(api, () => {
          doc.setProvenanceWithGenerator(doc.provenance, doc.provenanceGenerator);
          return typeof doc.provenance;
        });
      }
      case "provenance.equals.generator": {
        const doc = m.XIDDocument.from({ inceptionKey: alice, genesis: wolf });
        const env = doc.toEnvelope({ generator: "include" });
        const a = m.XIDDocument.fromEnvelope(env);
        const b = m.XIDDocument.fromEnvelope(env);
        nextMark(b, { date: new Date("2025-01-02T00:00:00Z") });
        return render({
          same: String(m.XIDDocument.fromEnvelope(env).equals(a)),
          advanced: String(a.equals(b)),
        });
      }
      default:
        throw new Error(`unknown domain case ${name}`);
    }
  };
  const api: VectorApi = {
    doc: (spec, out) => outputsFor(build(spec).doc, out),
    decode: (ur, verify, pw) => {
      const doc = m.XIDDocument.fromEnvelope(d.envelopeFromUR(ur), { password: pw, verify });
      return docFormat(doc);
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
      // The caller's generators, one per genesis, advanced in place across the script.
      const generators = new Map<string, any>();
      const provided = (g: GenesisSpec): any => {
        const id = JSON.stringify(g);
        let generator = generators.get(id);
        if (generator === undefined) {
          generator = genesisGenerator(g).generator;
          generators.set(id, generator);
        }
        return generator;
      };
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
            case "removeResolution": {
              // The URI removed; the frozen bundle reports a boolean.
              const removed = doc.removeResolutionMethod(op[1]);
              return typeof removed === "boolean"
                ? String(removed)
                : removed === undefined
                  ? "undefined"
                  : removed.toString();
            }
            case "removeEndpoint": {
              const key = findKey(doc, keyPub(op[1]));
              return key === undefined ? "undefined" : String(key.removeEndpoint(op[2]));
            }
            case "removeKeyReference": {
              const service = findService(doc, op[1]);
              return service === undefined
                ? "undefined"
                : String(service.removeKeyReference(keyPub(op[2]).reference()));
            }
            case "removeDelegateReference": {
              const service = findService(doc, op[1]);
              return service === undefined
                ? "undefined"
                : String(service.removeDelegateReference(built.delegates[op[2]].reference));
            }
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
              (doc.checkContainsKey ?? doc.expectKey).call(doc, keyPub(op[1]));
              return;
            case "checkContainsDelegate":
              (doc.checkContainsDelegate ?? doc.expectDelegate).call(
                doc,
                built.delegates[op[1]].xid,
              );
              return;
            case "checkServices":
              (doc.checkServicesConsistency ?? doc.expectServicesConsistent).call(doc);
              return;
            case "clearAttachments":
              doc.clearAttachments();
              return;
            case "removeAttachment": {
              const digests = [...doc.attachments].map((a: any) => a.digest());
              return doc.removeAttachment(digests[op[1]]) === undefined ? "undefined" : "removed";
            }
            case "clearEdges":
              doc.clearEdges();
              return;
            case "removeEdge": {
              const digests = [...edgesOf(doc)].map((e: any) => e.digest());
              return doc.removeEdge(digests[op[1]]) === undefined ? "undefined" : "removed";
            }
            case "nextMark":
              nextMark(doc, {
                date: new Date(op[1].date),
                ...(op[1].info === undefined ? {} : { info: d.cborText(op[1].info) }),
                ...(op[1].password === undefined ? {} : { password: op[1].password }),
              });
              return;
            case "nextMarkProvided": {
              const g = op[1].genesis ?? spec.genesis;
              if (g === undefined) throw new Error("nextMarkProvided needs a genesis");
              const generator = op[1].fresh === true ? genesisGenerator(g).generator : provided(g);
              nextMarkProvided(doc, generator, {
                date: new Date(op[1].date),
                ...(op[1].info === undefined ? {} : { info: d.cborText(op[1].info) }),
              });
              return;
            }
            case "dropGenerator":
              doc.setProvenance(doc.provenance);
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
      return `${lines.join("\n")}\n===\n${docFormat(doc)}`;
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
    provenance: (g, gen, pw, take) => {
      const { generator, mark } = genesisGenerator(g);
      const provenance = m.Provenance.from(mark, { generator });
      const env = provenance.toEnvelope({ generator: opt(gen as GenOpt) });
      const back = m.Provenance.fromEnvelope(env, { password: pw });
      const backGen = back.generator;
      const rows: Record<string, string> = {
        format: d.format(env),
        cbor: gen === "omit" ? d.cborHex(env) : "",
        mark: d.markUR(mark),
        roundtrip: String(provenance.equals(back)),
        generator: backGen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(backGen)}`,
        encrypted: String(back.hasEncryptedGenerator),
      };
      if (take) {
        // What `takeGenerator` hands back; the frozen bundle reports a boolean.
        const saltBefore = back.generatorSalt;
        const taken = back.takeGenerator();
        const salt = (s: any): string => (s.equals(saltBefore) ? "same" : "differs");
        rows["taken"] =
          typeof taken === "boolean"
            ? String(taken)
            : taken === undefined
              ? "-"
              : taken.data.type === "decrypted"
                ? `decrypted nextSeq=${d.generatorNextSeq(taken.data.generator)} salt=${salt(taken.salt)}`
                : `encrypted salt=${salt(taken.salt)}`;
        rows["afterTake"] = `${back.hasGenerator},${back.hasEncryptedGenerator}`;
      }
      return render(rows);
    },
    privileges: () =>
      PRIVILEGES.map((p) => {
        const kv = m.privilegeKnownValue(p);
        return `${p}=${d.kvName(kv)}(${d.kvValue(kv)}) ${d.format(m.privilegeEnvelope(p))}`;
      }).join("\n"),
    docEnvelope: (r) => {
      let env = r.base !== undefined ? build(r.base).doc.toEnvelope() : obj(r.subject!);
      env = withAssertions(env, r.assertions);
      for (const seed of r.sign ?? []) env = d.sign(env, priv(pkb(seed), "schnorr"));
      if (r.wrap === true) env = d.wrap(env);
      env = withAssertions(env, r.outer);
      const doc = m.XIDDocument.fromEnvelope(env, {
        verify: r.verify ?? "none",
        ...(r.password === undefined ? {} : { password: r.password }),
      });
      return render({ format: docFormat(doc), extra: String(doc.extraAssertions.length) });
    },
    keyEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const key = m.Key.fromEnvelope(env, r.password === undefined ? {} : { password: r.password });
      return render(keyOutputs(key));
    },
    serviceEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const service = m.Service.fromEnvelope(env);
      return render({
        format: d.format(service.toEnvelope()),
        capability: service.capability,
        name: service.name,
        keys: String(service.keyReferences.size),
        delegates: String(service.delegateReferences.size),
        allow: sortedPrivileges(service.permissions.allow),
        deny: sortedPrivileges(service.permissions.deny),
      });
    },
    provenanceEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const provenance = m.Provenance.fromEnvelope(
        env,
        r.password === undefined ? {} : { password: r.password },
      );
      const gen = provenance.generator;
      return render({
        format: d.format(provenance.toEnvelope({ generator: "include" })),
        generator: gen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(gen)}`,
        encrypted: String(provenance.hasEncryptedGenerator),
      });
    },
    cbor: (h, via) => {
      const value = decodeCbor(unhex(h));
      const doc =
        via === "tagged"
          ? m.XIDDocument.fromCbor(value)
          : via === "untagged"
            ? m.XIDDocument.fromUntaggedCbor(value)
            : m.XIDDocument.codec.decode(value);
      return render({
        format: docFormat(doc),
        cbor: hex(doc.toCbor().toData()),
        isEmpty: String(doc.isEmpty),
      });
    },
    ur: (s) => {
      const doc = m.XIDDocument.fromUR(d.parseUR(s));
      return render({ format: docFormat(doc), isEmpty: String(doc.isEmpty) });
    },
    nickname: (ops) => {
      const key = m.Key.from(
        pub(pkb("0000000000000000000000000000000000000000000000000000000000000001"), "schnorr"),
      );
      const lines = ops.map(
        ([op, v]) =>
          `${op}(${JSON.stringify(v)})=${attempt(api, () => {
            if (op === "add") key.addNickname(v);
            else key.setNickname(v);
          })}`,
      );
      return `${lines.join("\n")}\nnickname=${key.nickname}`;
    },
    construct: (op, v) => {
      const doc = m.XIDDocument.from({
        inceptionKey: pub(
          pkb("0000000000000000000000000000000000000000000000000000000000000001"),
          "schnorr",
        ),
      });
      switch (op) {
        case "service":
          return m.Service.from(v).uri.toString();
        case "resolution":
          doc.addResolutionMethod(v);
          return sortedUris(doc.resolutionMethods);
        case "endpoint":
          doc.inceptionKey.addEndpoint(v);
          return sortedUris(doc.inceptionKey.endpoints);
      }
    },
    domain,
    errorCode: (e) => {
      const x = e as { code?: unknown; name?: unknown; cause?: { code?: unknown } };
      const code = typeof x.code === "string" ? x.code : String(x.name ?? "Error");
      const inner =
        WRAPPING.has(code) && typeof x.cause?.code === "string" ? `[${x.cause.code}]` : "";
      return `${code}${inner}`;
    },
    // Engine errors word their messages per engine; report the name.
    errorMessage: (e) =>
      (e instanceof TypeError || e instanceof RangeError) && !("code" in e)
        ? e.name
        : e instanceof Error
          ? e.message
          : String(e),
  };
  return api;
}
