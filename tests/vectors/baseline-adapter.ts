/**
 * The adapter over the frozen bundle's surface of this package:
 * `XIDDocument.new(inception, genesis)`, zero-argument accessors,
 * `toEnvelope(privOpt, genOpt, signOpt)`, enums for the options, the
 * nickname mixin. A thrown value renders from the bundle's error code
 * (`UPPER_SNAKE`) or the error's class name, and its message.
 */
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion -- the recipe language is checked by its own type; a missing field is a corpus bug */
import {
  PRIVILEGES,
  KNOWN_VALUES,
  attempt,
  render,
  utf8,
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
  const pwBytes = (pw: string | undefined): Uint8Array | undefined =>
    pw === undefined ? undefined : utf8(pw);
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
          {
            type: "privateKeys",
            privateKeys: priv(
              spec.inception.privateSeed === undefined ? p : pkb(spec.inception.privateSeed),
              scheme,
            ),
            publicKeys: pub(p, scheme),
          },
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
      let env = omitEnvelope(doc);
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
  const verifyMode = (v: "none" | "inception"): any =>
    v === "none" ? m.XIDVerifySignature.None : m.XIDVerifySignature.Inception;
  const sortedUris = (set: Iterable<any>): string =>
    [...set]
      .map((u) => u.toString())
      .sort()
      .join(",");
  const sortedPrivileges = (set: Iterable<any>): string => [...set].map(String).sort().join(",");
  const omitEnvelope = (doc: any): any =>
    doc.toEnvelope(m.XIDPrivateKeyOptions.Omit, m.XIDGeneratorOptions.Omit, { type: "none" });
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
        return omitEnvelope(build(o.doc).doc);
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
      const doc = m.XIDDocument.fromEnvelope(env, pwBytes(pw), verifyMode(verify));
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
                pwBytes(op[1].password),
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
      const { generator, mark } = genesisGenerator(g);
      const provenance = m.Provenance.newWithGenerator(generator, mark);
      const env = provenance.intoEnvelopeOpt(genOpt(gen));
      const back = m.Provenance.tryFromEnvelope(env, pwBytes(pw));
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
    docEnvelope: (r) => {
      let env = r.base !== undefined ? omitEnvelope(build(r.base).doc) : obj(r.subject!);
      env = withAssertions(env, r.assertions);
      for (const seed of r.sign ?? []) env = d.sign(env, priv(pkb(seed), "schnorr"));
      if (r.wrap === true) env = d.wrap(env);
      env = withAssertions(env, r.outer);
      const doc = m.XIDDocument.fromEnvelope(
        env,
        pwBytes(r.password),
        verifyMode(r.verify ?? "none"),
      );
      return render({
        format: d.format(omitEnvelope(doc)),
        extra: String(doc.extraAssertions().length),
      });
    },
    keyEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const key = m.Key.tryFromEnvelope(env, pwBytes(r.password));
      return render({
        format: d.format(key.intoEnvelopeOpt(m.XIDPrivateKeyOptions.Include)),
        private: String(key.hasPrivateKeys()),
        encrypted: String(key.hasEncryptedPrivateKeys()),
        nickname: key.nickname(),
        endpoints: sortedUris(key.endpoints()),
        allow: sortedPrivileges(key.permissions().allow),
        deny: sortedPrivileges(key.permissions().deny),
      });
    },
    serviceEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const service = m.Service.tryFromEnvelope(env);
      return render({
        format: d.format(service.intoEnvelope()),
        capability: service.capability(),
        name: service.name(),
        keys: String(service.keyReferences().size),
        delegates: String(service.delegateReferences().size),
        allow: sortedPrivileges(service.permissions().allow),
        deny: sortedPrivileges(service.permissions().deny),
      });
    },
    provenanceEnvelope: (r) => {
      const env = withAssertions(obj(r.subject), r.assertions);
      const provenance = m.Provenance.tryFromEnvelope(env, pwBytes(r.password));
      const gen = provenance.generator();
      return render({
        format: d.format(provenance.intoEnvelopeOpt(m.XIDGeneratorOptions.Include)),
        generator: gen === undefined ? "-" : `nextSeq=${d.generatorNextSeq(gen)}`,
        encrypted: String(provenance.hasEncryptedGenerator()),
      });
    },
    cbor: () => {
      throw new Error("baseline: cannot decode raw CBOR bytes");
    },
    ur: (s) => {
      const doc = m.XIDDocument.fromURString(s);
      return render({ format: d.format(omitEnvelope(doc)), isEmpty: String(doc.isEmpty()) });
    },
    nickname: (ops) => {
      const key = m.Key.new(
        pub(pkb("0000000000000000000000000000000000000000000000000000000000000001"), "schnorr"),
      );
      const lines = ops.map(
        ([op, v]) =>
          `${op}(${JSON.stringify(v)})=${attempt(api, () => {
            if (op === "add") m.HasNicknameMixin.addNickname(key, v);
            else key.setNickname(v);
          })}`,
      );
      return `${lines.join("\n")}\nnickname=${key.nickname()}`;
    },
    construct: (op, v) => {
      const doc = m.XIDDocument.new(
        {
          type: "publicKeys",
          publicKeys: pub(
            pkb("0000000000000000000000000000000000000000000000000000000000000001"),
            "schnorr",
          ),
        },
        { type: "none" },
      );
      switch (op) {
        case "service":
          return m.Service.new(v).uriString();
        case "resolution":
          doc.addResolutionMethod(v);
          return sortedUris(doc.resolutionMethods());
        case "endpoint":
          doc.inceptionKey().addEndpoint(v);
          return sortedUris(doc.inceptionKey().endpoints());
        case "keyRefHex": {
          const s = m.Service.new("https://svc.example");
          s.addKeyReferenceHex(v);
          return String(s.keyReferences().size);
        }
        case "delegateRefHex": {
          const s = m.Service.new("https://svc.example");
          s.addDelegateReferenceHex(v);
          return String(s.delegateReferences().size);
        }
      }
    },
    domain: () => {
      throw new Error("baseline: no JavaScript-domain guards to compare");
    },
    errorCode: (e) => {
      const x = e as { code?: unknown; name?: unknown };
      return typeof x.code === "string" ? x.code : String(x.name ?? "Error");
    },
    errorMessage: (e) => (e instanceof Error ? e.message : String(e)),
  };
  return api;
}
