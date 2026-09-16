/**
 * The corpus and its golden subset: seeded documents covering every
 * inception kind, key scheme, privilege, delegate form, service shape,
 * attachments, edges, custom assertions and genesis marks; every output
 * option; decodes of every golden UR with each verification mode;
 * mutation scripts with their error paths; keys and provenance values on
 * their own; the privilege table; hand-assembled document, key, service
 * and provenance envelopes on every parser's accept and reject paths;
 * CBOR and URs given to every decoder; the nickname adders; construction
 * inputs; the JavaScript input domain.
 */
import {
  PRIVILEGES,
  type AssertionSpec,
  type DocSpec,
  type KeySpec,
  type Obj,
  type Op,
  type PrivOpt,
  type Recipe,
  type Resolution,
  type SignOpt,
} from "../vectors/recipes";
import { DOMAIN_CASES } from "../vectors/working-tree-adapter";

export const RESOLUTIONS: readonly Resolution[] = ["low", "medium", "quartile", "high"];
/** The reference's fake-RNG seeds (first two draws) and fixed patterns. */
export const SEEDS: readonly string[] = [
  "7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed",
  "518684c556472008a67932f7c682125b50cb72e8216f6906358fdaf28d354553",
  "0000000000000000000000000000000000000000000000000000000000000001",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "e9f1ab8b0f7f9c4b7c3e0c5d7f2a4b6d8e1f3a5b7c9d0e2f4a6b8c0d2e4f6a8b",
];
const S = SEEDS;
const DATE = "2025-01-01T00:00:00Z";

const alice: DocSpec = { inception: { kind: "privateKeyBase", seed: S[0] } };
const bobPub: DocSpec = { inception: { kind: "publicKeys", seed: S[1] } };
const key = (seed: string, extra: Partial<KeySpec> = {}): KeySpec => ({ seed, ...extra });

/** The reference's own document (X1) and the shapes its test suite builds. */
export function* referenceDocs(): Generator<Recipe> {
  yield { k: "doc", doc: { inception: { kind: "publicKeys", seed: S[0], scheme: "schnorr" } } };
  yield { k: "doc", doc: { inception: { kind: "xid", seed: S[0], scheme: "schnorr" } } };
  yield { k: "doc", doc: alice };
  yield { k: "doc", doc: bobPub };
  yield {
    k: "doc",
    doc: { ...bobPub, resolution: ["https://resolver.example.com", "btcr:01234567"] },
  };
  yield {
    k: "doc",
    doc: {
      ...alice,
      keys: [
        key(S[1], {
          nickname: "Alice's key",
          allow: ["All"],
          endpoints: [
            "https://resolver.example.com",
            "btc:9d2203b1c72eddc072b566c4a16ed8757fcba95a3be6f270e17a128e41554b33",
          ],
        }),
      ],
    },
  };
  yield {
    k: "doc",
    doc: {
      ...alice,
      keys: [key(S[1], { allow: ["Sign", "Encrypt"], deny: ["Burn"] })],
      delegates: [
        { doc: bobPub, allow: ["Encrypt", "Sign"] },
        { xidSeed: S[2], allow: ["Verify"] },
      ],
      services: [
        {
          uri: "https://example.com",
          capability: "com.example.messaging",
          name: "Example Service",
          keys: [-1, 0],
          delegates: [0],
          allow: ["Encrypt", "Sign"],
        },
      ],
    },
  };
  yield {
    k: "doc",
    doc: {
      ...alice,
      attachments: [
        {
          payload: "Attachment Data",
          vendor: "com.example",
          conformsTo: "https://example.com/schema",
        },
        { payload: "Second", vendor: "org.example" },
      ],
      edges: [
        { subject: "knows-bob", isA: "schema:colleague", source: "Alice", target: "Bob" },
        { subject: "self-desc", isA: "foaf:Person", source: "Alice", target: "Alice" },
      ],
      custom: [["customField", "customValue"]],
    },
  };
  for (const res of RESOLUTIONS)
    yield {
      k: "doc",
      doc: { ...alice, genesis: { passphrase: "test", res, date: DATE, info: "Genesis" } },
    };
  yield { k: "doc", doc: { ...alice, genesis: { seed: S[3], res: "quartile", date: DATE } } };
}

const PRIV_OPTS: PrivOpt[] = ["omit", "include", "elide", { encrypt: "correct horse" }];
const SIGN_OPTS: SignOpt[] = ["none", "inception", { seed: S[4] }];

export function* hand(): Generator<Recipe> {
  yield* referenceDocs();
  yield { k: "privileges" };
  // Every inception kind and scheme.
  for (const kind of ["publicKeys", "privateKeyBase", "privateKeys", "xid"] as const)
    for (const scheme of ["ed25519", "schnorr", "ecdsa"] as const)
      yield { k: "doc", doc: { inception: { kind, seed: S[2], scheme } } };
  // Every output option on a document that has private keys and a generator.
  const full: DocSpec = {
    ...alice,
    genesis: { passphrase: "Wolf", res: "low", date: DATE },
    keys: [
      key(S[1], { private: true, scheme: "schnorr", allow: ["Sign"] }),
      key(S[2], { allow: ["Encrypt"] }),
    ],
  };
  for (const priv of PRIV_OPTS)
    for (const gen of PRIV_OPTS)
      for (const sign of SIGN_OPTS) {
        if (typeof priv === "object" && typeof gen === "object" && priv.encrypt !== gen.encrypt)
          continue;
        yield { k: "doc", doc: full, out: { priv, gen, sign } };
      }
  // Signing a document whose inception key has no private key.
  yield { k: "doc", doc: bobPub, out: { sign: "inception" } };
  yield { k: "doc", doc: bobPub, out: { sign: { seed: S[1] } } };
  // Every privilege alone, allowed and denied, on a key, a delegate and a service.
  for (const p of PRIVILEGES) {
    yield { k: "doc", doc: { ...alice, keys: [key(S[1], { allow: [p] })] } };
    yield { k: "doc", doc: { ...alice, keys: [key(S[1], { deny: [p] })] } };
    yield { k: "doc", doc: { ...alice, delegates: [{ xidSeed: S[1], allow: [p] }] } };
    yield {
      k: "doc",
      doc: { ...alice, services: [{ uri: "https://svc.example", keys: [-1], allow: [p] }] },
    };
  }
  // Keys alone with each option.
  for (const priv of PRIV_OPTS) {
    yield {
      k: "key",
      key: key(S[0], {
        private: true,
        nickname: "k",
        allow: ["All"],
        endpoints: ["https://a.example"],
      }),
      priv,
    };
    yield { k: "key", key: key(S[0], { scheme: "schnorr" }), priv };
  }
  yield {
    k: "key",
    key: key(S[1], { private: true, scheme: "ecdsa", deny: ["Burn", "Revoke"] }),
    priv: "include",
  };
  // Every KDF; HKDF is not password-based, so its lock is not recognised on parse.
  for (const method of ["hkdf", "pbkdf2", "scrypt", "argon2id"] as const)
    yield { k: "key", key: key(S[0], { private: true }), priv: { encrypt: "pw", method } };
  // Provenance values.
  for (const res of RESOLUTIONS)
    for (const gen of PRIV_OPTS) {
      yield {
        k: "provenance",
        genesis: { passphrase: "test_passphrase", res, date: DATE, info: "Test mark" },
        gen,
        ...(typeof gen === "object" ? { password: gen.encrypt } : {}),
      };
    }
  yield { k: "provenance", genesis: { seed: S[5], res: "high", date: DATE }, gen: "include" };
  yield {
    k: "provenance",
    genesis: { passphrase: "x", res: "low", date: DATE },
    gen: { encrypt: "pw" },
    password: "wrong",
  };
  // Nested delegate documents with their own keys, and services with every reference shape.
  const nested: DocSpec = {
    ...bobPub,
    keys: [key(S[3], { allow: ["Sign"] })],
    resolution: ["https://bob.example"],
  };
  yield {
    k: "doc",
    doc: {
      ...alice,
      delegates: [
        { doc: nested, allow: ["All"] },
        { doc: alice, deny: ["Elect"] },
      ],
      services: [
        { uri: "https://a.example", delegates: [0, 1], allow: ["Access"] },
        {
          uri: "https://b.example",
          keys: [-1],
          capability: "cap",
          name: "B",
          allow: ["Sign"],
          deny: ["Burn"],
        },
      ],
    },
  };
}

export interface Materialized {
  urs: { ur: string; signed: boolean; name: string }[];
}

export function* decodeRecipes(m: Materialized): Generator<Recipe> {
  for (const u of m.urs) {
    yield { k: "decode", ur: u.ur, verify: "none" };
    yield { k: "decode", ur: u.ur, verify: "inception" };
  }
  // A UR that is not a document.
  yield { k: "decode", ur: "ur:envelope/tpsoihfyihjzjzjlbtzdvlvo", verify: "none" };
  yield { k: "decode", ur: "ur:xid/notbytewords", verify: "none" };
}

export function* mutateRecipes(): Generator<Recipe> {
  const withKeys: DocSpec = { ...alice, keys: [key(S[1], { allow: ["Sign"] }), key(S[2])] };
  const withService: DocSpec = {
    ...withKeys,
    services: [{ uri: "https://s.example", keys: [0], allow: ["Sign"] }],
  };
  const withDelegates: DocSpec = {
    ...alice,
    delegates: [{ xidSeed: S[1], allow: ["All"] }],
    services: [{ uri: "https://d.example", delegates: [0], allow: ["Access"] }],
  };
  const scripts: [DocSpec, Op[]][] = [
    [
      withKeys,
      [
        ["removeKey", 0],
        ["removeKey", 0],
        ["takeKey", 1],
        ["takeKey", 1],
      ],
    ],
    [
      withKeys,
      [
        ["removeInceptionKey"],
        ["removeInceptionKey"],
        ["checkContainsKey", -1],
        ["checkContainsKey", 0],
      ],
    ],
    [
      withKeys,
      [
        ["setNameForKey", 0, "renamed"],
        ["setNameForKey", 1, ""],
        ["addKey", key(S[1])],
        ["addKey", key(S[5], { nickname: "new" })],
      ],
    ],
    [
      withService,
      [
        ["removeKey", 0],
        ["takeKey", 0],
        ["removeService", "https://s.example"],
        ["removeKey", 0],
        ["removeService", "https://s.example"],
        ["takeService", "https://s.example"],
      ],
    ],
    [
      withService,
      [
        ["checkServices"],
        ["addService", { uri: "https://s.example", keys: [0], allow: ["Sign"] }],
        ["addService", { uri: "https://t.example", keys: [1] }],
        ["addService", { uri: "https://u.example", allow: ["Sign"] }],
        ["addService", { uri: "https://v.example", keys: [1], allow: ["Sign"] }],
      ],
    ],
    [
      withDelegates,
      [
        ["checkContainsDelegate", 0],
        ["removeDelegate", 0],
        ["takeDelegate", 0],
        ["removeService", "https://d.example"],
        ["removeDelegate", 0],
        ["takeDelegate", 0],
        ["checkContainsDelegate", 0],
      ],
    ],
    [
      { ...alice, resolution: ["https://r.example"] },
      [
        ["addResolution", "https://r.example"],
        ["removeResolution", "https://r.example"],
        ["removeResolution", "https://r.example"],
        ["addResolution", "btcr:1"],
      ],
    ],
    [
      {
        ...alice,
        attachments: [
          { payload: "a", vendor: "v" },
          { payload: "b", vendor: "w", conformsTo: "c" },
        ],
        edges: [{ subject: "s", isA: "t", source: "A", target: "B" }],
      },
      [
        ["removeAttachment", 0],
        ["removeAttachment", 0],
        ["removeEdge", 0],
        ["clearAttachments"],
        ["clearEdges"],
      ],
    ],
    [
      { ...alice, genesis: { passphrase: "Wolf", res: "low", date: DATE } },
      [
        ["nextMark", { date: "2025-01-02T00:00:00Z" }],
        ["nextMark", { date: "2025-01-03T00:00:00Z", info: "third" }],
        ["clone"],
        ["clearProvenance"],
        ["nextMark", { date: "2025-01-04T00:00:00Z" }],
      ],
    ],
    [alice, [["nextMark", { date: DATE }]]],
    [
      { ...alice, genesis: { passphrase: "Wolf", res: "medium", date: DATE } },
      [["clone"], ["nextMark", { date: "2024-01-01T00:00:00Z" }]],
    ],
  ];
  for (const [doc, ops] of scripts) yield { k: "mutate", doc, ops };
}

/** A small deterministic PRNG for the generated corpus. */
function* prng(seed: number): Generator<number> {
  let x = seed >>> 0 || 1;
  for (;;) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    yield x;
  }
}

export function* generated(): Generator<Recipe> {
  const g = prng(0x5eed);
  const next = (): number => g.next().value as number;
  const pick = <T>(xs: readonly T[]): T => xs[next() % xs.length];
  const some = <T>(xs: readonly T[], max: number): T[] => {
    const n = next() % (max + 1);
    const out: T[] = [];
    for (let i = 0; i < n; i++) {
      const x = pick(xs);
      if (!out.includes(x)) out.push(x);
    }
    return out;
  };
  const seedAt = (i: number): string => S[i % S.length];
  for (let i = 0; i < 160; i++) {
    const nKeys = next() % 4;
    const keys: KeySpec[] = Array.from({ length: nKeys }, (_, j) => ({
      seed: seedAt(1 + j),
      scheme: pick(["ed25519", "schnorr", "ecdsa"] as const),
      ...(next() % 3 === 0 ? { private: true } : {}),
      ...(next() % 2 === 0 ? { nickname: `key ${j}` } : {}),
      allow: some(PRIVILEGES, 3),
      deny: some(PRIVILEGES, 2),
      ...(next() % 3 === 0 ? { endpoints: [`https://k${j}.example`] } : {}),
    }));
    const nDelegates = next() % 3;
    const delegates = Array.from({ length: nDelegates }, (_, j) =>
      next() % 2 === 0
        ? { xidSeed: seedAt(4 + j), allow: some(PRIVILEGES, 2) }
        : {
            doc: { inception: { kind: "publicKeys" as const, seed: seedAt(4 + j) } },
            allow: some(PRIVILEGES, 2),
            deny: some(PRIVILEGES, 1),
          },
    );
    const nServices = next() % 3;
    const services = Array.from({ length: nServices }, (_, j) => ({
      uri: `https://s${j}.example`,
      ...(next() % 2 === 0 ? { capability: `cap${j}` } : {}),
      ...(next() % 2 === 0 ? { name: `Service ${j}` } : {}),
      keys: nKeys > 0 && next() % 2 === 0 ? [next() % nKeys] : [-1],
      delegates: nDelegates > 0 && next() % 2 === 0 ? [next() % nDelegates] : [],
      allow: some(PRIVILEGES, 2),
    }));
    const doc: DocSpec = {
      inception: {
        kind: pick(["publicKeys", "privateKeyBase", "privateKeys"] as const),
        seed: seedAt(i),
      },
      ...(next() % 3 === 0
        ? { genesis: { passphrase: `p${i}`, res: pick(RESOLUTIONS), date: DATE } }
        : {}),
      ...(next() % 2 === 0 ? { resolution: [`https://r${i}.example`] } : {}),
      keys,
      delegates,
      services,
      ...(next() % 4 === 0
        ? { attachments: [{ payload: `att ${i}`, vendor: "com.example" }] }
        : {}),
      ...(next() % 4 === 0
        ? { edges: [{ subject: `e${i}`, isA: "t", source: "A", target: "B" }] }
        : {}),
    };
    const out = {
      priv: pick(["omit", "include", "elide"] as const),
      gen: pick(["omit", "include", "elide"] as const),
      sign: pick(["none", "inception"] as const),
    };
    yield { k: "doc", doc, out };
    if (i % 8 === 0)
      yield {
        k: "doc",
        doc,
        out: { priv: { encrypt: "pw" }, gen: { encrypt: "pw" }, sign: "none" },
      };
  }
}

// Hand-assembled envelopes ----------------------------------------------------

const text = (v: string): Obj => ({ t: "text", v });
const int = (v: number): Obj => ({ t: "int", v });
const kv = (name: string): Obj => ({ t: "kv", name });
const uri = (v: string): Obj => ({ t: "uri", v });
const node = (subject: Obj, assertions: AssertionSpec[]): Obj => ({
  t: "node",
  subject,
  assertions,
});
const a = (pred: Obj, obj: Obj): AssertionSpec => ({ pred, obj });
const wolf = { passphrase: "wolf", res: "low" as const, date: DATE };
const wolfMedium = { passphrase: "wolf", res: "medium" as const, date: DATE };
/** 32 bytes of salt for the hand-built private-key and generator nodes. */
const SALT_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const saltAssertion: AssertionSpec = a(kv("salt"), { t: "salt", hex: SALT_HEX });
const withKeys: DocSpec = { ...alice, keys: [key(S[1], { allow: ["Sign"] })] };
const xidOnly: DocSpec = { inception: { kind: "xid", seed: S[2] } };

/** Document envelopes fed to `fromEnvelope`: the parser's every path. */
export function* docEnvelopes(): Generator<Recipe> {
  const de = (r: Omit<Extract<Recipe, { k: "docEnvelope" }>, "k">): Recipe => ({
    k: "docEnvelope",
    ...r,
  });
  // Subjects that are not a XID.
  yield de({ subject: text("hello") });
  yield de({ subject: int(42) });
  yield de({ subject: kv("isA") });
  yield de({ subject: { t: "bytes", hex: "0102" } });
  // Signature handling.
  yield de({ base: alice, wrap: true });
  yield de({ base: alice, wrap: true, verify: "inception" });
  yield de({ base: alice, verify: "inception" });
  yield de({ base: xidOnly, sign: [S[0]], verify: "inception" });
  yield de({ base: alice, sign: [S[1]], verify: "inception" });
  yield de({ base: alice, sign: [S[0]], verify: "inception" });
  yield de({ base: alice, sign: [S[0]] });
  yield de({ base: alice, sign: [S[0], S[0]], verify: "inception" });
  yield de({
    base: alice,
    sign: [S[0]],
    outer: [a(kv("note"), text("outer"))],
    verify: "inception",
  });
  yield de({ base: alice, sign: [S[0]], outer: [a(kv("note"), text("outer"))] });
  yield de({
    base: {
      inception: { kind: "xid", seed: S[2] },
      keys: [key(S[0], { scheme: "schnorr", allow: ["All"] })],
    },
    sign: [S[0]],
    verify: "inception",
  });
  // Resolution methods.
  yield de({ base: alice, assertions: [a(kv("dereferenceVia"), int(42))] });
  yield de({ base: alice, assertions: [a(kv("dereferenceVia"), text("not a uri"))] });
  yield de({
    base: alice,
    assertions: [
      a(kv("dereferenceVia"), node(uri("https://r.example"), [a(kv("note"), text("n"))])),
    ],
  });
  yield de({ base: alice, assertions: [a(kv("dereferenceVia"), uri("https://r.example"))] });
  // Keys, delegates, services, provenance.
  yield de({ base: alice, assertions: [a(kv("key"), text("text"))] });
  yield de({
    base: alice,
    assertions: [a(kv("key"), node({ t: "pub", seed: S[1] }, [a(kv("nickname"), int(5))]))],
  });
  yield de({ base: alice, assertions: [a(kv("delegate"), { t: "doc", doc: bobPub })] });
  yield de({
    base: alice,
    assertions: [a(kv("delegate"), { t: "wrapped", inner: { t: "doc", doc: bobPub } })],
  });
  yield de({ base: alice, assertions: [a(kv("delegate"), text("x"))] });
  yield de({
    base: alice,
    assertions: [a(kv("service"), node(uri("https://s.example"), [a(kv("note"), text("n"))]))],
  });
  yield de({
    base: alice,
    assertions: [
      a(
        kv("service"),
        node(uri("https://s.example"), [
          a(kv("key"), { t: "ref", seed: S[0], scheme: "schnorr" }),
          a(kv("allow"), kv("Sign")),
        ]),
      ),
    ],
  });
  yield de({
    base: alice,
    assertions: [
      a(
        kv("service"),
        node(uri("https://s.example"), [
          a(kv("key"), { t: "ref", seed: S[5] }),
          a(kv("allow"), kv("Sign")),
        ]),
      ),
    ],
  });
  yield de({
    base: alice,
    assertions: [
      a(
        kv("service"),
        node(uri("https://s.example"), [
          a(kv("delegate"), { t: "xidRef", seed: S[5] }),
          a(kv("allow"), kv("Sign")),
        ]),
      ),
    ],
  });
  yield de({
    base: alice,
    assertions: [
      a(
        kv("service"),
        node(uri("https://s.example"), [a(kv("key"), { t: "ref", seed: S[0], scheme: "schnorr" })]),
      ),
    ],
  });
  yield de({
    base: alice,
    assertions: [a(kv("service"), node(uri("https://s.example"), [a(kv("allow"), kv("Sign"))]))],
  });
  yield de({
    base: alice,
    assertions: [
      a(kv("provenance"), { t: "mark", genesis: wolf }),
      a(kv("provenance"), { t: "mark", genesis: wolfMedium }),
    ],
  });
  yield de({ base: alice, assertions: [a(kv("provenance"), text("x"))] });
  yield de({ base: alice, assertions: [a(kv("provenance"), { t: "mark", genesis: wolf })] });
  // Attachments, edges, unknown and elided assertions.
  yield de({ base: alice, assertions: [a(kv("attachment"), text("x"))] });
  yield de({ base: alice, assertions: [a(kv("edge"), text("x"))] });
  yield de({
    base: alice,
    assertions: [a(text("customField"), text("a")), a(text("other"), text("b"))],
  });
  yield de({
    base: alice,
    assertions: [a(text("other"), text("b")), a(text("customField"), text("a"))],
  });
  yield de({ base: alice, assertions: [a(kv("note"), text("n"))] });
  yield de({ base: alice, assertions: [{ ...a(kv("note"), text("n")), elide: true }] });
  yield de({ base: alice, assertions: [a(int(7), text("n"))] });
  // Duplicate keys and delegates.
  yield de({ base: withKeys, assertions: [a(kv("key"), { t: "pub", seed: S[1] })] });
  yield de({
    base: alice,
    assertions: [
      a(kv("delegate"), { t: "wrapped", inner: { t: "doc", doc: bobPub } }),
      a(kv("delegate"), { t: "wrapped", inner: { t: "doc", doc: bobPub } }),
    ],
  });
  // A locked private key parsed with and without its password, and with a wrong one.
  for (const password of [undefined, "correct horse", "wrong"]) {
    yield de({
      base: { ...alice, keys: [key(S[1], { private: true, scheme: "schnorr" })] },
      ...(password === undefined ? {} : { password }),
    });
  }
}

/** Key envelopes fed to `Key.fromEnvelope`. */
export function* keyEnvelopes(): Generator<Recipe> {
  const ke = (subject: Obj, assertions?: AssertionSpec[], password?: string): Recipe => ({
    k: "keyEnvelope",
    subject,
    ...(assertions === undefined ? {} : { assertions }),
    ...(password === undefined ? {} : { password }),
  });
  const pub: Obj = { t: "pub", seed: S[0], scheme: "schnorr" };
  yield ke(pub);
  yield ke(text("text"));
  yield ke(pub, [a(kv("nickname"), text("a"))]);
  yield ke(pub, [a(kv("nickname"), text("a")), a(kv("nickname"), text("b"))]);
  yield ke(pub, [a(kv("nickname"), int(5))]);
  yield ke(pub, [a(kv("nickname"), text(""))]);
  yield ke(pub, [a(kv("note"), text("n"))]);
  yield ke(pub, [a(kv("endpoint"), int(5))]);
  yield ke(pub, [
    a(kv("endpoint"), uri("https://a.example")),
    a(kv("endpoint"), uri("https://b.example")),
  ]);
  const priv: Obj = { t: "priv", seed: S[0], scheme: "schnorr" };
  yield ke(pub, [a(kv("privateKey"), priv)]);
  yield ke(pub, [{ ...a(kv("privateKey"), priv), with: [saltAssertion] }]);
  yield ke(pub, [
    { ...a(kv("privateKey"), { t: "priv", seed: S[1], scheme: "schnorr" }), with: [saltAssertion] },
  ]);
  yield ke(pub, [{ ...a(kv("privateKey"), text("x")), with: [saltAssertion] }]);
  yield ke(pub, [{ ...a(kv("privateKey"), priv), with: [a(kv("salt"), text("x"))] }]);
  yield ke(pub, [
    { ...a(kv("privateKey"), node(priv, [a(kv("note"), text("n"))])), with: [saltAssertion] },
  ]);
  yield ke(pub, [a(kv("allow"), kv("Sign")), a(kv("deny"), kv("All"))]);
  yield ke(pub, [a(kv("allow"), kv("note"))]);
  yield ke(pub, [a(kv("allow"), text("Sign"))]);
  yield ke(pub, [a(kv("deny"), int(3))]);
}

/** Service envelopes fed to `Service.fromEnvelope`. */
export function* serviceEnvelopes(): Generator<Recipe> {
  const se = (subject: Obj, assertions?: AssertionSpec[]): Recipe => ({
    k: "serviceEnvelope",
    subject,
    ...(assertions === undefined ? {} : { assertions }),
  });
  const svc = uri("https://svc.example");
  const ref: Obj = { t: "ref", seed: S[0], scheme: "schnorr" };
  yield se(svc);
  yield se(text("text"));
  yield se(svc, [a(kv("key"), ref), a(kv("allow"), kv("Sign"))]);
  yield se(svc, [a(kv("key"), ref), a(kv("key"), ref)]);
  yield se(svc, [a(kv("key"), text("abc"))]);
  yield se(svc, [a(kv("key"), node(ref, [a(kv("note"), text("n"))]))]);
  yield se(svc, [a(kv("delegate"), { t: "xidRef", seed: S[1] })]);
  yield se(svc, [a(kv("delegate"), int(1))]);
  yield se(svc, [a(kv("note"), text("n"))]);
  yield se(svc, [a(text("foo"), text("bar"))]);
  yield se(svc, [a(kv("allow"), kv("note"))]);
  yield se(svc, [a(kv("allow"), text("Sign"))]);
  yield se(svc, [a(kv("deny"), kv("Sign"))]);
  yield se(svc, [a(kv("capability"), int(5))]);
  yield se(svc, [a(kv("capability"), text("a")), a(kv("capability"), text("b"))]);
  yield se(svc, [a(kv("capability"), text(""))]);
  yield se(svc, [a(kv("capability"), text("com.example.cap"))]);
  yield se(svc, [a(kv("name"), int(5))]);
  yield se(svc, [a(kv("name"), text("a")), a(kv("name"), text("b"))]);
  yield se(svc, [a(kv("name"), text(""))]);
  yield se(svc, [a(kv("name"), text("Example"))]);
}

/** Provenance envelopes fed to `Provenance.fromEnvelope`. */
export function* provenanceEnvelopes(): Generator<Recipe> {
  const pe = (subject: Obj, assertions?: AssertionSpec[], password?: string): Recipe => ({
    k: "provenanceEnvelope",
    subject,
    ...(assertions === undefined ? {} : { assertions }),
    ...(password === undefined ? {} : { password }),
  });
  const mark: Obj = { t: "mark", genesis: wolf };
  const generator: Obj = { t: "generatorEnv", genesis: wolf };
  yield pe(mark);
  yield pe(text("x"));
  yield pe(int(1));
  yield pe(mark, [a(kv("note"), text("n"))]);
  yield pe(mark, [a(kv("provenanceGenerator"), generator)]);
  yield pe(mark, [{ ...a(kv("provenanceGenerator"), generator), with: [saltAssertion] }]);
  yield pe(mark, [
    {
      ...a(kv("provenanceGenerator"), { t: "generatorEnv", genesis: wolfMedium }),
      with: [saltAssertion],
    },
  ]);
  yield pe(mark, [{ ...a(kv("provenanceGenerator"), text("x")), with: [saltAssertion] }]);
  yield pe(mark, [{ ...a(kv("provenanceGenerator"), generator), with: [a(kv("salt"), int(1))] }]);
}

/** CBOR of an empty document (the XID alone) and of a one-key document, in every framing. */
const EMPTY_TAGGED = "d99c58582071274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c";
const EMPTY_UNTAGGED = "582071274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c";
const DOC_UNTAGGED =
  "d8c882d8c9d99c58582071274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93ca10882d8c9d99c5182d99c565820618c40370884f0d49c2f54bd2d9540e74e9b886a045e76b54829cadc52e305b4d99c4b5820388af2e3ee48ce10f962a70e98c60294f3f80e78c27b4a51173991bb1dd37520a1183c1846";
const DOC_TAGGED = `d99c58${DOC_UNTAGGED}`;
const BYTES31 = "581f71274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b9";
const TAG200_BYTES = "d8c8582071274df133169a0e2d2ffb11cbc7917732acafa31989f685cca6cb69d473b93c";
const TEXT_HELLO = "6568656c6c6f";
const DOUBLE_TAGGED = `d99c58${EMPTY_TAGGED}`;
const ENV_TEXT_TAGGED = "d99c58d8c8d8c96568656c6c6f";
const ENV_TEXT_UNTAGGED = "d8c8d8c96568656c6c6f";

/** CBOR given to every decoder. */
export function* cborRecipes(): Generator<Recipe> {
  for (const hex of [EMPTY_TAGGED, EMPTY_UNTAGGED, DOC_TAGGED, DOC_UNTAGGED, DOUBLE_TAGGED])
    for (const via of ["tagged", "untagged", "codec"] as const) yield { k: "cbor", hex, via };
  for (const hex of [BYTES31, TAG200_BYTES, TEXT_HELLO, ENV_TEXT_TAGGED, ENV_TEXT_UNTAGGED, "f6"]) {
    yield { k: "cbor", hex, via: "tagged" };
    yield { k: "cbor", hex, via: "untagged" };
  }
}

/** URs given to `fromUR`: the XID type, another type, and a grammar fault. */
export function* urRecipes(): Generator<Recipe> {
  yield {
    k: "ur",
    s: "ur:xid/hdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnvsbyrdfw",
  };
  yield {
    k: "ur",
    s: "ur:xid/tpsplftpsotanshdhdcxjsdigtwneocmnybadpdlzobysbstmekteypspeotcfldynlpsfolsbintyjkrhfnoyaylftpsotansgylftanshfhdcxhslkfzemaylrwttynsdlghrydpmdfzvdglndloimaahykorefddtsguogmvlahqztansgrhdcxetlewzvlwyfdtobeytidosbamkswaomwwfyabakssakggegychesmerkcatekpcxoycsfncsfggmplgshd",
  };
  yield { k: "ur", s: "ur:envelope/tpsohskskbvofzgt" };
  yield { k: "ur", s: "ur:xid/notbytewords" };
  yield { k: "ur", s: "xid/hdcx" };
}

/** The nickname adders in sequence. */
export function* nicknameRecipes(): Generator<Recipe> {
  yield { k: "nickname", ops: [["add", "a"]] };
  yield {
    k: "nickname",
    ops: [
      ["add", "a"],
      ["add", "b"],
    ],
  };
  yield { k: "nickname", ops: [["add", ""]] };
  yield {
    k: "nickname",
    ops: [
      ["set", "a"],
      ["set", "b"],
      ["set", ""],
    ],
  };
  yield {
    k: "nickname",
    ops: [
      ["set", "a"],
      ["add", "b"],
      ["set", ""],
      ["add", "c"],
    ],
  };
}

/** Constructor inputs: URIs the siblings accept or reject, and hex references. */
export function* constructRecipes(): Generator<Recipe> {
  for (const v of [
    "https://svc.example",
    "",
    "foo",
    "http://",
    "a:b",
    "https://example.com/a b",
    "example.com",
  ]) {
    yield { k: "construct", op: "service", v };
    yield { k: "construct", op: "resolution", v };
  }
  yield { k: "construct", op: "endpoint", v: "https://e.example" };
  yield { k: "construct", op: "endpoint", v: "" };
  yield {
    k: "construct",
    op: "keyRefHex",
    v: "7a41e4c6ebb7f5e0d4c7cbd0dc6cbd7cd6f6d7a5cf6f2ec74e8fd9b7fa3b4dd1",
  };
  yield { k: "construct", op: "keyRefHex", v: "zz" };
  yield { k: "construct", op: "keyRefHex", v: "abcd" };
  yield { k: "construct", op: "delegateRefHex", v: "zz" };
}

/** The JavaScript input domain. */
export function* domainRecipes(): Generator<Recipe> {
  for (const [name, cls] of DOMAIN_CASES) yield { k: "domain", case: name, cls };
}

/** Documents whose private keys do not match their public keys. */
export function* mismatchedPairs(): Generator<Recipe> {
  const doc: DocSpec = {
    inception: { kind: "privateKeys", seed: S[0], privateSeed: S[1], scheme: "schnorr" },
  };
  yield { k: "doc", doc, out: { sign: "inception" } };
  yield { k: "doc", doc, out: { priv: "include" } };
}

export const categories: Record<string, (m: Materialized) => Generator<Recipe>> = {
  hand: () => hand(),
  decode: (m) => decodeRecipes(m),
  mutate: () => mutateRecipes(),
  docEnvelopes: () => docEnvelopes(),
  keyEnvelopes: () => keyEnvelopes(),
  serviceEnvelopes: () => serviceEnvelopes(),
  provenanceEnvelopes: () => provenanceEnvelopes(),
  cbor: () => cborRecipes(),
  ur: () => urRecipes(),
  nickname: () => nicknameRecipes(),
  construct: () => constructRecipes(),
  mismatchedPairs: () => mismatchedPairs(),
  domain: () => domainRecipes(),
  generated: () => generated(),
};

/** The golden subset: everything but the generated documents. */
export function* goldenRecipes(m: Materialized): Generator<Recipe> {
  for (const [name, gen] of Object.entries(categories)) if (name !== "generated") yield* gen(m);
}
