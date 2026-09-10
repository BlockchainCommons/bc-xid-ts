/**
 * Differential corpus (Phase 1.3) and the golden subset (Phase 1.2): seeded
 * documents covering every inception kind, key scheme, privilege, delegate
 * form, service shape, attachments, edges, custom assertions and genesis
 * marks; every output option; decodes of every golden UR with each
 * verification mode; mutation scripts with their error paths; keys and
 * provenance values on their own; the privilege table.
 */
import {
  PRIVILEGES,
  type DocSpec,
  type KeySpec,
  type Op,
  type PrivOpt,
  type Recipe,
  type Resolution,
  type SignOpt,
} from "../vectors/recipes";

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

export const categories: Record<string, (m: Materialized) => Generator<Recipe>> = {
  hand: () => hand(),
  decode: (m) => decodeRecipes(m),
  mutate: () => mutateRecipes(),
  generated: () => generated(),
};

/** The golden subset: everything hand-written plus the decodes and mutations. */
export function* goldenRecipes(m: Materialized): Generator<Recipe> {
  yield* hand();
  yield* decodeRecipes(m);
  yield* mutateRecipes();
}
