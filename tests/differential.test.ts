/**
 * Differential harness: every corpus recipe is run with the frozen
 * baseline bundle (the published packages it inlines) AND the
 * working tree; every rendered document, decode outcome, mutation result,
 * key and provenance value must be identical outside the enumerated
 * tombstones.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { materialize, recipeName, isBaselineSupported, type Recipe } from "./vectors/recipes";
import { baselineAdapterFor } from "./vectors/baseline-adapter";
import { workingTreeAdapterFor } from "./vectors/working-tree-adapter";
import { baselineDeps, baselineModule, currentDeps, currentModule } from "./vectors/deps";
import { materializedFrom } from "./vectors/materialized";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = readFileSync(join(here, "baseline/README.md"), "utf8").match(
  /Baseline sha256: ([0-9a-f]{64})/,
)?.[1];

/** Every differing line of `a` and `b` (same line count) satisfies `pred`. */
const differingLines = (a: string, b: string, pred: (x: string, y: string) => boolean): boolean => {
  const [x, y] = [a.split("\n"), b.split("\n")];
  if (x.length !== y.length) return false;
  let differ = false;
  for (let i = 0; i < x.length; i++) {
    if (x[i] === y[i]) continue;
    differ = true;
    if (!pred(x[i], y[i])) return false;
  }
  return differ;
};
/** The frozen bundle's sibling error class names (`CryptoError`, `BytewordsError`, a bare `Error`, …). */
const siblingClass = /throw:(?:[A-Z_]+_)?ERROR$/;
/** The working tree's four wrapping codes. */
const wrapping = /throw:(?:ENVELOPE_PARSING|COMPONENT|CBOR|PROVENANCE_MARK)$/;
const throws = /throw:[A-Z_]+$/;

/** Tombstones: the only allowed differences. */
const TOMBSTONES: {
  id: string;
  matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}[] = [
  {
    // The frozen bundle's envelope `Attachments.addToEnvelope` wrapped each
    // attachment under a second `'attachment'` predicate; the working tree's
    // envelope adds the assertion as it is, as the reference does.
    id: "T1 attachments single-wrapped",
    matches: (_r, a, b) =>
      a.includes("'attachment': 'attachment':") && !b.includes("'attachment': 'attachment':"),
  },
  {
    // The frozen bundle's `equals` compared public content only; the
    // reference compares every field, private keys, salts and the
    // generator included, so a round trip that omitted, elided or locked
    // them is no longer equal.
    id: "T2 equality includes private material",
    matches: (r, a, b) =>
      (r.k === "doc" || r.k === "key" || r.k === "provenance") &&
      /^roundtrip=true$/m.test(a) &&
      /^roundtrip=false$/m.test(b) &&
      a.replace(/^roundtrip=.*$/m, "") === b.replace(/^roundtrip=.*$/m, ""),
  },
  {
    // The siblings render differently from the frozen bundle's inlined
    // copies, and the reference agrees with the working tree: a key's
    // summary is its short reference (`ECPublicKey(5a76e29e)`,
    // `SchnorrPrivateKey(d780590f)`, `EncapsulationPrivateKey(e71a714b,
    // X25519PrivateKey(e71a714b))`), where the bundle printed a hex prefix
    // or the key's own reference; a provenance mark renders as
    // `ProvenanceMark(<id>)` once provenance-mark's summariser is
    // registered, where the bundle printed the tag and its array. The
    // golden vectors pin the working tree's renderings; this tombstone
    // drops those lines from both sides and requires everything else to
    // be equal, the round-trip flag included unless the row is a T2 row.
    id: "T3 sibling renderings",
    matches: (r, a, b) => {
      const t2 =
        (r.k === "doc" || r.k === "key" || r.k === "provenance") &&
        /^roundtrip=true$/m.test(a) &&
        /^roundtrip=false$/m.test(b);
      const rendered = (line: string): boolean =>
        /^(?:\s*'(?:key|privateKey)': |format=)(?:Public|Private)Keys\(/.test(line) ||
        /^\s*'provenance': (?:1347571542\(|ProvenanceMark\()/.test(line) ||
        /^format=(?:1347571542\(|ProvenanceMark\()/.test(line) ||
        (t2 && /^roundtrip=/.test(line));
      const norm = (s: string): string =>
        s
          .split("\n")
          .filter((line) => !rendered(line))
          .join("\n");
      return a !== b && norm(a) === norm(b);
    },
  },
  {
    // A failure raised by a sibling surfaced as that sibling's error in the
    // frozen bundle: its class name (`CryptoError`, `BytewordsError`, a
    // bare `Error`) or its own code (`NotLeaf`, `NotWrapped`,
    // `NotKnownValue`); the working tree's siblings throw coded errors, and
    // inside a decoder the package wraps them with the reference's codes.
    // Both sides throw on the same rows.
    id: "T4 sibling error identities",
    matches: (_r, a, b) =>
      differingLines(
        a,
        b,
        (x, y) =>
          throws.test(x) &&
          throws.test(y) &&
          ((siblingClass.test(x) && !siblingClass.test(y)) || (wrapping.test(y) && x !== y)),
      ),
  },
  {
    // The frozen bundle's envelope kept two identical assertions, so the
    // document and service parsers saw a duplicate; the working tree's
    // envelope, like the reference, adds an assertion that is already there
    // once.
    id: "T5 identical assertions added once",
    matches: (r, a, b) =>
      (r.k === "docEnvelope" || r.k === "serviceEnvelope") &&
      /^throw:DUPLICATE$/.test(a) &&
      b.startsWith("format="),
  },
  {
    // The frozen bundle's envelope accepted a non-attachment under
    // `'attachment'`; the working tree's rejects it, as the reference does.
    id: "T6 attachment objects validated",
    matches: (r, a, b) =>
      r.k === "docEnvelope" && a.startsWith("format=") && /^throw:ENVELOPE_PARSING$/.test(b),
  },
  {
    // The parsers use the reference's codes where the frozen bundle used
    // its own: a subject that is not a leaf and a `'dereferenceVia'` object
    // with assertions are `EnvelopeParsing`, not `InvalidXid` or
    // `InvalidResolutionMethod`; an `'allow'` object that is not a known
    // value is `EnvelopeParsing`, not `UnknownPrivilege`; a `'capability'`
    // or `'name'` that is not text is `Cbor`, not `EnvelopeParsing`; a
    // second or non-text `'nickname'` is rejected, not read as empty; a
    // provenance subject that is not a mark is `Cbor`.
    id: "T7 parser codes follow the reference",
    matches: (r, a, b) => {
      if (
        r.k !== "docEnvelope" &&
        r.k !== "keyEnvelope" &&
        r.k !== "serviceEnvelope" &&
        r.k !== "provenanceEnvelope"
      )
        return false;
      const pairs: [RegExp, RegExp][] = [
        [/^throw:INVALID_XID$/, /^throw:ENVELOPE_PARSING$/],
        [/^throw:INVALID_RESOLUTION_METHOD$/, /^throw:ENVELOPE_PARSING$/],
        [/^throw:UNKNOWN_PRIVILEGE$/, /^throw:ENVELOPE_PARSING$/],
        [/^throw:ENVELOPE_PARSING$/, /^throw:CBOR$/],
        [/^throw:PROVENANCE_MARK_ERROR$/, /^throw:CBOR$/],
        [/^format=/, /^throw:(?:ENVELOPE_PARSING|CBOR)$/],
      ];
      return pairs.some(([x, y]) => x.test(a) && y.test(b));
    },
  },
];

const baselineMod = await baselineModule();
const baseline = baselineAdapterFor(baselineMod, baselineDeps(baselineMod));
const current = workingTreeAdapterFor(await currentModule(), currentDeps);
const materialized = materializedFrom(baseline);

/**
 * The frozen bundle renders a rejection as `throw:<UPPER_SNAKE code>|<message>`
 * (or the error's class name); the working tree as
 * `throw:<Code>[<inner>]|<message>`. Both reduce to `throw:<UPPER_SNAKE>` for
 * the comparison, so only the code is compared.
 */
export const normalizeCode = (s: string): string =>
  s.replace(
    /throw:([A-Za-z_]+)(?:\[[A-Za-z]+\])?(?:\|[^\n]*)?/g,
    (_m, code: string) => `throw:${code.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase()}`,
  );

describe("differential: baseline vs working tree", () => {
  it("baseline bundle integrity", () => {
    const sha = createHash("sha256")
      .update(readFileSync(join(here, "baseline/xid-baseline.mjs")))
      .digest("hex");
    expect(sha).toBe(BASELINE_SHA256);
  });
  it("skips only the categories the frozen bundle cannot run", () => {
    const skipped = Object.entries(categories)
      .filter(([, gen]) => ![...gen(materialized)].some(isBaselineSupported))
      .map(([name]) => name);
    expect(skipped).toEqual(["cbor", "domain"]);
  });
  for (const [name, gen] of Object.entries(categories)) {
    if (name === "cbor" || name === "domain") continue;
    it(`category ${name}`, { timeout: 1_800_000 }, () => {
      let n = 0;
      const diffs: string[] = [];
      for (const recipe of gen(materialized)) {
        if (!isBaselineSupported(recipe)) continue;
        n++;
        const a = normalizeCode(materialize(baseline, recipe));
        const b = normalizeCode(materialize(current, recipe));
        const tomb = TOMBSTONES.find((t) => t.matches(recipe, a, b));
        if (a !== b && tomb === undefined)
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 120)} !== ${b.slice(0, 120)}`);
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
    });
  }
});
