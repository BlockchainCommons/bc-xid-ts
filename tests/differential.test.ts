/**
 * Differential harness (Phase 1.3): every corpus recipe is run with the
 * frozen baseline bundle (the published pre-redesign packages) AND the
 * working tree; every rendered document, decode outcome, mutation result,
 * key and provenance value must be identical outside the enumerated
 * tombstones.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  materialize,
  baselineAdapterFor,
  redesignedAdapterFor,
  recipeName,
  type Recipe,
} from "./vectors/recipes";
import { baselineDeps, baselineModule, currentDeps, currentModule } from "./vectors/deps";
import { materializedFrom } from "./vectors/materialized";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = readFileSync(join(here, "baseline/README.md"), "utf8").match(
  /Baseline sha256: ([0-9a-f]{64})/,
)?.[1];

/** Tombstones: the only allowed differences. */
const TOMBSTONES: {
  id: string;
  landed: boolean;
  matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}[] = [
  {
    // The pre-redesign envelope's `Attachments.addToEnvelope` wrapped each
    // attachment under a second `'attachment'` predicate; the redesigned
    // envelope adds the assertion as it is, as the reference does.
    id: "T1 attachments single-wrapped",
    landed: true,
    matches: (_r, a, b) =>
      a.includes("'attachment': 'attachment':") && !b.includes("'attachment': 'attachment':"),
  },
  {
    // The pre-redesign `equals` compared public content only; the
    // reference compares every field, private keys, salts and the
    // generator included, so a round trip that omitted, elided or locked
    // them is no longer equal.
    id: "T2 equality includes private material",
    landed: true,
    matches: (r, a, b) =>
      (r.k === "doc" || r.k === "key" || r.k === "provenance") &&
      /^roundtrip=true$/m.test(a) &&
      /^roundtrip=false$/m.test(b) &&
      a.replace(/^roundtrip=.*$/m, "") === b.replace(/^roundtrip=.*$/m, ""),
  },
];

const baselineMod = await baselineModule();
const baseline = baselineAdapterFor(baselineMod, baselineDeps(baselineMod));
const current = redesignedAdapterFor(await currentModule(), currentDeps);
const materialized = materializedFrom(baseline);

describe("differential: baseline vs working tree", () => {
  it("baseline bundle integrity", () => {
    const sha = createHash("sha256")
      .update(readFileSync(join(here, "baseline/xid-baseline.mjs")))
      .digest("hex");
    expect(sha).toBe(BASELINE_SHA256);
  });
  for (const [name, gen] of Object.entries(categories)) {
    it(`category ${name}`, { timeout: 1_800_000 }, () => {
      let n = 0;
      const diffs: string[] = [];
      for (const recipe of gen(materialized)) {
        n++;
        const a = materialize(baseline, recipe);
        const b = materialize(current, recipe);
        const tomb = TOMBSTONES.find((t) => t.matches(recipe, a, b));
        if (a !== b && tomb?.landed !== true)
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 120)} !== ${b.slice(0, 120)}`);
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
    });
  }
});
