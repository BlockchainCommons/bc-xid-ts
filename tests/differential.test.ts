/**
 * Differential harness: every corpus recipe is run with the frozen
 * baseline bundle (the package as it shipped at 1.0.0-beta.2, its siblings
 * inlined) AND the working tree; every rendered document, decode outcome,
 * mutation result, key and provenance value must be identical outside the
 * enumerated tombstones.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { materialize, recipeName, isBaselineSupported, type Recipe } from "./vectors/recipes";
import { workingTreeAdapterFor } from "./vectors/working-tree-adapter";
import { baselineDeps, baselineModule, currentDeps, currentModule } from "./vectors/deps";
import { materializedFrom } from "./vectors/materialized";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = readFileSync(join(here, "baseline/README.md"), "utf8").match(
  /Baseline sha256: ([0-9a-f]{64})/,
)?.[1];

/** Tombstones: the only allowed differences from the frozen bundle. */
const TOMBSTONES: {
  id: string;
  /** `false` until the change lands: the rows must still agree with the baseline. */
  landed?: boolean;
  matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}[] = [
  {
    id: "T1 removeResolutionMethod returns the URI; the frozen bundle a boolean",
    landed: true,
    matches: (r) => r.k === "mutate" && r.ops.some((o) => o[0] === "removeResolution"),
  },
  {
    id: "T2 takeGenerator returns the generator and its salt; the frozen bundle a boolean",
    landed: true,
    matches: (r) => r.k === "provenance" && r.take === true,
  },
  {
    id: "T3 removeEndpoint, removeKeyReference, removeDelegateReference did not exist",
    landed: true,
    matches: (r) =>
      r.k === "mutate" &&
      r.ops.some((o) =>
        ["removeEndpoint", "removeKeyReference", "removeDelegateReference"].includes(o[0]),
      ),
  },
  {
    id: "T4 Delegate.from copies the controller; the frozen bundle kept the caller's object",
    landed: true,
    matches: (r) =>
      r.k === "doc" && (r.doc.delegates ?? []).some((d) => (d.laterResolution?.length ?? 0) > 0),
  },
];

const baselineMod = await baselineModule();
const baseline = workingTreeAdapterFor(baselineMod, baselineDeps(baselineMod));
const current = workingTreeAdapterFor(await currentModule(), currentDeps);
const materialized = materializedFrom(baseline);

/** A rejection reduces to `throw:<Code>[<inner>]`: the codes are compared, the message is not. */
export const normalizeCode = (s: string): string =>
  s.replace(/throw:([A-Za-z_]+(?:\[[A-Za-z]+\])?)(?:\|[^\n]*)?/g, "throw:$1");

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
    expect(skipped).toEqual(["domain"]);
  });
  for (const [name, gen] of Object.entries(categories)) {
    if (name === "domain") continue;
    it(`category ${name}`, { timeout: 1_800_000 }, () => {
      let n = 0;
      const diffs: string[] = [];
      for (const recipe of gen(materialized)) {
        if (!isBaselineSupported(recipe)) continue;
        n++;
        const a = normalizeCode(materialize(baseline, recipe));
        const b = normalizeCode(materialize(current, recipe));
        const tomb = TOMBSTONES.find((t) => t.matches(recipe, a, b));
        if (a !== b && (tomb === undefined || tomb.landed === false))
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 120)} !== ${b.slice(0, 120)}`);
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
    });
  }
});
