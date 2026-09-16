/**
 * Golden vector suite: the committed freeze of every document,
 * decode, mutation, key and provenance outcome. Changes only through
 * `bun run vectors:generate`.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { materialize, type Recipe, type Outcome } from "./vectors/recipes";
import { workingTreeAdapterFor } from "./vectors/working-tree-adapter";
import { currentDeps, currentModule } from "./vectors/deps";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { name: string; recipe: Recipe; expect: Outcome }[];
};
const api = workingTreeAdapterFor(await currentModule(), currentDeps);

describe("golden vectors (frozen)", () => {
  it("fixture is self-consistent and non-trivial", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThanOrEqual(350);
  });
  it("every vector matches", { timeout: 300_000 }, () => {
    const diffs: string[] = [];
    for (const v of vectors) {
      const got = materialize(api, v.recipe);
      if (got !== v.expect)
        diffs.push(`${v.name}: ${got.slice(0, 120)} !== ${v.expect.slice(0, 120)}`);
    }
    expect(diffs).toEqual([]);
  });
});
