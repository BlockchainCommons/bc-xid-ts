/**
 * Golden vector generator (Phase 1.2). `bun scripts/generate-vectors.mjs`.
 * Materialises the golden recipe subset with the WORKING TREE and writes
 * tests/vectors/vectors.json. With VECTORS_FROM=baseline it materialises
 * with the frozen bundle instead, the way the file was first created.
 * Regenerating is a deliberate, reviewed act.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  materialize,
  recipeName,
  baselineAdapterFor,
  redesignedAdapterFor,
} from "../tests/vectors/recipes.ts";
import { goldenRecipes } from "../tests/corpus/corpus.ts";
import { baselineDeps, baselineModule, currentDeps, currentModule } from "../tests/vectors/deps.ts";
import { materializedFrom } from "../tests/vectors/materialized.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const api =
  process.env.VECTORS_FROM === "baseline"
    ? await (async () => {
        const m = await baselineModule();
        return baselineAdapterFor(m, baselineDeps(m));
      })()
    : redesignedAdapterFor(await currentModule(), currentDeps);
const vectors = [];
for (const recipe of goldenRecipes(materializedFrom(api)))
  vectors.push({ name: recipeName(recipe), recipe, expect: materialize(api, recipe) });
writeFileSync(
  join(root, "tests/vectors/vectors.json"),
  JSON.stringify({ count: vectors.length, vectors }, null, 1) + "\n",
);
const throws = vectors.filter((v) => v.expect.startsWith("throw:")).length;
console.log(
  `wrote ${vectors.length} vectors (${throws} throw) from ${process.env.VECTORS_FROM === "baseline" ? "the frozen baseline" : "working tree"}`,
);
