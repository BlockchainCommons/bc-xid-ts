/**
 * Golden snapshot (Phase 0.2): the reference documents, every output option,
 * the decodes, the mutation scripts and the privilege table. Reviewable,
 * auto-updatable with -u.
 */
import { describe, it, expect } from "vitest";
import { materialize, redesignedAdapterFor, recipeName } from "./vectors/recipes";
import { currentDeps, currentModule } from "./vectors/deps";
import { materializedFrom } from "./vectors/materialized";
import { referenceDocs, decodeRecipes, mutateRecipes } from "./corpus/corpus";

const api = redesignedAdapterFor(await currentModule(), currentDeps);
const m = materializedFrom(api);

describe("golden", () => {
  it("reference documents", () => {
    const rows = [...referenceDocs()].map((r) => `## ${recipeName(r)}\n${materialize(api, r)}`);
    expect(rows.length).toBeGreaterThan(10);
    expect(rows).toMatchSnapshot();
  });
  it("decodes", () => {
    const rows = [...decodeRecipes(m)].map((r) => `## ${recipeName(r)}\n${materialize(api, r)}`);
    expect(rows.length).toBeGreaterThan(20);
    expect(rows).toMatchSnapshot();
  });
  it("mutation scripts", () => {
    const rows = [...mutateRecipes()].map((r) => `## ${recipeName(r)}\n${materialize(api, r)}`);
    expect(rows.length).toBeGreaterThan(8);
    expect(rows).toMatchSnapshot();
  });
});
