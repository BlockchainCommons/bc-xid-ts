/**
 * The golden documents materialised through an adapter, so the decode
 * recipes can carry real URs (unsigned, signed, with private keys).
 */
import { materialize, type VectorApi } from "./recipes";
import { referenceDocs, type Materialized } from "../corpus/corpus";

export function materializedFrom(api: VectorApi): Materialized {
  const m: Materialized = { urs: [] };
  for (const recipe of referenceDocs()) {
    if (recipe.k !== "doc") continue;
    const out = materialize(api, recipe);
    const ur = out.match(/^ur=(.*)$/m)?.[1];
    if (ur !== undefined && ur !== "")
      m.urs.push({ ur, signed: false, name: recipe.doc.inception.seed.slice(0, 8) });
  }
  return m;
}
