/**
 * Baseline vs working tree micro-benchmarks (Phase 2.3).
 *
 *   bun run build && bun bench/benchmark.mjs
 */
import * as baseline from "../tests/baseline/xid-baseline.mjs";
import * as current from "../dist/index.mjs";
import { PrivateKeyBase } from "@blockchaincommons/components";

const N = 200;
const seeds = Array.from({ length: 11 }, (_, i) => Uint8Array.from({ length: 32 }, (_, j) => (i * 31 + j * 7 + 1) & 0xff));
const api = (m, redesigned) => {
  const pkb = (s) => (m.PrivateKeyBase ? m.PrivateKeyBase.fromData(s) : PrivateKeyBase.from(s));
  const build = () => {
    const base = pkb(seeds[0]);
    const doc = redesigned
      ? m.XIDDocument.from({ inceptionKey: base })
      : m.XIDDocument.new({ type: "privateKeyBase", privateKeyBase: base }, { type: "none" });
    for (let i = 1; i < 11; i++) {
      const p = pkb(seeds[i]);
      const key = redesigned ? m.Key.from(p.ed25519PublicKeys(), { privateKeys: p.ed25519PrivateKeys() }) : m.Key.newWithPrivateKeys(p.ed25519PrivateKeys(), p.ed25519PublicKeys());
      doc.addKey(key);
    }
    return doc;
  };
  const sign = (doc) => (redesigned ? doc.toEnvelope({ sign: "inception" }) : doc.toEnvelope(m.XIDPrivateKeyOptions.Omit, m.XIDGeneratorOptions.Omit, { type: "inception" }));
  const verify = (env) => (redesigned ? m.XIDDocument.fromEnvelope(env, { verify: "inception" }) : m.XIDDocument.fromEnvelope(env, undefined, m.XIDVerifySignature.Inception));
  const parse = (env) => (redesigned ? m.XIDDocument.fromEnvelope(env) : m.XIDDocument.fromEnvelope(env));
  return { build, sign, verify, parse };
};
const time = (fn, n) => { fn(); const t0 = performance.now(); for (let i = 0; i < n; i++) fn(); return (performance.now() - t0) / n; };
const run = (m, redesigned) => {
  const a = api(m, redesigned);
  const doc = a.build();
  const signed = a.sign(doc);
  return [
    ["build a 10-key document", time(() => a.build(), N)],
    ["sign with the inception key", time(() => a.sign(doc), 50)],
    ["parse and verify the signature", time(() => a.verify(signed), 50)],
    ["parse (no verification)", time(() => a.parse(signed), N)],
  ];
};
const before = run(baseline, false);
const after = run(current, typeof current.XIDDocument.from === "function");
console.log(`${"operation".padEnd(34)} ${"baseline".padStart(10)} ${"current".padStart(10)} ${"ratio".padStart(7)}`);
for (let i = 0; i < before.length; i++) {
  const [label, b] = before[i]; const c = after[i][1];
  console.log(`${label.padEnd(34)} ${b.toFixed(3).padStart(8)}ms ${c.toFixed(3).padStart(8)}ms ${(c / b).toFixed(2).padStart(6)}×`);
}
