// Bench: build a document (inception key, genesis mark, a key, a service, a
// delegate), sign it into an envelope, parse it back verified, advance the
// provenance chain. Run: bun run bench   (builds dist first)
import { performance } from "node:perf_hooks";
import { PrivateKeyBase } from "@blockchaincommons/components";
import { DirectoryConfig, setDirectoryConfig } from "@blockchaincommons/known-values";
import { registerTags } from "@blockchaincommons/provenance-mark";
import { Key, Service, XIDDocument } from "../dist/index.mjs";

setDirectoryConfig(new DirectoryConfig());
registerTags();

const time = (label, iterations, fn) => {
  fn();
  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const ms = (performance.now() - t0) / iterations;
  console.log(`${label.padEnd(48)} ${ms.toFixed(3)} ms/op`);
};

const inception = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const other = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => 255 - i));
const build = () => {
  const doc = XIDDocument.from({
    inceptionKey: inception,
    genesis: { passphrase: "bench", date: new Date("2023-06-20T12:00:00Z") },
  });
  doc.addKey(Key.fromPrivateKeyBase(other));
  const service = Service.from("https://example.com/api");
  service.addKey(doc.inceptionKey);
  service.addAllow("All");
  doc.addService(service);
  return doc;
};
time("build document with genesis, key, service", 50, build);
const doc = build();
time("toEnvelope signed, private keys included", 50, () =>
  doc.toEnvelope({ privateKeys: "include", generator: "include", sign: "inception" }),
);
const envelope = doc.toEnvelope({
  privateKeys: "include",
  generator: "include",
  sign: "inception",
});
time("fromEnvelope verified", 50, () =>
  XIDDocument.fromEnvelope(envelope, { verify: "inception" }),
);
time("nextProvenanceMarkWithEmbeddedGenerator", 50, () => {
  const d = XIDDocument.fromEnvelope(envelope);
  d.nextProvenanceMarkWithEmbeddedGenerator({ date: new Date("2023-06-21T12:00:00Z") });
});
