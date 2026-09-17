/**
 * The JavaScript input domain at the document's boundary: an argument
 * that is not an instance of the class the reference's type demands is a
 * `TypeError` naming it, wherever a plain object would otherwise be read
 * as if it were one. Dates are a `Date` or a `CborDate`; whether they
 * hold a time is the mark generator's check.
 */
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { PrivateKeyBase } from "@blockchaincommons/components";
import { CborDate } from "@blockchaincommons/dcbor";
import { ProvenanceMarkError, ProvenanceMarkGenerator } from "@blockchaincommons/provenance-mark";
import { Delegate, Key, Provenance, Service, XIDDocument, XIDError } from "../src";

const alice = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const bob = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => 255 - i));
const at = new Date("2025-01-01T00:00:00Z");
const genesis = { passphrase: "wolf", resolution: "low", date: at } as const;

const docWithGenerator = (): XIDDocument => XIDDocument.from({ inceptionKey: alice, genesis });
const markOnly = (): XIDDocument => {
  const doc = XIDDocument.from({ inceptionKey: alice });
  doc.setProvenance(must(docWithGenerator().provenance));
  return doc;
};
const freshGenerator = (): ProvenanceMarkGenerator =>
  ProvenanceMarkGenerator.fromPassphrase("low", "wolf");
const provenance = (): Provenance => {
  const generator = freshGenerator();
  return Provenance.from(generator.next(at), { generator });
};
const bare = (): XIDDocument => XIDDocument.from({ inceptionKey: alice });
const must = <T>(value: T | undefined): T => {
  if (value === undefined) throw new Error("expected a value");
  return value;
};

/** Every guarded call, the plain value it must reject, and the argument the message names. */
const GUARDS: [string, (bogus: unknown) => unknown, string][] = [
  [
    "XIDDocument.from inceptionKey",
    (b) => XIDDocument.from({ inceptionKey: b as never }),
    "inceptionKey",
  ],
  [
    "XIDDocument.from inceptionKey pair publicKeys",
    (b) =>
      XIDDocument.from({
        inceptionKey: { publicKeys: b, privateKeys: alice.schnorrPrivateKeys() } as never,
      }),
    "inceptionKey.publicKeys",
  ],
  [
    "XIDDocument.from inceptionKey pair privateKeys",
    (b) =>
      XIDDocument.from({
        inceptionKey: { publicKeys: alice.schnorrPublicKeys(), privateKeys: b } as never,
      }),
    "inceptionKey.privateKeys",
  ],
  ["addKey", (b) => bare().addKey(b as never), "key"],
  ["addService", (b) => bare().addService(b as never), "service"],
  ["addDelegate", (b) => bare().addDelegate(b as never), "delegate"],
  ["setProvenance", (b) => bare().setProvenance(b as never), "provenance"],
  [
    "setProvenanceWithGenerator generator",
    (b) => bare().setProvenanceWithGenerator(b as never, must(markOnly().provenance)),
    "generator",
  ],
  [
    "setProvenanceWithGenerator mark",
    (b) => bare().setProvenanceWithGenerator(freshGenerator(), b as never),
    "mark",
  ],
  [
    "nextProvenanceMarkWithProvidedGenerator generator",
    (b) => markOnly().nextProvenanceMarkWithProvidedGenerator(b as never),
    "generator",
  ],
  [
    "nextProvenanceMarkWithEmbeddedGenerator date",
    (b) => docWithGenerator().nextProvenanceMarkWithEmbeddedGenerator({ date: b as never }),
    "date",
  ],
  [
    "nextProvenanceMarkWithProvidedGenerator date",
    (b) =>
      markOnly().nextProvenanceMarkWithProvidedGenerator(freshGenerator(), { date: b as never }),
    "date",
  ],
  [
    "XIDDocument.from genesis.date",
    (b) => XIDDocument.from({ inceptionKey: alice, genesis: { ...genesis, date: b as never } }),
    "genesis.date",
  ],
  ["XIDDocument.equals", (b) => bare().equals(b as never), "other"],
  ["Provenance.from mark", (b) => Provenance.from(b as never), "mark"],
  [
    "Provenance.from generator",
    (b) => Provenance.from(must(markOnly().provenance), { generator: b as never }),
    "generator",
  ],
  ["Provenance.setMark", (b) => provenance().setMark(b as never), "mark"],
  ["Provenance.setGenerator", (b) => provenance().setGenerator(b as never), "generator"],
  ["Provenance.equals", (b) => provenance().equals(b as never), "other"],
];

/** The message names the argument, or one of its fields for the inception key pair. */
const names = (argument: string): RegExp =>
  new RegExp(`^${argument.replace(".", "\\.")}(\\.\\w+)? must be `);

const PLAIN_VALUES: unknown[] = [
  {},
  { publicKeys: {}, privateKeys: {} },
  "x",
  1,
  [],
  null,
  Symbol("s"),
  () => {},
];

describe("instance guards", () => {
  describe.each(GUARDS)("%s", (_name, call, argument) => {
    it.each(
      PLAIN_VALUES.map((v) => [
        typeof v === "symbol" ? "symbol" : (JSON.stringify(v) ?? String(v)),
        v,
      ]),
    )("rejects %s with a TypeError naming the argument", (_label, value) => {
      expect(() => call(value)).toThrow(TypeError);
      expect(() => call(value)).toThrow(names(argument));
    });
  });

  it("rejects any non-instance value with a TypeError (property; undefined is an absent option)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...GUARDS),
        fc
          .anything({ withObjectString: true, withMap: true, withSet: true, withDate: false })
          .filter((v) => v !== undefined),
        ([, call, argument], value) => {
          let thrown: unknown;
          try {
            call(value);
          } catch (e) {
            thrown = e;
          }
          return (
            thrown instanceof TypeError &&
            !("code" in thrown) &&
            names(argument).test(thrown.message)
          );
        },
      ),
      { numRuns: 300 },
    );
  });

  it("accepts the real classes at every guarded call", () => {
    const doc = bare();
    const key = Key.fromPrivateKeyBase(bob);
    doc.addKey(key);
    const service = Service.from("https://example.com/api");
    service.addKey(key);
    service.addAllow("All");
    doc.addService(service);
    doc.addDelegate(Delegate.from(XIDDocument.from({ inceptionKey: bob })));
    const generator = freshGenerator();
    const mark = generator.next(at);
    doc.setProvenanceWithGenerator(generator, mark);
    doc.nextProvenanceMarkWithEmbeddedGenerator({ date: new Date("2025-01-02T00:00:00Z") });
    expect(must(doc.provenance).seq).toBe(1);
    doc.setProvenance(mark);
    expect(doc.provenanceGenerator).toBeUndefined();
    const continuing = freshGenerator();
    continuing.next(at);
    doc.nextProvenanceMarkWithProvidedGenerator(continuing);
    expect(must(doc.provenance).seq).toBe(1);
    expect(doc.equals(doc)).toBe(true);
    const p = provenance();
    p.setMark(p.mark);
    p.setGenerator(must(p.generator));
    expect(p.equals(p)).toBe(true);
  });
});

describe("dates", () => {
  it("takes a CborDate at genesis.date and at the next mark", () => {
    const fromDate = docWithGenerator();
    const fromCbor = XIDDocument.from({
      inceptionKey: alice,
      genesis: { ...genesis, date: CborDate.fromString("2025-01-01T00:00:00Z") },
    });
    expect(must(fromCbor.provenance).equals(must(fromDate.provenance))).toBe(true);
    fromDate.nextProvenanceMarkWithEmbeddedGenerator({ date: new Date("2025-01-02T00:00:00Z") });
    fromCbor.nextProvenanceMarkWithEmbeddedGenerator({
      date: CborDate.fromString("2025-01-02T00:00:00Z"),
    });
    expect(must(fromCbor.provenance).equals(must(fromDate.provenance))).toBe(true);
    expect(must(fromCbor.provenance).seq).toBe(1);
  });

  it("surfaces a Date without a time as ProvenanceMark[InvalidDate]", () => {
    for (const call of [
      () => XIDDocument.from({ inceptionKey: alice, genesis: { ...genesis, date: new Date(NaN) } }),
      () => docWithGenerator().nextProvenanceMarkWithEmbeddedGenerator({ date: new Date(NaN) }),
    ]) {
      let thrown: unknown;
      try {
        call();
      } catch (e) {
        thrown = e;
      }
      expect(XIDError.isXIDError(thrown) && thrown.is("ProvenanceMark")).toBe(true);
      const cause = (thrown as XIDError).cause;
      expect(ProvenanceMarkError.isProvenanceMarkError(cause) && cause.is("InvalidDate")).toBe(
        true,
      );
    }
  });
});

describe("Provenance.equals", () => {
  it("compares generators through ProvenanceMarkGenerator.equals", () => {
    const envelope = provenance().toEnvelope({ generator: "include" });
    const a = Provenance.fromEnvelope(envelope);
    const b = Provenance.fromEnvelope(envelope);
    expect(a.equals(b)).toBe(true);
    must(b.generator).next(new Date("2025-01-02T00:00:00Z"));
    expect(a.mark.equals(b.mark)).toBe(true);
    expect(a.equals(b)).toBe(false);

    const doc = docWithGenerator().toEnvelope({ generator: "include" });
    const x = XIDDocument.fromEnvelope(doc);
    const y = XIDDocument.fromEnvelope(doc);
    expect(x.equals(y)).toBe(true);
    must(y.provenanceGenerator).next(new Date("2025-01-02T00:00:00Z"));
    expect(must(x.provenance).equals(must(y.provenance))).toBe(true);
    expect(x.equals(y)).toBe(false);
  });
});
