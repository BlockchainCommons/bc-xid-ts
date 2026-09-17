/**
 * Snapshot of the behaviours at the object boundary the vectors do not
 * reach: a `CborDate` at the two date inputs, plain objects where a key,
 * service, delegate, generator, mark or document goes, and the
 * provenance's equality guard. Reviewable, auto-updatable with -u.
 */
import { describe, expect, it } from "vitest";
import { CborDate } from "@blockchaincommons/dcbor";
import { PrivateKeyBase } from "@blockchaincommons/components";
import { PROVENANCE } from "@blockchaincommons/known-values";
import { Provenance, XIDDocument } from "../src";

const outcome = (f: () => unknown): string => {
  try {
    const v = f();
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch (e) {
    const x = e as { code?: string; name: string; message: string };
    return `throw:${x.code ?? x.name}|${x.message.replace(/\(evaluating '[^']*'\)/, "(evaluating …)")}`;
  }
};
const base = PrivateKeyBase.from(new Uint8Array(32).fill(7));
const fresh = (): XIDDocument =>
  XIDDocument.from({
    inceptionKey: base,
    genesis: { passphrase: "Wolf", date: new Date("2023-06-20T12:00:00Z") },
  });

describe("boundary behaviours", () => {
  it("a CborDate at the date inputs", () => {
    const date = CborDate.fromString("2023-06-21T12:00:00Z") as unknown as Date;
    expect([
      outcome(
        () =>
          XIDDocument.from({ inceptionKey: base, genesis: { passphrase: "Wolf", date } }).provenance
            ?.seq,
      ),
      outcome(() => {
        const doc = fresh();
        doc.nextProvenanceMarkWithEmbeddedGenerator({ date });
        return doc.provenance?.seq;
      }),
      outcome(() => {
        const doc = fresh();
        doc.nextProvenanceMarkWithEmbeddedGenerator({ date: new Date(NaN) });
        return doc.provenance?.seq;
      }),
    ]).toMatchSnapshot();
  });

  it("plain objects where instances go", () => {
    const doc = fresh();
    expect([
      outcome(() => XIDDocument.from({ inceptionKey: { foo: 1 } as never }).xid.toString()),
      outcome(() =>
        XIDDocument.from({
          inceptionKey: { publicKeys: {}, privateKeys: {} } as never,
        }).xid.toString(),
      ),
      outcome(() => doc.addKey({} as never)),
      outcome(() => doc.addService({} as never)),
      outcome(() => doc.addDelegate({} as never)),
      outcome(() => doc.equals({} as never)),
      outcome(() => doc.nextProvenanceMarkWithProvidedGenerator({} as never)),
      outcome(() => {
        const d = fresh();
        d.setProvenance("x" as never);
        return typeof d.provenance;
      }),
      outcome(() => typeof Provenance.from({} as never).mark),
      outcome(() => {
        const d = fresh();
        d.setProvenanceWithGenerator(d.provenance as never, d.provenanceGenerator as never);
        return typeof d.provenance;
      }),
      outcome(() => {
        const p = Provenance.fromEnvelope(
          doc.toEnvelope({ generator: "include" }).objectForPredicate(PROVENANCE),
        );
        return p.equals({} as never);
      }),
    ]).toMatchSnapshot();
  });
});
