/**
 * The error contract, the decode boundary, the JavaScript-domain guards,
 * the CBOR and UR decoders, and the copy-out and live-handle policy.
 */
import { PrivateKeyBase, URI } from "@blockchaincommons/components";
import { CborError, cbor, decodeCbor, taggedValue, Tag } from "@blockchaincommons/dcbor";
import { Envelope, EnvelopeError } from "@blockchaincommons/envelope";
import {
  CAPABILITY,
  DELEGATE,
  DEREFERENCE_VIA,
  KEY,
  NICKNAME,
  NOTE,
  PROVENANCE,
  PROVENANCE_GENERATOR,
} from "@blockchaincommons/known-values";
import { ProvenanceMarkError } from "@blockchaincommons/provenance-mark";
import { UR } from "@blockchaincommons/uniform-resources";
import {
  Delegate,
  Key,
  Permissions,
  Provenance,
  Service,
  XIDDocument,
  XIDError,
  XID_ERROR_CODES,
  privilegeFromEnvelope,
  type XIDErrorCode,
} from "../src";

const unhex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
const alice = PrivateKeyBase.from(
  unhex("7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed"),
);
const bob = PrivateKeyBase.from(
  unhex("518684c556472008a67932f7c682125b50cb72e8216f6906358fdaf28d354553"),
);
const wolf = {
  passphrase: "wolf",
  resolution: "low" as const,
  date: new Date("2025-01-01T00:00:00Z"),
};

const caught = (f: () => unknown): unknown => {
  try {
    f();
  } catch (e) {
    return e;
  }
  return undefined;
};
const xidError = (f: () => unknown): XIDError => {
  const e = caught(f);
  if (!XIDError.isXIDError(e)) throw new Error(`expected an XIDError, got ${String(e)}`);
  return e;
};

describe("XIDError", () => {
  it("is an instance of its class and narrows on its code", () => {
    const e = XIDError.duplicate("key");
    expect(XIDError.isXIDError(e)).toBe(true);
    expect(XIDError.isXIDError({ name: "XIDError", code: "Duplicate" })).toBe(false);
    expect(XIDError.isXIDError(Object.assign(new Error("x"), { code: "Duplicate" }))).toBe(false);
    if (e.is("Duplicate")) expect(e.details.item).toBe("key");
    expect(e.is("NotFound")).toBe(false);
    expect(e.name).toBe("XIDError");
    expect(e.message).toBe("duplicate item: key");
  });

  it("lists every code once", () => {
    expect(new Set(XID_ERROR_CODES).size).toBe(XID_ERROR_CODES.length);
    expect(XID_ERROR_CODES).toHaveLength(29);
  });

  it("carries the fields of each code in details", () => {
    expect(XIDError.unexpectedPredicate("61").details).toEqual({
      code: "UnexpectedPredicate",
      predicate: "61",
    });
    expect(XIDError.unknownKeyReference("Reference(1234abcd)", "https://s").details).toEqual({
      code: "UnknownKeyReference",
      reference: "Reference(1234abcd)",
      uri: "https://s",
    });
    expect(XIDError.sequenceMismatch(2, 5).message).toBe(
      "generator sequence mismatch: expected 2, got 5",
    );
    expect(XIDError.chainIdMismatch(new Uint8Array([1]), new Uint8Array([2])).message).toBe(
      "generator chain ID mismatch: expected 01, got 02",
    );
    expect(XIDError.invalidXid().details).toEqual({ code: "InvalidXid" });
  });

  it("wraps a sibling error with the reference's message and keeps it as the cause", () => {
    const inner = EnvelopeError.notLeaf();
    const e = XIDError.envelopeParsing(inner);
    expect(e.message).toBe("envelope parsing error");
    expect(e.details).toEqual({ code: "EnvelopeParsing", message: inner.message });
    expect(e.cause).toBe(inner);
    expect(XIDError.cbor("text").details).toEqual({ code: "Cbor", message: "text" });
    expect(XIDError.component(undefined).details).toEqual({ code: "Component", message: "" });
    expect(XIDError.provenanceMark(42).details).toEqual({ code: "ProvenanceMark", message: "" });
    const decode = XIDError.cborDecode(CborError.custom("bad"));
    expect(decode.message).toBe("bad");
    expect(decode.code).toBe("Cbor");
  });
});

describe("decode boundary", () => {
  const doc = XIDDocument.from({ inceptionKey: alice.schnorrPublicKeys() });

  const parseWith = (predicate: unknown, object: unknown): XIDError =>
    xidError(() =>
      XIDDocument.fromEnvelope(doc.toEnvelope().addAssertion(predicate as never, object as never)),
    );

  it("wraps envelope failures as EnvelopeParsing with the envelope error as cause", () => {
    const e = xidError(() => XIDDocument.fromEnvelope(Envelope.knownValue(1)));
    expect(e.code).toBe("EnvelopeParsing");
    expect(EnvelopeError.isEnvelopeError(e.cause) && e.cause.code).toBe("NotLeaf");
    const wrongDelegate = parseWith(DELEGATE, "x");
    expect(wrongDelegate.code).toBe("EnvelopeParsing");
    expect(EnvelopeError.isEnvelopeError(wrongDelegate.cause) && wrongDelegate.cause.code).toBe(
      "NotWrapped",
    );
  });

  it("wraps decoder failures as Cbor with the dcbor error as cause", () => {
    const e = xidError(() => XIDDocument.fromEnvelope(Envelope.from("hello")));
    expect(e.code).toBe("Cbor");
    expect(e.message).toBe("CBOR error");
    expect(CborError.isCborError(e.cause) && e.cause.code).toBe("WrongType");
    expect(parseWith(KEY, "text").code).toBe("Cbor");
    expect(parseWith(PROVENANCE, "x").code).toBe("Cbor");
  });

  it("keeps the package's own codes", () => {
    expect(parseWith(DEREFERENCE_VIA, 42).code).toBe("InvalidResolutionMethod");
    expect(parseWith(DEREFERENCE_VIA, "not a uri").code).toBe("InvalidResolutionMethod");
    const node = Envelope.from(URI.from("https://r.example")).addAssertion(NOTE, "n");
    expect(parseWith(DEREFERENCE_VIA, node).code).toBe("EnvelopeParsing");
  });

  it("reads a nickname as the reference does", () => {
    const pub = Envelope.from(alice.schnorrPublicKeys());
    expect(Key.fromEnvelope(pub.addAssertion(NICKNAME, "a")).nickname).toBe("a");
    const twice = xidError(() =>
      Key.fromEnvelope(pub.addAssertion(NICKNAME, "a").addAssertion(NICKNAME, "b")),
    );
    expect(twice.code).toBe("EnvelopeParsing");
    expect(EnvelopeError.isEnvelopeError(twice.cause) && twice.cause.code).toBe(
      "AmbiguousPredicate",
    );
    const number = xidError(() => Key.fromEnvelope(pub.addAssertion(NICKNAME, 5)));
    expect(number.code).toBe("EnvelopeParsing");
    expect(EnvelopeError.isEnvelopeError(number.cause) && number.cause.code).toBe("Cbor");
  });

  it("reads permissions and privileges as the reference does", () => {
    expect(xidError(() => privilegeFromEnvelope(Envelope.from("Sign"))).code).toBe(
      "EnvelopeParsing",
    );
    expect(xidError(() => privilegeFromEnvelope(Envelope.knownValue(NOTE))).code).toBe(
      "UnknownPrivilege",
    );
    const svc = Envelope.from(URI.from("https://svc.example"));
    expect(xidError(() => Service.fromEnvelope(svc.addAssertion(CAPABILITY, 5))).code).toBe("Cbor");
    expect(xidError(() => Service.fromEnvelope(svc.addAssertion(NOTE, "n"))).details).toEqual({
      code: "UnexpectedPredicate",
      predicate: "4",
    });
    expect(xidError(() => Service.fromEnvelope(svc.addAssertion("foo", "bar"))).code).toBe(
      "EnvelopeParsing",
    );
  });

  it("wraps a provenance-mark failure as ProvenanceMark", () => {
    const mark = XIDDocument.from({ inceptionKey: alice, genesis: wolf }).provenance;
    if (mark === undefined) throw new Error("no mark");
    const generatorAssertion = Envelope.assertion(PROVENANCE_GENERATOR, "x").addSalt();
    const e = xidError(() =>
      Provenance.fromEnvelope(Envelope.from(mark).addAssertionEnvelope(generatorAssertion)),
    );
    expect(e.code).toBe("ProvenanceMark");
    expect(ProvenanceMarkError.isProvenanceMarkError(e.cause)).toBe(true);
  });

  it("renders references in the reference's short form", () => {
    const service = Service.from("https://s.example", { allow: ["Sign"] } as never);
    service.addAllow("Sign");
    service.addKeyReference(bob.schnorrPublicKeys().reference());
    const e = xidError(() => {
      const d = XIDDocument.from({ inceptionKey: alice.schnorrPublicKeys() });
      d.addService(service);
      d.checkServicesConsistency();
    });
    expect(e.code).toBe("UnknownKeyReference");
    expect(e.is("UnknownKeyReference") && e.details.reference).toMatch(
      /^Reference\([0-9a-f]{8}\)$/,
    );
  });
});

describe("CBOR and UR decoders", () => {
  const empty = XIDDocument.fromXid(XIDDocument.from({ inceptionKey: alice }).xid);
  const full = XIDDocument.from({ inceptionKey: alice.schnorrPublicKeys() });

  it("fromCbor requires the xid tag and fromUntaggedCbor refuses it", () => {
    expect(XIDDocument.fromCbor(empty.toCbor()).equals(empty)).toBe(true);
    expect(XIDDocument.fromCbor(full.toCbor()).equals(full)).toBe(true);
    expect(XIDDocument.codec.decode(full.toCbor()).equals(full)).toBe(true);
    expect(XIDDocument.fromUntaggedCbor(empty.untaggedCbor()).equals(empty)).toBe(true);
    expect(XIDDocument.fromUntaggedCbor(full.untaggedCbor()).equals(full)).toBe(true);
    const untagged = xidError(() => XIDDocument.fromCbor(empty.untaggedCbor()));
    expect(untagged.code).toBe("Cbor");
    expect(CborError.isCborError(untagged.cause) && untagged.cause.code).toBe("WrongType");
    const tagged = xidError(() => XIDDocument.fromUntaggedCbor(full.toCbor()));
    expect(tagged.code).toBe("Cbor");
    expect(tagged.message).toMatch(/^expected CBOR tag envelope, but got /);
    expect(xidError(() => XIDDocument.fromUntaggedCbor(cbor(new Uint8Array(31)))).message).toBe(
      "invalid XID size: expected 32, got 31",
    );
    const elided = xidError(() =>
      XIDDocument.fromUntaggedCbor(taggedValue(Tag.from(200), cbor(new Uint8Array(32)))),
    );
    expect(elided.message).toBe("envelope parsing error");
    expect(xidError(() => XIDDocument.fromCbor(decodeCbor(unhex("f6")))).code).toBe("Cbor");
  });

  it("fromUR reports a UR of another type as Cbor", () => {
    expect(XIDDocument.fromUR(full.toUR()).equals(full)).toBe(true);
    const e = xidError(() => XIDDocument.fromUR(UR.parse(Envelope.from("x").toUR().toString())));
    expect(e.code).toBe("Cbor");
    expect(e.message).toBe("expected UR type xid, but found envelope");
  });
});

describe("JavaScript-domain guards", () => {
  const typeError = (f: () => unknown): string => {
    const e = caught(f);
    if (!(e instanceof TypeError)) throw new Error(`expected a TypeError, got ${String(e)}`);
    return e.message;
  };
  const doc = XIDDocument.from({ inceptionKey: alice, genesis: wolf });

  it("rejects null private keys", () => {
    expect(
      typeError(() => Key.from(alice.schnorrPublicKeys(), { privateKeys: null as never })),
    ).toMatch(/privateKeys/);
  });

  it("validates the genesis", () => {
    expect(typeError(() => XIDDocument.from({ inceptionKey: alice, genesis: {} }))).toMatch(
      /exactly one/,
    );
    expect(
      typeError(() =>
        XIDDocument.from({
          inceptionKey: alice,
          genesis: { passphrase: "a", seed: new Uint8Array(32) },
        }),
      ),
    ).toMatch(/exactly one/);
    for (const length of [16, 40]) {
      const e = xidError(() =>
        XIDDocument.from({ inceptionKey: alice, genesis: { seed: new Uint8Array(length) } }),
      );
      expect(e.code).toBe("ProvenanceMark");
      expect(ProvenanceMarkError.isProvenanceMarkError(e.cause)).toBe(true);
    }
    const invalidDate = xidError(() =>
      XIDDocument.from({ inceptionKey: alice, genesis: { ...wolf, date: new Date(NaN) } }),
    );
    expect(invalidDate.code).toBe("ProvenanceMark");
    expect(
      ProvenanceMarkError.isProvenanceMarkError(invalidDate.cause) &&
        invalidDate.cause.is("InvalidDate"),
    ).toBe(true);
    expect(
      typeError(() =>
        XIDDocument.from({
          inceptionKey: alice,
          genesis: { ...wolf, date: "2025-01-01" as never },
        }),
      ),
    ).toMatch(/genesis.date must be a Date or a CborDate/);
    expect(
      typeError(() =>
        XIDDocument.from({
          inceptionKey: alice,
          genesis: { ...wolf, resolution: "bogus" as never },
        }),
      ),
    ).toMatch(/genesis.resolution/);
    const nextInvalidDate = xidError(() =>
      doc.nextProvenanceMarkWithEmbeddedGenerator({ date: new Date(NaN) }),
    );
    expect(nextInvalidDate.code).toBe("ProvenanceMark");
    expect(
      ProvenanceMarkError.isProvenanceMarkError(nextInvalidDate.cause) &&
        nextInvalidDate.cause.is("InvalidDate"),
    ).toBe(true);
    expect(
      typeError(() => doc.nextProvenanceMarkWithEmbeddedGenerator({ date: 1 as never })),
    ).toMatch(/date must be a Date or a CborDate/);
  });

  it("rejects unknown option strings", () => {
    const env = doc.toEnvelope();
    expect(typeError(() => XIDDocument.fromEnvelope(env, { verify: "bogus" as never }))).toMatch(
      /verify/,
    );
    expect(typeError(() => doc.toEnvelope({ privateKeys: "bogus" as never }))).toMatch(
      /privateKeys/,
    );
    expect(typeError(() => doc.toEnvelope({ generator: "bogus" as never }))).toMatch(/generator/);
    expect(typeError(() => doc.toEnvelope({ sign: "bogus" as never }))).toMatch(/sign/);
    expect(typeError(() => XIDDocument.from({ inceptionKey: undefined as never }))).toMatch(
      /inceptionKey/,
    );
  });

  it("takes a genesis through random", () => {
    const random = XIDDocument.random({ genesis: wolf });
    expect(random.provenance).toBeDefined();
    expect(random.provenanceGenerator).toBeDefined();
  });
});

describe("nicknames", () => {
  it("addNickname sets once; setNickname overwrites", () => {
    const key = Key.from(alice.schnorrPublicKeys());
    key.addNickname("a");
    expect(xidError(() => key.addNickname("b")).details).toEqual({
      code: "Duplicate",
      item: "nickname",
    });
    key.setNickname("");
    expect(xidError(() => key.addNickname("")).details).toEqual({
      code: "EmptyValue",
      field: "nickname",
    });
    key.setNickname("c");
    expect(key.nickname).toBe("c");
  });
});

describe("copy-out and live handles", () => {
  it("copies containers out and hands values out live", () => {
    const doc = XIDDocument.from({ inceptionKey: alice });
    (doc.resolutionMethods as Set<URI>).add(URI.from("https://x.example"));
    expect(doc.resolutionMethods.size).toBe(0);
    (doc.keys as Key[]).push(Key.from(bob.schnorrPublicKeys()));
    expect(doc.keys).toHaveLength(1);
    doc.keys[0].setNickname("live");
    expect(doc.inceptionKey?.nickname).toBe("live");
    doc.keys[0].permissions.addDeny("Sign");
    expect(doc.inceptionKey?.deny.has("Sign")).toBe(true);
    const permissions = Permissions.from({ allow: ["Sign"] });
    (permissions.allow as Set<string>).add("Burn");
    expect(permissions.allow.size).toBe(1);
    (doc.extraAssertions as Envelope[]).push(Envelope.from("x"));
    expect(doc.extraAssertions).toHaveLength(0);
  });

  it("carriers edit their permissions under the reference's names", () => {
    const key = Key.from(alice.schnorrPublicKeys());
    const service = Service.from("https://s.example");
    const delegate = Delegate.from(XIDDocument.from({ inceptionKey: bob.schnorrPublicKeys() }));
    for (const carrier of [key, service, delegate]) {
      carrier.addAllow("Sign");
      carrier.addDeny("Burn");
      expect([...carrier.allow]).toEqual(["Sign"]);
      expect([...carrier.deny]).toEqual(["Burn"]);
      expect(carrier.permissions.allow.has("Sign")).toBe(true);
      carrier.removeAllow("Sign");
      carrier.removeDeny("Burn");
      expect(carrier.allow.size + carrier.deny.size).toBe(0);
      carrier.addAllow("All");
      carrier.addDeny("All");
      carrier.clearAllPermissions();
      expect(carrier.permissions.equals(Permissions.from())).toBe(true);
      // The getters copy out.
      carrier.addAllow("Sign");
      (carrier.allow as Set<string>).add("Burn");
      expect(carrier.allow.size).toBe(1);
    }
    key.addPermission("Encrypt");
    expect(key.allow.has("Encrypt")).toBe(true);
    const p = Permissions.from({ allow: ["All"], deny: ["Burn"] });
    p.removeDeny("Burn");
    p.removeAllow("All");
    p.addAllow("Sign");
    p.clearAllPermissions();
    expect(p.allow.size + p.deny.size).toBe(0);
  });

  it("delegates parse their controller with XIDDocument.fromEnvelope", () => {
    const controller = XIDDocument.from({ inceptionKey: bob.schnorrPublicKeys() });
    const delegate = Delegate.from(controller, {
      permissions: Permissions.from({ allow: ["Sign"] }),
    });
    const back = Delegate.fromEnvelope(delegate.toEnvelope());
    expect(back.equals(delegate)).toBe(true);
    expect(back.controller.xid.equals(controller.xid)).toBe(true);
  });

  it("takeGenerator hands back the generator as held, with its salt", () => {
    const doc = XIDDocument.from({ inceptionKey: alice, genesis: wolf });
    const mark = doc.provenance;
    const generator = doc.provenanceGenerator;
    if (mark === undefined || generator === undefined) throw new Error("no provenance");
    const provenance = Provenance.from(mark, { generator });
    const salt = provenance.generatorSalt;
    const taken = provenance.takeGenerator();
    expect(taken?.data.type).toBe("decrypted");
    expect(taken?.data.type === "decrypted" && taken.data.generator.equals(generator)).toBe(true);
    expect(salt !== undefined && taken?.salt.equals(salt)).toBe(true);
    expect(provenance.hasGenerator).toBe(false);
    expect(provenance.takeGenerator()).toBeUndefined();

    const locked = Provenance.fromEnvelope(
      Provenance.from(mark, { generator }).toEnvelope({ generator: { encrypt: "pw" } }),
    );
    const lockedTaken = locked.takeGenerator();
    expect(lockedTaken?.data.type).toBe("encrypted");
    expect(locked.hasEncryptedGenerator).toBe(false);
  });

  it("removeResolutionMethod returns the URI it removed", () => {
    const doc = XIDDocument.from({ inceptionKey: alice });
    doc.addResolutionMethod("https://r.example");
    expect(doc.removeResolutionMethod("https://r.example")?.toString()).toBe("https://r.example");
    expect(doc.removeResolutionMethod(URI.from("https://r.example"))).toBeUndefined();
    expect(doc.resolutionMethods.size).toBe(0);
  });
});

describe("every code has a factory", () => {
  it("covers the code list", () => {
    const seen = new Set<XIDErrorCode>([
      XIDError.duplicate("x").code,
      XIDError.notFound("x").code,
      XIDError.stillReferenced("x").code,
      XIDError.emptyValue("x").code,
      XIDError.unknownPrivilege().code,
      XIDError.invalidXid().code,
      XIDError.missingInceptionKey().code,
      XIDError.invalidResolutionMethod().code,
      XIDError.multipleProvenanceMarks().code,
      XIDError.unexpectedPredicate("1").code,
      XIDError.unexpectedNestedAssertions().code,
      XIDError.noPermissions("u").code,
      XIDError.noReferences("u").code,
      XIDError.unknownKeyReference("r", "u").code,
      XIDError.unknownDelegateReference("r", "u").code,
      XIDError.keyNotFoundInDocument("k").code,
      XIDError.delegateNotFoundInDocument("d").code,
      XIDError.invalidPassword().code,
      XIDError.envelopeNotSigned().code,
      XIDError.signatureVerificationFailed().code,
      XIDError.noProvenanceMark().code,
      XIDError.generatorConflict().code,
      XIDError.noGenerator().code,
      XIDError.chainIdMismatch(new Uint8Array(), new Uint8Array()).code,
      XIDError.sequenceMismatch(1, 2).code,
      XIDError.envelopeParsing(new Error("e")).code,
      XIDError.component(new Error("c")).code,
      XIDError.cbor(new Error("c")).code,
      XIDError.provenanceMark(new Error("p")).code,
    ]);
    expect([...seen].sort()).toEqual([...XID_ERROR_CODES].sort());
  });
});
