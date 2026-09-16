/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The one error this package throws: a `code` naming what went wrong (the
 * reference's variant names) and `details` typed by that code.
 */

/** Every code an `XIDError` can carry: the reference's `Error` variant names. */
export type XIDErrorCode =
  | "Duplicate"
  | "NotFound"
  | "StillReferenced"
  | "EmptyValue"
  | "UnknownPrivilege"
  | "InvalidXid"
  | "MissingInceptionKey"
  | "InvalidResolutionMethod"
  | "MultipleProvenanceMarks"
  | "UnexpectedPredicate"
  | "UnexpectedNestedAssertions"
  | "NoPermissions"
  | "NoReferences"
  | "UnknownKeyReference"
  | "UnknownDelegateReference"
  | "KeyNotFoundInDocument"
  | "DelegateNotFoundInDocument"
  | "InvalidPassword"
  | "EnvelopeNotSigned"
  | "SignatureVerificationFailed"
  | "NoProvenanceMark"
  | "GeneratorConflict"
  | "NoGenerator"
  | "ChainIdMismatch"
  | "SequenceMismatch"
  | "EnvelopeParsing"
  | "Component"
  | "Cbor"
  | "ProvenanceMark";

/** Every code, for exhaustive tables and tests. */
export const XID_ERROR_CODES: readonly XIDErrorCode[] = Object.freeze([
  "Duplicate",
  "NotFound",
  "StillReferenced",
  "EmptyValue",
  "UnknownPrivilege",
  "InvalidXid",
  "MissingInceptionKey",
  "InvalidResolutionMethod",
  "MultipleProvenanceMarks",
  "UnexpectedPredicate",
  "UnexpectedNestedAssertions",
  "NoPermissions",
  "NoReferences",
  "UnknownKeyReference",
  "UnknownDelegateReference",
  "KeyNotFoundInDocument",
  "DelegateNotFoundInDocument",
  "InvalidPassword",
  "EnvelopeNotSigned",
  "SignatureVerificationFailed",
  "NoProvenanceMark",
  "GeneratorConflict",
  "NoGenerator",
  "ChainIdMismatch",
  "SequenceMismatch",
  "EnvelopeParsing",
  "Component",
  "Cbor",
  "ProvenanceMark",
]);

/** The fields each code carries besides `code`. */
export interface XIDErrorDetailsByCode {
  /** An item of this kind is already there. */
  Duplicate: {
    /** The item's kind: `"key"`, `"delegate"`, `"service"`, `"nickname"`, … */
    readonly item: string;
  };
  /** No item of this kind is there. */
  NotFound: {
    /** The item's kind. */
    readonly item: string;
  };
  /** A service still names the item. */
  StillReferenced: {
    /** The item's kind. */
    readonly item: string;
  };
  /** The field must not be empty. */
  EmptyValue: {
    /** The field's name. */
    readonly item: string;
  };
  /** A known value that names no privilege. */
  UnknownPrivilege: unknown;
  /** The inception key does not produce the document's XID. */
  InvalidXid: unknown;
  /** The document has no inception key, or it has no private keys. */
  MissingInceptionKey: unknown;
  /** A `'dereferenceVia'` object that is not a URI. */
  InvalidResolutionMethod: unknown;
  /** More than one `'provenance'` assertion. */
  MultipleProvenanceMarks: unknown;
  /** A service assertion with a predicate the parser does not take. */
  UnexpectedPredicate: {
    /** The predicate's known value, as decimal text. */
    readonly predicate: string;
  };
  /** A service assertion whose object has assertions. */
  UnexpectedNestedAssertions: unknown;
  /** The service allows nothing. */
  NoPermissions: {
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names no key and no delegate. */
  NoReferences: {
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names a key the document lacks. */
  UnknownKeyReference: {
    /** The reference, rendered `Reference(<short hex>)`. */
    readonly reference: string;
    /** The service's URI. */
    readonly uri: string;
  };
  /** The service names a delegate the document lacks. */
  UnknownDelegateReference: {
    /** The reference, rendered `Reference(<short hex>)`. */
    readonly reference: string;
    /** The service's URI. */
    readonly uri: string;
  };
  /** `expectKey` found no such key. */
  KeyNotFoundInDocument: {
    /** The key's public keys, rendered. */
    readonly key: string;
  };
  /** `expectDelegate` found no such delegate. */
  DelegateNotFoundInDocument: {
    /** The delegate's XID, rendered. */
    readonly delegate: string;
  };
  /** A locked key or generator did not open. */
  InvalidPassword: unknown;
  /** Verification was asked of an unsigned envelope. */
  EnvelopeNotSigned: unknown;
  /** The inception key did not sign the envelope. */
  SignatureVerificationFailed: unknown;
  /** The document has no mark to advance. */
  NoProvenanceMark: unknown;
  /** A generator was given to a document that holds one. */
  GeneratorConflict: unknown;
  /** The document holds no generator and none was given. */
  NoGenerator: unknown;
  /** The generator continues another chain. */
  ChainIdMismatch: {
    /** The mark's chain id. */
    readonly expected: Uint8Array;
    /** The generator's chain id. */
    readonly actual: Uint8Array;
  };
  /** The generator's next sequence number is not the mark's plus one. */
  SequenceMismatch: {
    /** The sequence number the mark demands. */
    readonly expected: number;
    /** The generator's next sequence number. */
    readonly actual: number;
  };
  /** An envelope error inside a decoder; the error itself is `cause`. */
  EnvelopeParsing: {
    /** The envelope error's message. */
    readonly message: string;
  };
  /** A components error; the error itself is `cause`. */
  Component: {
    /** The components error's message. */
    readonly message: string;
  };
  /** A dcbor error inside a decoder; the error itself is `cause`. */
  Cbor: {
    /** The dcbor error's message. */
    readonly message: string;
  };
  /** A provenance-mark error; the error itself is `cause`. */
  ProvenanceMark: {
    /** The provenance-mark error's message. */
    readonly message: string;
  };
}

/** `details` of one code: `code` and that code's fields. */
export type XIDErrorDetailsFor<C extends XIDErrorCode> = C extends XIDErrorCode
  ? {
      /** The discriminant. */
      readonly code: C;
    } & XIDErrorDetailsByCode[C]
  : never;

/** `details` is discriminated by `code`. */
export type XIDErrorDetails = XIDErrorDetailsFor<XIDErrorCode>;

/**
 * An `XIDError` whose `code` and `details` are narrowed to one code (or,
 * with the default argument, the union over every code), so `error.code
 * === "Duplicate"` narrows `error.details.item` to a string.
 */
export type XIDErrorTyped<C extends XIDErrorCode = XIDErrorCode> = C extends XIDErrorCode
  ? XIDError & {
      /** The condition. */
      readonly code: C;
      /** The condition's fields. */
      readonly details: XIDErrorDetailsFor<C>;
    }
  : never;

/** `details` of the four item codes. */
export type ItemDetails = XIDErrorDetailsFor<
  "Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue"
>;
/** `details` of the codes with nothing more to say. */
export type PlainDetails = XIDErrorDetailsFor<
  | "UnknownPrivilege"
  | "InvalidXid"
  | "MissingInceptionKey"
  | "InvalidResolutionMethod"
  | "MultipleProvenanceMarks"
  | "UnexpectedNestedAssertions"
  | "InvalidPassword"
  | "EnvelopeNotSigned"
  | "SignatureVerificationFailed"
  | "NoProvenanceMark"
  | "GeneratorConflict"
  | "NoGenerator"
>;
/** `details` of `UnexpectedPredicate`. */
export type UnexpectedPredicateDetails = XIDErrorDetailsFor<"UnexpectedPredicate">;
/** `details` of a service that is incomplete. */
export type ServiceDetails = XIDErrorDetailsFor<"NoPermissions" | "NoReferences">;
/** `details` of a service reference that names nothing in the document. */
export type UnknownReferenceDetails = XIDErrorDetailsFor<
  "UnknownKeyReference" | "UnknownDelegateReference"
>;
/** `details` of `KeyNotFoundInDocument`. */
export type KeyNotFoundDetails = XIDErrorDetailsFor<"KeyNotFoundInDocument">;
/** `details` of `DelegateNotFoundInDocument`. */
export type DelegateNotFoundDetails = XIDErrorDetailsFor<"DelegateNotFoundInDocument">;
/** `details` of `ChainIdMismatch`. */
export type ChainIdMismatchDetails = XIDErrorDetailsFor<"ChainIdMismatch">;
/** `details` of `SequenceMismatch`. */
export type SequenceMismatchDetails = XIDErrorDetailsFor<"SequenceMismatch">;
/** `details` of a wrapped failure from envelope, components, dcbor or provenance-mark. */
export type WrappedDetails = XIDErrorDetailsFor<
  "EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark"
>;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const messageOf = (cause: unknown): string =>
  cause instanceof Error ? cause.message : typeof cause === "string" ? cause : "";

/**
 * The error every operation of this package throws. `code` names the
 * condition (one of `XIDErrorCode`, the reference's variant names),
 * `details` is discriminated by it, and `cause` carries the sibling
 * error when a decoder wrapped one.
 *
 * ```ts
 * try {
 *   doc.addKey(key);
 * } catch (e) {
 *   if (XIDError.isXIDError(e) && e.is("Duplicate")) console.log(e.details.item);
 * }
 * ```
 */
export class XIDError extends Error {
  /** Always `"XIDError"`. */
  override readonly name = "XIDError";
  /** The condition, one of `XIDErrorCode`. */
  readonly code: XIDErrorCode;
  /** The fields of the condition, discriminated by `code`. */
  readonly details: XIDErrorDetails;

  private constructor(message: string, details: XIDErrorDetails, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.code = details.code;
    this.details = details;
  }

  private static make<C extends XIDErrorCode>(
    message: string,
    details: XIDErrorDetailsFor<C>,
    cause?: unknown,
  ): XIDErrorTyped<C> {
    return new XIDError(message, details, cause) as XIDErrorTyped<C>;
  }

  /** Whether `value` is an `XIDError`: an instance of this class. */
  static isXIDError(value: unknown): value is XIDError {
    return value instanceof XIDError;
  }

  /** Whether this error's code is `code`, narrowing `details`. */
  is<C extends XIDErrorCode>(code: C): this is XIDErrorTyped<C> {
    return this.code === code;
  }

  private static plain<C extends PlainDetails["code"]>(code: C, message: string): XIDErrorTyped<C> {
    return XIDError.make<C>(message, { code } as XIDErrorDetailsFor<C>);
  }

  // Items ---------------------------------------------------------------------

  /** `Duplicate`: an item of this kind is already there. */
  static duplicate(item: string): XIDErrorTyped<"Duplicate"> {
    return XIDError.make(`duplicate item: ${item}`, { code: "Duplicate", item });
  }

  /** `NotFound`: no item of this kind is there. */
  static notFound(item: string): XIDErrorTyped<"NotFound"> {
    return XIDError.make(`item not found: ${item}`, { code: "NotFound", item });
  }

  /** `StillReferenced`: a service still names the item. */
  static stillReferenced(item: string): XIDErrorTyped<"StillReferenced"> {
    return XIDError.make(`item is still referenced: ${item}`, { code: "StillReferenced", item });
  }

  /** `EmptyValue`: the field must not be empty. */
  static emptyValue(field: string): XIDErrorTyped<"EmptyValue"> {
    return XIDError.make(`invalid or empty value: ${field}`, { code: "EmptyValue", item: field });
  }

  // Structure -----------------------------------------------------------------

  /** `UnknownPrivilege`: a known value that names no privilege. */
  static unknownPrivilege(): XIDErrorTyped<"UnknownPrivilege"> {
    return XIDError.plain("UnknownPrivilege", "unknown privilege");
  }

  /** `InvalidXid`: the inception key does not produce the document's XID. */
  static invalidXid(): XIDErrorTyped<"InvalidXid"> {
    return XIDError.plain("InvalidXid", "invalid XID");
  }

  /** `MissingInceptionKey`: the document has no inception key, or it has no private keys. */
  static missingInceptionKey(): XIDErrorTyped<"MissingInceptionKey"> {
    return XIDError.plain("MissingInceptionKey", "missing inception key");
  }

  /** `InvalidResolutionMethod`: a `'dereferenceVia'` object that is not a URI. */
  static invalidResolutionMethod(): XIDErrorTyped<"InvalidResolutionMethod"> {
    return XIDError.plain("InvalidResolutionMethod", "invalid resolution method");
  }

  /** `MultipleProvenanceMarks`: more than one `'provenance'` assertion. */
  static multipleProvenanceMarks(): XIDErrorTyped<"MultipleProvenanceMarks"> {
    return XIDError.plain("MultipleProvenanceMarks", "multiple provenance marks");
  }

  /** `UnexpectedPredicate`: a service assertion with a predicate the parser does not take. */
  static unexpectedPredicate(predicate: string): XIDErrorTyped<"UnexpectedPredicate"> {
    return XIDError.make(`unexpected predicate: ${predicate}`, {
      code: "UnexpectedPredicate",
      predicate,
    });
  }

  /** `UnexpectedNestedAssertions`: a service assertion whose object has assertions. */
  static unexpectedNestedAssertions(): XIDErrorTyped<"UnexpectedNestedAssertions"> {
    return XIDError.plain("UnexpectedNestedAssertions", "unexpected nested assertions");
  }

  // Services ------------------------------------------------------------------

  /** `NoPermissions`: the service allows nothing. */
  static noPermissions(uri: string): XIDErrorTyped<"NoPermissions"> {
    return XIDError.make(`no permissions in service '${uri}'`, { code: "NoPermissions", uri });
  }

  /** `NoReferences`: the service names no key and no delegate. */
  static noReferences(uri: string): XIDErrorTyped<"NoReferences"> {
    return XIDError.make(`no key or delegate references in service '${uri}'`, {
      code: "NoReferences",
      uri,
    });
  }

  /** `UnknownKeyReference`: the service names a key the document lacks. */
  static unknownKeyReference(reference: string, uri: string): XIDErrorTyped<"UnknownKeyReference"> {
    return XIDError.make(`unknown key reference ${reference} in service '${uri}'`, {
      code: "UnknownKeyReference",
      reference,
      uri,
    });
  }

  /** `UnknownDelegateReference`: the service names a delegate the document lacks. */
  static unknownDelegateReference(
    reference: string,
    uri: string,
  ): XIDErrorTyped<"UnknownDelegateReference"> {
    return XIDError.make(`unknown delegate reference ${reference} in service '${uri}'`, {
      code: "UnknownDelegateReference",
      reference,
      uri,
    });
  }

  /** `KeyNotFoundInDocument`: `expectKey` found no such key. */
  static keyNotFoundInDocument(key: string): XIDErrorTyped<"KeyNotFoundInDocument"> {
    return XIDError.make(`key not found in XID document: ${key}`, {
      code: "KeyNotFoundInDocument",
      key,
    });
  }

  /** `DelegateNotFoundInDocument`: `expectDelegate` found no such delegate. */
  static delegateNotFoundInDocument(delegate: string): XIDErrorTyped<"DelegateNotFoundInDocument"> {
    return XIDError.make(`delegate not found in XID document: ${delegate}`, {
      code: "DelegateNotFoundInDocument",
      delegate,
    });
  }

  // Secrets and signatures ----------------------------------------------------

  /** `InvalidPassword`: a locked key or generator did not open. */
  static invalidPassword(): XIDErrorTyped<"InvalidPassword"> {
    return XIDError.plain("InvalidPassword", "invalid password");
  }

  /** `EnvelopeNotSigned`: verification was asked of an unsigned envelope. */
  static envelopeNotSigned(): XIDErrorTyped<"EnvelopeNotSigned"> {
    return XIDError.plain("EnvelopeNotSigned", "envelope is not signed");
  }

  /** `SignatureVerificationFailed`: the inception key did not sign the envelope. */
  static signatureVerificationFailed(): XIDErrorTyped<"SignatureVerificationFailed"> {
    return XIDError.plain("SignatureVerificationFailed", "signature verification failed");
  }

  // Provenance ----------------------------------------------------------------

  /** `NoProvenanceMark`: the document has no mark to advance. */
  static noProvenanceMark(): XIDErrorTyped<"NoProvenanceMark"> {
    return XIDError.plain("NoProvenanceMark", "no provenance mark to advance");
  }

  /** `GeneratorConflict`: a generator was given to a document that holds one. */
  static generatorConflict(): XIDErrorTyped<"GeneratorConflict"> {
    return XIDError.plain(
      "GeneratorConflict",
      "document already has generator, cannot provide external generator",
    );
  }

  /** `NoGenerator`: the document holds no generator and none was given. */
  static noGenerator(): XIDErrorTyped<"NoGenerator"> {
    return XIDError.plain(
      "NoGenerator",
      "document does not have generator, must provide external generator",
    );
  }

  /** `ChainIdMismatch`: the generator continues another chain. */
  static chainIdMismatch(
    expected: Uint8Array,
    actual: Uint8Array,
  ): XIDErrorTyped<"ChainIdMismatch"> {
    return XIDError.make(
      `generator chain ID mismatch: expected ${hex(expected)}, got ${hex(actual)}`,
      { code: "ChainIdMismatch", expected, actual },
    );
  }

  /** `SequenceMismatch`: the generator's next sequence number is not the mark's plus one. */
  static sequenceMismatch(expected: number, actual: number): XIDErrorTyped<"SequenceMismatch"> {
    return XIDError.make(`generator sequence mismatch: expected ${expected}, got ${actual}`, {
      code: "SequenceMismatch",
      expected,
      actual,
    });
  }

  // Wrapped dependencies ------------------------------------------------------

  /**
   * `EnvelopeParsing`: an envelope error inside a decoder. The message is
   * the reference's `envelope parsing error`; the envelope error is
   * `cause` and its message is `details.message`.
   */
  static envelopeParsing(cause: unknown): XIDErrorTyped<"EnvelopeParsing"> {
    return XIDError.make(
      "envelope parsing error",
      { code: "EnvelopeParsing", message: messageOf(cause) },
      cause,
    );
  }

  /** `Component`: a components error; the message is the reference's `component error`. */
  static component(cause: unknown): XIDErrorTyped<"Component"> {
    return XIDError.make(
      "component error",
      { code: "Component", message: messageOf(cause) },
      cause,
    );
  }

  /** `Cbor`: a dcbor error inside a decoder; the message is the reference's `CBOR error`. */
  static cbor(cause: unknown): XIDErrorTyped<"Cbor"> {
    return XIDError.make("CBOR error", { code: "Cbor", message: messageOf(cause) }, cause);
  }

  /**
   * `Cbor` from a CBOR or UR decoder entry point (`fromCbor`,
   * `fromUntaggedCbor`, `fromUR`), where the reference returns the dcbor
   * error itself: the message is the dcbor error's.
   */
  static cborDecode(cause: Error): XIDErrorTyped<"Cbor"> {
    return XIDError.make(cause.message, { code: "Cbor", message: cause.message }, cause);
  }

  /** `ProvenanceMark`: a provenance-mark error; the message is the reference's `provenance mark error`. */
  static provenanceMark(cause: unknown): XIDErrorTyped<"ProvenanceMark"> {
    return XIDError.make(
      "provenance mark error",
      { code: "ProvenanceMark", message: messageOf(cause) },
      cause,
    );
  }
}
