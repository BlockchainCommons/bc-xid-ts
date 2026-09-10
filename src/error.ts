/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The one error this package throws: a `code` naming what went wrong (the
 * reference's variant names) and `details` typed by that code.
 */

// Ported from bc-xid-rust/src/error.rs

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

export const XID_ERROR_CODES: readonly XIDErrorCode[] = [
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
];

/** A named item (a key, a delegate, a service, a nickname, …). */
export interface ItemDetails {
  code: "Duplicate" | "NotFound" | "StillReferenced" | "EmptyValue";
  item: string;
}

/** A structural rejection with nothing more to say. */
export interface PlainDetails {
  code:
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
    | "NoGenerator";
}

export interface UnexpectedPredicateDetails {
  code: "UnexpectedPredicate";
  predicate: string;
}

/** A service that is incomplete. */
export interface ServiceDetails {
  code: "NoPermissions" | "NoReferences";
  uri: string;
}

/** A service reference that names nothing in the document. */
export interface UnknownReferenceDetails {
  code: "UnknownKeyReference" | "UnknownDelegateReference";
  reference: string;
  uri: string;
}

export interface KeyNotFoundDetails {
  code: "KeyNotFoundInDocument";
  key: string;
}

export interface DelegateNotFoundDetails {
  code: "DelegateNotFoundInDocument";
  delegate: string;
}

export interface ChainIdMismatchDetails {
  code: "ChainIdMismatch";
  expected: Uint8Array;
  actual: Uint8Array;
}

export interface SequenceMismatchDetails {
  code: "SequenceMismatch";
  expected: number;
  actual: number;
}

/** A wrapped failure from envelope, components, dcbor or provenance-mark. */
export interface WrappedDetails {
  code: "EnvelopeParsing" | "Component" | "Cbor" | "ProvenanceMark";
  message: string;
}

export type XIDErrorDetails =
  | ItemDetails
  | PlainDetails
  | UnexpectedPredicateDetails
  | ServiceDetails
  | UnknownReferenceDetails
  | KeyNotFoundDetails
  | DelegateNotFoundDetails
  | ChainIdMismatchDetails
  | SequenceMismatchDetails
  | WrappedDetails;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

export class XIDError extends Error {
  override readonly name = "XIDError";
  readonly code: XIDErrorCode;
  readonly details: XIDErrorDetails;

  private constructor(message: string, details: XIDErrorDetails, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.code = details.code;
    this.details = details;
  }

  static isXIDError(value: unknown): value is XIDError {
    return value instanceof Error && value.name === "XIDError" && "code" in value;
  }

  is(code: XIDErrorCode): boolean {
    return this.code === code;
  }

  private static plain(code: PlainDetails["code"], message: string): XIDError {
    return new XIDError(message, { code });
  }

  // Items ---------------------------------------------------------------------

  static duplicate(item: string): XIDError {
    return new XIDError(`duplicate item: ${item}`, { code: "Duplicate", item });
  }

  static notFound(item: string): XIDError {
    return new XIDError(`item not found: ${item}`, { code: "NotFound", item });
  }

  static stillReferenced(item: string): XIDError {
    return new XIDError(`item is still referenced: ${item}`, { code: "StillReferenced", item });
  }

  static emptyValue(field: string): XIDError {
    return new XIDError(`invalid or empty value: ${field}`, { code: "EmptyValue", item: field });
  }

  // Structure -----------------------------------------------------------------

  static unknownPrivilege(): XIDError {
    return XIDError.plain("UnknownPrivilege", "unknown privilege");
  }

  static invalidXid(): XIDError {
    return XIDError.plain("InvalidXid", "invalid XID");
  }

  static missingInceptionKey(): XIDError {
    return XIDError.plain("MissingInceptionKey", "missing inception key");
  }

  static invalidResolutionMethod(): XIDError {
    return XIDError.plain("InvalidResolutionMethod", "invalid resolution method");
  }

  static multipleProvenanceMarks(): XIDError {
    return XIDError.plain("MultipleProvenanceMarks", "multiple provenance marks");
  }

  static unexpectedPredicate(predicate: string): XIDError {
    return new XIDError(`unexpected predicate: ${predicate}`, {
      code: "UnexpectedPredicate",
      predicate,
    });
  }

  static unexpectedNestedAssertions(): XIDError {
    return XIDError.plain("UnexpectedNestedAssertions", "unexpected nested assertions");
  }

  // Services ------------------------------------------------------------------

  static noPermissions(uri: string): XIDError {
    return new XIDError(`no permissions in service '${uri}'`, { code: "NoPermissions", uri });
  }

  static noReferences(uri: string): XIDError {
    return new XIDError(`no key or delegate references in service '${uri}'`, {
      code: "NoReferences",
      uri,
    });
  }

  static unknownKeyReference(reference: string, uri: string): XIDError {
    return new XIDError(`unknown key reference ${reference} in service '${uri}'`, {
      code: "UnknownKeyReference",
      reference,
      uri,
    });
  }

  static unknownDelegateReference(reference: string, uri: string): XIDError {
    return new XIDError(`unknown delegate reference ${reference} in service '${uri}'`, {
      code: "UnknownDelegateReference",
      reference,
      uri,
    });
  }

  static keyNotFoundInDocument(key: string): XIDError {
    return new XIDError(`key not found in XID document: ${key}`, {
      code: "KeyNotFoundInDocument",
      key,
    });
  }

  static delegateNotFoundInDocument(delegate: string): XIDError {
    return new XIDError(`delegate not found in XID document: ${delegate}`, {
      code: "DelegateNotFoundInDocument",
      delegate,
    });
  }

  // Secrets and signatures ----------------------------------------------------

  static invalidPassword(): XIDError {
    return XIDError.plain("InvalidPassword", "invalid password");
  }

  static envelopeNotSigned(): XIDError {
    return XIDError.plain("EnvelopeNotSigned", "envelope is not signed");
  }

  static signatureVerificationFailed(): XIDError {
    return XIDError.plain("SignatureVerificationFailed", "signature verification failed");
  }

  // Provenance ----------------------------------------------------------------

  static noProvenanceMark(): XIDError {
    return XIDError.plain("NoProvenanceMark", "no provenance mark to advance");
  }

  static generatorConflict(): XIDError {
    return XIDError.plain(
      "GeneratorConflict",
      "document already has generator, cannot provide external generator",
    );
  }

  static noGenerator(): XIDError {
    return XIDError.plain(
      "NoGenerator",
      "document does not have generator, must provide external generator",
    );
  }

  static chainIdMismatch(expected: Uint8Array, actual: Uint8Array): XIDError {
    return new XIDError(
      `generator chain ID mismatch: expected ${hex(expected)}, got ${hex(actual)}`,
      { code: "ChainIdMismatch", expected, actual },
    );
  }

  static sequenceMismatch(expected: number, actual: number): XIDError {
    return new XIDError(`generator sequence mismatch: expected ${expected}, got ${actual}`, {
      code: "SequenceMismatch",
      expected,
      actual,
    });
  }

  // Wrapped dependencies ------------------------------------------------------

  private static wrapped(code: WrappedDetails["code"], message: string, cause: unknown): XIDError {
    const detail =
      cause instanceof Error ? cause.message : cause === undefined ? "" : String(cause);
    return new XIDError(
      detail === "" ? message : `${message}: ${detail}`,
      { code, message: detail === "" ? message : detail },
      cause,
    );
  }

  static envelopeParsing(cause?: unknown): XIDError {
    return XIDError.wrapped("EnvelopeParsing", "envelope parsing error", cause);
  }

  static component(cause?: unknown): XIDError {
    return XIDError.wrapped("Component", "component error", cause);
  }

  static cbor(cause?: unknown): XIDError {
    return XIDError.wrapped("Cbor", "CBOR error", cause);
  }

  static provenanceMark(cause?: unknown): XIDError {
    return XIDError.wrapped("ProvenanceMark", "provenance mark error", cause);
  }
}
