/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The boundary between this package and the layers below it, and the
 * guards on the JavaScript input domain. Internal: nothing here is
 * exported from the package.
 *
 * Inside a decoder, a failure raised by a sibling package becomes an
 * `XIDError` with the code the reference's `From` conversions give it:
 * an `EnvelopeError` is `EnvelopeParsing`, a `CborError` is `Cbor`, a
 * `ProvenanceMarkError` is `ProvenanceMark`; a `ComponentsError` is
 * `Cbor` too, because the reference's `TryFrom<CBOR>` decoders return
 * the dcbor error itself (its `Cbor` code contributes its cause, any
 * other code a `Custom` error of its message). A leaf decoder's
 * `ProvenanceMarkError` with code `Cbor` contributes its cause the same
 * way (`ProvenanceMark::try_from(CBOR)` returns the dcbor error).
 */
import { CborDate, CborError, type Cbor } from "@blockchaincommons/dcbor";
import { ComponentsError } from "@blockchaincommons/components";
import { type Envelope, EnvelopeError, type EnvelopeInput } from "@blockchaincommons/envelope";
import { type DateInput, ProvenanceMarkError } from "@blockchaincommons/provenance-mark";
import { XIDError } from "./error";

/**
 * The `CborError` a thrown value stands for: a `CborError` is itself; a
 * `ComponentsError` with code `Cbor` is its `CborError` cause when it has
 * one, else `Custom` of its bare message; an `EnvelopeError` with code
 * `Cbor` is its `CborError` cause likewise; anything else is `Custom` of
 * its message.
 */
export function cborErrorOf(error: unknown): CborError {
  if (CborError.isCborError(error)) return error;
  if (ComponentsError.isComponentsError(error) && error.code === "Cbor") {
    if (CborError.isCborError(error.cause)) return error.cause;
    const message = "message" in error.details ? error.details.message : error.message;
    return CborError.custom(message);
  }
  if (EnvelopeError.isEnvelopeError(error) && error.code === "Cbor") {
    if (CborError.isCborError(error.cause)) return error.cause;
    return CborError.custom("message" in error.details ? error.details.message : error.message);
  }
  if (ProvenanceMarkError.isProvenanceMarkError(error) && error.is("Cbor")) {
    if (CborError.isCborError(error.cause)) return error.cause;
    return CborError.custom(error.details.message);
  }
  return CborError.custom(error instanceof Error ? error.message : String(error));
}

/**
 * The `XIDError` a sibling error becomes inside a decoder; an `XIDError`
 * and any other value are returned as they are.
 */
export function wrapForeign(error: unknown): unknown {
  if (XIDError.isXIDError(error)) return error;
  if (EnvelopeError.isEnvelopeError(error)) return XIDError.envelopeParsing(error);
  if (ProvenanceMarkError.isProvenanceMarkError(error)) return XIDError.provenanceMark(error);
  if (CborError.isCborError(error) || ComponentsError.isComponentsError(error)) {
    return XIDError.cbor(cborErrorOf(error));
  }
  return error;
}

/** Runs a decoder; every sibling failure inside it surfaces as an `XIDError`. */
export function guarded<T>(decode: () => T): T {
  try {
    return decode();
  } catch (error) {
    throw wrapForeign(error);
  }
}

/** A decoder of a leaf's CBOR (`XID.fromCbor`, `expectText`, …). */
export type LeafDecoder<T> = (cbor: Cbor) => T;

/**
 * The reference's `envelope.try_leaf()?.try_into()?`: the leaf, decoded.
 * A subject that is not a leaf is `EnvelopeParsing`; a leaf the decoder
 * rejects is `Cbor`.
 */
export function leafAs<T>(envelope: Envelope, decode: LeafDecoder<T>): T {
  let cbor: Cbor;
  try {
    cbor = envelope.expectLeaf();
  } catch (error) {
    throw wrapForeign(error);
  }
  try {
    return decode(cbor);
  } catch (error) {
    throw XIDError.cbor(cborErrorOf(error));
  }
}

/**
 * The reference's `extract_object_for_predicate::<T>(predicate)`: the one
 * assertion's object, decoded, where every failure (no assertion, more
 * than one, not a leaf, the wrong type) is an envelope error and so
 * `EnvelopeParsing`.
 */
export function extractObjectForPredicate<T>(
  envelope: Envelope,
  predicate: EnvelopeInput,
  decode: LeafDecoder<T>,
): T {
  return guarded(() => decodeObject(envelope.objectForPredicate(predicate), decode));
}

/** `extract_object_for_predicate_with_default`: `fallback` when there is no such assertion. */
export function extractObjectForPredicateOr<T>(
  envelope: Envelope,
  predicate: EnvelopeInput,
  decode: LeafDecoder<T>,
  fallback: T,
): T {
  return guarded(() => {
    const object = envelope.optionalObjectForPredicate(predicate);
    return object === undefined ? fallback : decodeObject(object, decode);
  });
}

/** A leaf decoded under the envelope's own `Cbor` code (the reference's `extract_subject`). */
function decodeObject<T>(object: Envelope, decode: LeafDecoder<T>): T {
  const cbor = object.expectLeaf();
  try {
    return decode(cbor);
  } catch (error) {
    const cause = cborErrorOf(error);
    throw EnvelopeError.cbor(cause.message, cause);
  }
}

// The JavaScript input domain ------------------------------------------------

/** `value` is one of `allowed`, else a `TypeError` naming the option. */
export function expectOneOf<T extends string>(
  value: unknown,
  allowed: readonly T[],
  name: string,
): T {
  if (typeof value === "string" && (allowed as readonly string[]).includes(value))
    return value as T;
  throw new TypeError(`${name} must be one of ${allowed.map((a) => `"${a}"`).join(", ")}`);
}

/** A class whose instances a guard checks for (its constructor may be private). */
export interface InstanceClass<T> {
  readonly prototype: T;
  readonly name: string;
}

/** `value` is an instance of `cls`, else a `TypeError` naming the argument. */
export function expectInstance<T>(
  value: unknown,
  cls: InstanceClass<T>,
  name: string,
  what = `a ${cls.name}`,
): T {
  if (value instanceof (cls as unknown as abstract new () => T)) return value;
  throw new TypeError(`${name} must be ${what}`);
}

/**
 * A `Date` or `CborDate`, else a `TypeError`. Whether the date holds a
 * time is the mark generator's check (`ProvenanceMark[InvalidDate]`).
 */
export function expectDateInput(value: unknown, name: string): DateInput {
  if (value instanceof Date || value instanceof CborDate) return value;
  throw new TypeError(`${name} must be a Date or a CborDate`);
}

/** `value` is not `null` (an absent option is `undefined`), else a `TypeError`. */
export function rejectNull(value: unknown, name: string): void {
  if (value === null) throw new TypeError(`${name} must be omitted or undefined, not null`);
}
