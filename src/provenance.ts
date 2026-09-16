/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A document's provenance: its current mark and, when the document can
 * advance the chain, the generator (in the clear or password-locked).
 */

import { Envelope, type EnvelopeInput } from "@blockchaincommons/envelope";
import {
  lockSubject,
  unlockSubject,
  isLockedWithPassword,
} from "@blockchaincommons/envelope/secret";
import { PROVENANCE_GENERATOR, SALT } from "@blockchaincommons/known-values";
import { Salt } from "@blockchaincommons/components";
import { ProvenanceMark, ProvenanceMarkGenerator } from "@blockchaincommons/provenance-mark";

import { XIDError } from "./error";
import {
  type EncryptOptions,
  type PasswordOptions,
  envelopeBytesEqual,
  expectPrivateKeyOptions,
  kdfOf,
  passwordBytes,
} from "./key";
import { extractObjectForPredicate, guarded, leafAs } from "./domain";

/** How the generator goes into an envelope; the same four forms as private keys. */
export type XIDGeneratorOptions = "omit" | "include" | "elide" | EncryptOptions;

/** The generator as held: in the clear, or the locked envelope as parsed. */
type GeneratorData =
  | { type: "decrypted"; generator: ProvenanceMarkGenerator }
  | { type: "encrypted"; envelope: Envelope };

/** What `Provenance.from` takes besides the mark. */
export interface ProvenanceInput {
  /** The generator that produced the mark, when the document should keep it. */
  generator?: ProvenanceMarkGenerator | undefined;
}

/** What `Provenance.toEnvelope` takes. */
export interface ProvenanceEnvelopeOptions {
  /** How the generator goes into the envelope; `"omit"` unless given. */
  generator?: XIDGeneratorOptions | undefined;
}

/** A provenance mark and, optionally, the generator that continues its chain. */
export class Provenance {
  private _mark: ProvenanceMark;
  private _generator: { data: GeneratorData; salt: Salt } | undefined;

  private constructor(mark: ProvenanceMark, generator?: { data: GeneratorData; salt: Salt }) {
    this._mark = mark;
    this._generator = generator;
  }

  /** A mark, with the generator that produced it when the document should keep it. */
  static from(mark: ProvenanceMark, { generator }: ProvenanceInput = {}): Provenance {
    return new Provenance(
      mark,
      generator === undefined
        ? undefined
        : { data: { type: "decrypted", generator }, salt: Salt.random({ length: 32 }) },
    );
  }

  /** The current mark. */
  get mark(): ProvenanceMark {
    return this._mark;
  }

  /** The generator when held in the clear. */
  get generator(): ProvenanceMarkGenerator | undefined {
    return this._generator?.data.type === "decrypted" ? this._generator.data.generator : undefined;
  }

  /** Whether the generator is held in the clear. */
  get hasGenerator(): boolean {
    return this._generator?.data.type === "decrypted";
  }

  /** Whether the generator is held locked (parsed without the password). */
  get hasEncryptedGenerator(): boolean {
    return this._generator?.data.type === "encrypted";
  }

  /** The salt the `'provenanceGenerator'` assertion carries. */
  get generatorSalt(): Salt | undefined {
    return this._generator?.salt;
  }

  /** Replaces the mark (no chain check, as the reference's `set_mark`). */
  setMark(mark: ProvenanceMark): void {
    this._mark = mark;
  }

  /** Sets or replaces the generator, with a fresh salt. */
  setGenerator(generator: ProvenanceMarkGenerator): void {
    this._generator = { data: { type: "decrypted", generator }, salt: Salt.random({ length: 32 }) };
  }

  /** Removes the generator, returning whether one was held. */
  takeGenerator(): boolean {
    const had = this._generator !== undefined;
    this._generator = undefined;
    return had;
  }

  /**
   * The generator, unlocking a locked one with the password (it stays
   * unlocked); `InvalidPassword` when it is locked and the password is
   * missing or wrong; `undefined` when there is no generator.
   */
  unlockGenerator({ password }: PasswordOptions = {}): ProvenanceMarkGenerator | undefined {
    if (this._generator === undefined) return undefined;
    if (this._generator.data.type === "decrypted") return this._generator.data.generator;
    if (password === undefined) throw XIDError.invalidPassword();
    let decrypted: Envelope;
    try {
      decrypted = unlockSubject(this._generator.data.envelope, passwordBytes(password));
    } catch {
      throw XIDError.invalidPassword();
    }
    const generator = Provenance.generatorOf(guarded(() => decrypted.unwrap()));
    this._generator = { data: { type: "decrypted", generator }, salt: this._generator.salt };
    return generator;
  }

  /** A generator from its envelope; a provenance-mark failure is `ProvenanceMark`. */
  private static generatorOf(envelope: Envelope): ProvenanceMarkGenerator {
    return guarded(() => ProvenanceMarkGenerator.fromEnvelope(envelope));
  }

  private generatorAssertionEnvelope(): Envelope {
    if (this._generator === undefined) {
      throw new Error("generatorAssertionEnvelope called with no generator");
    }
    const { data, salt } = this._generator;
    const object: EnvelopeInput = data.type === "decrypted" ? data.generator : data.envelope;
    return Envelope.assertion(PROVENANCE_GENERATOR, object).addSalt({ salt });
  }

  /**
   * The generator as an envelope: in the clear when held so, unlocked
   * with the password when locked (`InvalidPassword` when it does not
   * fit), or the locked envelope itself without a password.
   */
  generatorEnvelope({ password }: PasswordOptions = {}): Envelope | undefined {
    if (this._generator === undefined) return undefined;
    const { data } = this._generator;
    if (data.type === "decrypted") return data.generator.toEnvelope();
    if (password === undefined) return data.envelope;
    try {
      return unlockSubject(data.envelope, passwordBytes(password)).unwrap();
    } catch {
      throw XIDError.invalidPassword();
    }
  }

  /**
   * The mark as the subject; the generator per `generator` (a locked one
   * stays locked). An unknown option is a `TypeError`.
   */
  toEnvelope({ generator = "omit" }: ProvenanceEnvelopeOptions = {}): Envelope {
    const option = expectPrivateKeyOptions(generator, "generator");
    let envelope = Envelope.from(this._mark);
    if (this._generator !== undefined) {
      const { data, salt } = this._generator;
      if (data.type === "encrypted") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope());
      } else if (option === "include") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope());
      } else if (option === "elide") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope().elide());
      } else if (typeof option === "object") {
        const locked = lockSubject(
          data.generator.toEnvelope().wrap(),
          kdfOf(option),
          passwordBytes(option.encrypt),
        );
        envelope = envelope.addAssertionEnvelope(
          Envelope.assertion(PROVENANCE_GENERATOR, locked).addSalt({ salt }),
        );
      }
    }
    return envelope;
  }

  /**
   * A provenance from its envelope. A locked generator is unlocked with
   * the password when one is given and it fits; otherwise it is kept
   * locked. A subject that is not a mark is `Cbor`; a missing or repeated
   * `'salt'` is `EnvelopeParsing`; a generator envelope that is not a
   * generator's is `ProvenanceMark`.
   */
  static fromEnvelope(envelope: Envelope, { password }: PasswordOptions = {}): Provenance {
    const mark = leafAs(envelope.subject(), (c) => ProvenanceMark.fromCbor(c));
    return new Provenance(mark, Provenance.generatorDataOf(envelope, password));
  }

  private static generatorDataOf(
    envelope: Envelope,
    password: Uint8Array | string | undefined,
  ): { data: GeneratorData; salt: Salt } | undefined {
    const generatorAssertion = guarded(() =>
      envelope.optionalAssertionWithPredicate(PROVENANCE_GENERATOR),
    );
    if (generatorAssertion === undefined) return undefined;
    const generatorObject = guarded(() => generatorAssertion.subject().expectObject());
    const salt = extractObjectForPredicate(generatorAssertion, SALT, (c) => Salt.fromCbor(c));
    if (isLockedWithPassword(generatorObject)) {
      if (password === undefined) {
        return { data: { type: "encrypted", envelope: generatorObject }, salt };
      }
      let decrypted: Envelope;
      try {
        decrypted = unlockSubject(generatorObject, passwordBytes(password));
      } catch {
        // A wrong password leaves the generator locked.
        return { data: { type: "encrypted", envelope: generatorObject }, salt };
      }
      const generator = Provenance.generatorOf(guarded(() => decrypted.unwrap()));
      return { data: { type: "decrypted", generator }, salt };
    }
    return {
      data: { type: "decrypted", generator: Provenance.generatorOf(generatorObject) },
      salt,
    };
  }

  /** Same mark and generator (in the clear or locked, with its salt) — as the reference's equality. */
  equals(other: Provenance): boolean {
    if (!this._mark.equals(other._mark)) return false;
    const a = this._generator;
    const b = other._generator;
    if (a === undefined || b === undefined) return a === b;
    if (!a.salt.equals(b.salt)) return false;
    if (a.data.type === "decrypted" && b.data.type === "decrypted") {
      return (
        JSON.stringify(a.data.generator.toJSON()) === JSON.stringify(b.data.generator.toJSON())
      );
    }
    if (a.data.type === "encrypted" && b.data.type === "encrypted") {
      return envelopeBytesEqual(a.data.envelope, b.data.envelope);
    }
    return false;
  }

  /** A copy: the generator material shared. */
  clone(): Provenance {
    return new Provenance(
      this._mark,
      this._generator === undefined
        ? undefined
        : { data: this._generator.data, salt: this._generator.salt },
    );
  }
}
