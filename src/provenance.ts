/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * A document's provenance: its current mark and, when the document can
 * advance the chain, the generator (in the clear or password-locked).
 */

// Ported from bc-xid-rust/src/provenance.rs

import { Envelope, type EnvelopeInput } from "@blockchaincommons/envelope";
import {
  lockSubject,
  unlockSubject,
  isLockedWithPassword,
} from "@blockchaincommons/envelope/secret";
import { PROVENANCE_GENERATOR, SALT } from "@blockchaincommons/known-values";
import { Salt } from "@blockchaincommons/components";
import type { KeyDerivationMethod } from "@blockchaincommons/components/kdf";
import { ProvenanceMark, ProvenanceMarkGenerator } from "@blockchaincommons/provenance-mark";

import { XIDError } from "./error";
import { type PasswordOptions, envelopeBytesEqual, kdfOf, passwordBytes } from "./key";

/** How the generator goes into an envelope; the same four forms as private keys. */
export type XIDGeneratorOptions =
  | "omit"
  | "include"
  | "elide"
  | { encrypt: Uint8Array | string; method?: KeyDerivationMethod | undefined };

/** The generator as held: decrypted, or the locked envelope as parsed. */
export type GeneratorData =
  | { type: "decrypted"; generator: ProvenanceMarkGenerator }
  | { type: "encrypted"; envelope: Envelope };

export interface ProvenanceInput {
  generator?: ProvenanceMarkGenerator | undefined;
}

export interface ProvenanceEnvelopeOptions {
  generator?: XIDGeneratorOptions | undefined;
}

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

  get mark(): ProvenanceMark {
    return this._mark;
  }

  /** The generator when held in the clear. */
  get generator(): ProvenanceMarkGenerator | undefined {
    return this._generator?.data.type === "decrypted" ? this._generator.data.generator : undefined;
  }

  get hasGenerator(): boolean {
    return this._generator?.data.type === "decrypted";
  }

  get hasEncryptedGenerator(): boolean {
    return this._generator?.data.type === "encrypted";
  }

  get generatorSalt(): Salt | undefined {
    return this._generator?.salt;
  }

  setMark(mark: ProvenanceMark): void {
    this._mark = mark;
  }

  setGenerator(generator: ProvenanceMarkGenerator): void {
    this._generator = { data: { type: "decrypted", generator }, salt: Salt.random({ length: 32 }) };
  }

  /** Removes and returns the held generator data. */
  takeGenerator(): { data: GeneratorData; salt: Salt } | undefined {
    const gen = this._generator;
    this._generator = undefined;
    return gen;
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
    try {
      const decrypted = unlockSubject(this._generator.data.envelope, passwordBytes(password));
      const generator = ProvenanceMarkGenerator.fromEnvelope(decrypted.unwrap());
      this._generator = { data: { type: "decrypted", generator }, salt: this._generator.salt };
      return generator;
    } catch {
      throw XIDError.invalidPassword();
    }
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

  /** The mark as the subject; the generator per `generator` (a locked one stays locked). */
  toEnvelope({ generator = "omit" }: ProvenanceEnvelopeOptions = {}): Envelope {
    let envelope = Envelope.from(this._mark);
    if (this._generator !== undefined) {
      const { data, salt } = this._generator;
      if (data.type === "encrypted") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope());
      } else if (generator === "include") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope());
      } else if (generator === "elide") {
        envelope = envelope.addAssertionEnvelope(this.generatorAssertionEnvelope().elide());
      } else if (typeof generator === "object") {
        const locked = lockSubject(
          data.generator.toEnvelope().wrap(),
          kdfOf(generator),
          passwordBytes(generator.encrypt),
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
   * locked.
   */
  static fromEnvelope(envelope: Envelope, { password }: PasswordOptions = {}): Provenance {
    const mark = ProvenanceMark.fromCbor(envelope.subject().expectLeaf());
    let generator: { data: GeneratorData; salt: Salt } | undefined;
    const generatorAssertion = envelope.optionalAssertionWithPredicate(PROVENANCE_GENERATOR);
    if (generatorAssertion !== undefined) {
      const generatorObject = generatorAssertion.subject().expectObject();
      const saltAssertion = generatorAssertion.optionalAssertionWithPredicate(SALT);
      if (saltAssertion === undefined) {
        throw XIDError.envelopeParsing(
          new Error("missing 'salt' assertion on provenance-generator node"),
        );
      }
      const salt = Salt.fromCbor(saltAssertion.expectObject().expectLeaf());
      if (isLockedWithPassword(generatorObject)) {
        generator = { data: { type: "encrypted", envelope: generatorObject }, salt };
        if (password !== undefined) {
          try {
            const decrypted = unlockSubject(generatorObject, passwordBytes(password));
            const gen = ProvenanceMarkGenerator.fromEnvelope(decrypted.unwrap());
            generator = { data: { type: "decrypted", generator: gen }, salt };
          } catch {
            // A wrong password leaves the generator locked.
          }
        }
      } else {
        const gen = ProvenanceMarkGenerator.fromEnvelope(generatorObject);
        generator = { data: { type: "decrypted", generator: gen }, salt };
      }
    }
    return new Provenance(mark, generator);
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

  clone(): Provenance {
    return new Provenance(
      this._mark,
      this._generator === undefined
        ? undefined
        : { data: this._generator.data, salt: this._generator.salt },
    );
  }
}
