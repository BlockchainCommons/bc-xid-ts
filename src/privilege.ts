/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * The privileges a key, delegate or service can be allowed or denied, as
 * the known-value names the reference uses.
 */

// Ported from bc-xid-rust/src/privilege.rs

import {
  type KnownValue,
  PRIVILEGE_ALL,
  PRIVILEGE_AUTH,
  PRIVILEGE_SIGN,
  PRIVILEGE_ENCRYPT,
  PRIVILEGE_ELIDE,
  PRIVILEGE_ISSUE,
  PRIVILEGE_ACCESS,
  PRIVILEGE_DELEGATE,
  PRIVILEGE_VERIFY,
  PRIVILEGE_UPDATE,
  PRIVILEGE_TRANSFER,
  PRIVILEGE_ELECT,
  PRIVILEGE_BURN,
  PRIVILEGE_REVOKE,
} from "@blockchaincommons/known-values";
import { Envelope } from "@blockchaincommons/envelope";

import { XIDError } from "./error";

/**
 * `All` grants every privilege; the operational ones (`Auth`, `Sign`,
 * `Encrypt`, `Elide`, `Issue`, `Access`) and the management ones
 * (`Delegate`, `Verify`, `Update`, `Transfer`, `Elect`, `Burn`, `Revoke`)
 * name one capability each.
 */
export type Privilege =
  | "All"
  | "Auth"
  | "Sign"
  | "Encrypt"
  | "Elide"
  | "Issue"
  | "Access"
  | "Delegate"
  | "Verify"
  | "Update"
  | "Transfer"
  | "Elect"
  | "Burn"
  | "Revoke";

export const PRIVILEGES: readonly Privilege[] = [
  "All",
  "Auth",
  "Sign",
  "Encrypt",
  "Elide",
  "Issue",
  "Access",
  "Delegate",
  "Verify",
  "Update",
  "Transfer",
  "Elect",
  "Burn",
  "Revoke",
];

const KNOWN_VALUES: Record<Privilege, KnownValue> = {
  All: PRIVILEGE_ALL,
  Auth: PRIVILEGE_AUTH,
  Sign: PRIVILEGE_SIGN,
  Encrypt: PRIVILEGE_ENCRYPT,
  Elide: PRIVILEGE_ELIDE,
  Issue: PRIVILEGE_ISSUE,
  Access: PRIVILEGE_ACCESS,
  Delegate: PRIVILEGE_DELEGATE,
  Verify: PRIVILEGE_VERIFY,
  Update: PRIVILEGE_UPDATE,
  Transfer: PRIVILEGE_TRANSFER,
  Elect: PRIVILEGE_ELECT,
  Burn: PRIVILEGE_BURN,
  Revoke: PRIVILEGE_REVOKE,
};

export function isPrivilege(value: unknown): value is Privilege {
  return (PRIVILEGES as readonly unknown[]).includes(value);
}

/** The known value the privilege is encoded as. */
export function privilegeKnownValue(privilege: Privilege): KnownValue {
  const kv = KNOWN_VALUES[privilege] as KnownValue | undefined;
  if (kv === undefined) throw XIDError.unknownPrivilege();
  return kv;
}

/** The privilege a known value names; `UnknownPrivilege` for any other value. */
export function privilegeFromKnownValue(knownValue: KnownValue): Privilege {
  const value = knownValue.value;
  for (const p of PRIVILEGES) if (KNOWN_VALUES[p].value === value) return p;
  throw XIDError.unknownPrivilege();
}

/** The privilege as a known-value envelope. */
export function privilegeEnvelope(privilege: Privilege): Envelope {
  return Envelope.knownValue(privilegeKnownValue(privilege));
}

/** The privilege a known-value envelope names. */
export function privilegeFromEnvelope(envelope: Envelope): Privilege {
  const c = envelope.case;
  if (c.type !== "knownValue") throw XIDError.unknownPrivilege();
  return privilegeFromKnownValue(c.value);
}
