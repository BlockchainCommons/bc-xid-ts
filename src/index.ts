/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 *
 * XID documents: the keys, delegates, services, resolution methods,
 * provenance, attachments and edges published under an extensible
 * identifier (BCR-2024-010), and their envelope, CBOR and UR forms.
 */

// Ported from bc-xid-rust

export {
  XIDError,
  XID_ERROR_CODES,
  type XIDErrorCode,
  type XIDErrorDetails,
  type ItemDetails,
  type PlainDetails,
  type UnexpectedPredicateDetails,
  type ServiceDetails,
  type UnknownReferenceDetails,
  type KeyNotFoundDetails,
  type DelegateNotFoundDetails,
  type ChainIdMismatchDetails,
  type SequenceMismatchDetails,
  type WrappedDetails,
} from "./error";

export {
  type Privilege,
  PRIVILEGES,
  isPrivilege,
  privilegeKnownValue,
  privilegeFromKnownValue,
  privilegeEnvelope,
  privilegeFromEnvelope,
} from "./privilege";

export { Permissions, type PermissionsInput, type HasPermissions } from "./permissions";

export {
  Key,
  type KeyInput,
  type KeyEnvelopeOptions,
  type PasswordOptions,
  type XIDPrivateKeyOptions,
  type PrivateKeyData,
} from "./key";

export { Service, type ServiceInput } from "./service";

export {
  Delegate,
  type DelegateInput,
  type ParseXIDDocument,
  type XIDDocumentLike,
} from "./delegate";

export {
  Provenance,
  type ProvenanceInput,
  type ProvenanceEnvelopeOptions,
  type XIDGeneratorOptions,
  type GeneratorData,
} from "./provenance";

export {
  XIDDocument,
  type XIDDocumentInput,
  type XIDInceptionKey,
  type XIDGenesis,
  type XIDSigning,
  type XIDVerifySignature,
  type XIDEnvelopeOptions,
  type XIDParseOptions,
  type SignedEnvelopeOptions,
  type NextProvenanceMarkOptions,
} from "./xid-document";
