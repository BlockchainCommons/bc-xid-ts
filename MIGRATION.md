# Migrating to the redesigned `@blockchaincommons/xid`

Every wire form — the document envelope and each key, delegate, service,
provenance, attachment and edge assertion inside it, the private-key and
generator forms (included with their salt, elided, password-locked),
signatures, tagged CBOR and UR — is unchanged. This was proven against the
published pre-redesign packages (`@bcts/xid` 1.0.0-beta.6 and its closure,
frozen as `tests/baseline`; `tests/differential.test.ts`, zero differences
outside the two tombstones below) and against `bc-xid-rust` 0.23.0
(`tests/rust-validation`: 184 of 203 vectors byte-identical, the other 19
the rendering conventions in `RUST_DIVERGENCES.md`).

Two behaviours moved toward the reference on the way:

- **Attachments** rendered `'attachment': 'attachment': {…}` (the
  pre-redesign envelope wrapped each stored attachment twice); they now
  render `'attachment': {…}` as the reference does.
- **Equality** compared public content only; `XIDDocument.equals`,
  `Key.equals`, `Delegate.equals`, `Service.equals` and `Provenance.equals`
  now compare every field, private keys, salts and the generator included,
  as the reference's `PartialEq` does. A document re-parsed from an envelope
  that omitted its private keys is no longer equal to the original.

## 1. Documents

| Before | After |
|---|---|
| `XIDDocument.new({ type: "publicKeys", publicKeys }, { type: "none" })` | `XIDDocument.from({ inceptionKey: publicKeys })` |
| `XIDDocument.new({ type: "privateKeyBase", privateKeyBase }, …)` | `XIDDocument.from({ inceptionKey: privateKeyBase })` |
| `XIDDocument.new({ type: "privateKeys", privateKeys, publicKeys }, …)` | `XIDDocument.from({ inceptionKey: { publicKeys, privateKeys } })` |
| `XIDDocument.new()` / `{ type: "default" }` | `XIDDocument.random({ rng? })` |
| genesis `{ type: "passphrase", passphrase, resolution, date, info }` / `{ type: "seed", seed, … }` | `genesis: { passphrase \| seed, resolution?, date?, info? }` (resolution is `"low" \| "medium" \| "quartile" \| "high"`) |
| `doc.xid()`, `reference()`, `keys()`, `delegates()`, `services()`, `resolutionMethods()`, `provenance()`, `provenanceGenerator()`, `inceptionKey()`, `inceptionPrivateKeys()`, `inceptionSigningKey()`, `verificationKey()`, `encryptionKey()`, `isEmpty()`, `hasAttachments()`, `getAttachments()`, `extraAssertions()` | getters: `doc.xid`, `doc.reference`, `doc.keys`, … `doc.attachments`, `doc.extraAssertions` (`edges()` and `hasEdges()` stay methods: envelope's `Edgeable`) |
| `findKeyByPublicKeys(p)` / `findKeyByReference(r)` / `findDelegateByXid(x)` / `findDelegateByReference(r)` / `findServiceByUri(u)` | `key(p)` / `keyByReference(r)` / `delegate(x)` / `delegateByReference(r)` / `service(u)` |
| `checkContainsKey(p)` / `checkContainsDelegate(x)` / `checkServicesConsistency()` / `checkServiceConsistency(s)` | `expectKey(p)` / `expectDelegate(x)` / `expectServicesConsistent()` / `expectServiceConsistent(s)` (the first two return the item) |
| `removeKey(p): void` / `removeDelegate(x): void` / `removeService(u): void` | return the removed item (`StillReferenced`/`NotFound` as before); `takeKey`/`takeDelegate`/`takeService` unchanged (unchecked, `undefined` when absent) |
| `getAttachment(d)` | `attachment(d)` (`getEdge(d)` stays, `edge(d)` added) |
| `toEnvelope(privateKeyOptions, generatorOptions, signingOptions)` | `toEnvelope({ privateKeys?, generator?, sign? })` — `sign` is `"none"`, `"inception"` or a `Signer` |
| `intoEnvelope()` | `toEnvelope()` (`ToEnvelope`) |
| `toSignedEnvelope(signer)` / `toSignedEnvelopeOpt(signer, privateKeyOptions)` | `toSignedEnvelope(signer, { privateKeys? })` |
| `fromEnvelope(envelope, password, verifySignature)` / `tryFromEnvelope(envelope)` | `fromEnvelope(envelope, { password?, verify?: "none" \| "inception" })` |
| `extractInceptionPrivateKeysFromEnvelope(e, pw)` | `inceptionPrivateKeysFromEnvelope(e, pw)` |
| `privateKeyEnvelopeForKey(p, password)` | `privateKeyEnvelopeForKey(p, { password })` |
| `nextProvenanceMarkWithEmbeddedGenerator(password, date, info)` / `nextProvenanceMarkWithProvidedGenerator(generator, date, info)` | `nextProvenanceMark({ date?, info?, password?, generator? })` |
| `ur()` / `urString()` / `fromUR` / `fromURString(s)` | `toUR()` / `toUR().toString()` / `fromUR(ur)` / `fromUR(UR.parse(s))` |
| `untaggedCbor()` / `fromUntaggedCbor(c)` | `untaggedCbor()`, `toCbor()` (tag `xid`), `fromCbor(c)`, `XIDDocument.codec` |

## 2. Keys, services, delegates, provenance

| Before | After |
|---|---|
| `Key.new(p)` / `Key.newAllowAll(p)` / `Key.newWithPrivateKeys(priv, pub)` / `Key.newWithPrivateKeyBase(b)` | `Key.from(p, { privateKeys?, nickname?, endpoints?, permissions? })` / `Key.allowAll(p)` / `Key.from(pub, { privateKeys: priv })` / `Key.fromPrivateKeyBase(b)` |
| `key.publicKeys()`, `privateKeys()`, `hasPrivateKeys()`, `hasEncryptedPrivateKeys()`, `privateKeySalt()`, `reference()`, `signingPublicKey()`, `nickname()`, `endpoints()`, `permissions()`, `permissionsMut()` | getters (`encapsulationPublicKey()` stays a method, like `PublicKeys`') |
| `key.addPermission(p)` / `HasPermissionsMixin.addAllow(key, p)` / `…addDeny` | `key.allow(p)` / `key.deny(p)` (also on `Service` and `Delegate`); `key.permissions` for the rest |
| `HasNicknameMixin.addNickname(key, n)` | `key.setNickname(n)` |
| `key.intoEnvelopeOpt(options)` / `intoEnvelope()` | `key.toEnvelope({ privateKeys? })` |
| `Key.tryFromEnvelope(e, password)` | `Key.fromEnvelope(e, { password? })` |
| `key.privateKeyEnvelope(password)` | `key.privateKeyEnvelope({ password? })` |
| `key.hashKey()` | `key.reference.toHex()` |
| `Service.new(uri)` | `Service.from(uri, { capability?, name?, keyReferences?, delegateReferences?, permissions? })` |
| `service.uri()`, `uriString()`, `capability()`, `name()`, `keyReferences()`, `delegateReferences()`, `permissions()`, `keyReferencesMut()`, `delegateReferencesMut()` | `service.uri`, `uri.toString()`, `capability`, `name`, `keyReferences`, `delegateReferences`, `permissions`; `hasKeyReference(r)`/`hasDelegateReference(r)` |
| `service.addKey({ publicKeys() })` / `addDelegate({ xid() })` | `addKey(key)` / `addDelegate(delegate \| document)` (getters) |
| `Service.tryFromEnvelope(e)` / `service.intoEnvelope()` | `Service.fromEnvelope(e)` / `service.toEnvelope()` |
| `Delegate.new(controller)`, `delegate.controller().read()`, `xid()`, `reference()`, `permissions()` | `Delegate.from(controller, { permissions? })`, `delegate.controller`, `xid`, `reference`, `permissions` |
| `Delegate.tryFromEnvelope(e)` (after `registerXIDDocumentClass`) | `Delegate.fromEnvelope(e, (inner) => XIDDocument.fromEnvelope(inner))` |
| `Provenance.new(mark)` / `Provenance.newWithGenerator(generator, mark)` | `Provenance.from(mark, { generator? })` |
| `provenance.mark()`, `generator()`, `hasGenerator()`, `hasEncryptedGenerator()`, `generatorSalt()` | getters |
| `provenance.generatorMut(password)` / `generatorEnvelope(password)` | `unlockGenerator({ password })` / `generatorEnvelope({ password })` |
| `provenance.intoEnvelopeOpt(options)` / `Provenance.tryFromEnvelope(e, password)` | `toEnvelope({ generator? })` / `Provenance.fromEnvelope(e, { password? })` |
| `Permissions.new()` / `newAllowAll()` / `new Permissions(allow, deny)` / `tryFromEnvelope(e)` | `Permissions.from({ allow?, deny? })` / `allowAll()` / `fromEnvelope(e)`; `allow`/`deny` are read-only sets, `addAllow`/`addDeny`/`removeAllow`/`removeDeny`/`clear` mutate |

## 3. Options, privileges, errors

| Before | After |
|---|---|
| `XIDPrivateKeyOptions.Omit` / `.Include` / `.Elide` / `{ type: XIDPrivateKeyOptions.Encrypt, password, method? }` | `"omit"` / `"include"` / `"elide"` / `{ encrypt: password, method? }` (`XIDPrivateKeyOptions` is the union) |
| `XIDGeneratorOptions` likewise | likewise |
| `XIDVerifySignature.None` / `.Inception` | `"none"` / `"inception"` |
| `Privilege.All` … `Privilege.Revoke` (enum) | `"All"` … `"Revoke"` (`Privilege` union, `PRIVILEGES`, `isPrivilege`) |
| `privilegeToKnownValue` / `privilegeToEnvelope` | `privilegeKnownValue` / `privilegeEnvelope` (`privilegeFromKnownValue`/`privilegeFromEnvelope` unchanged) |
| `XIDErrorCode.DUPLICATE` … (enum), `error.code` | `error.code` is `"Duplicate"` … `"ProvenanceMark"` (the reference's variant names; `XIDErrorCode`, `XID_ERROR_CODES`), `error.details` typed per code, `XIDError.isXIDError`, `error.is(code)` |
| `XIDResult<T>` | gone (it was `T`) |
| `Shared<T>`, `HasNickname`, `HasPermissionsMixin`, `HasNicknameMixin`, `registerXIDDocumentClass`, `XIDDocumentType`, `VERSION`, the `XID`/`Attachments`/`Edges`/`Edgeable` re-exports | gone: import `XID` from `@blockchaincommons/components`, `Attachments` from `@blockchaincommons/envelope/attachment`, `Edges`/`Edgeable` from `@blockchaincommons/envelope/edge`; `HasPermissions` and `XIDDocumentLike` are the remaining shape types |

## 4. Dependencies

`@blockchaincommons/dcbor-compat` is gone; `dcbor`, `rand` and `tags` are
declared. The redesigned `components` (`/kdf` for `KeyDerivationMethod`),
`envelope` (`/attachment`, `/edge`, `/secret`, `/signature`, `/types`),
`known-values`, `provenance-mark` and `uniform-resources` are required.

## Appendix: migrating from `@bcts/xid`

`@blockchaincommons/xid` is the canonical home of this library. It was extracted from the
[`paritytech/bcts`](https://github.com/paritytech/bcts) monorepo, where it was
published as `@bcts/xid`, into its own Blockchain Commons repository at
[`BlockchainCommons/bc-xid-ts`](https://github.com/BlockchainCommons/bc-xid-ts).

For the extraction release, **`1.0.0-beta.1`, the public API is unchanged.** The
migration is a rename. `@bcts/xid` remains published for one beta cycle as a
thin re-export of this package, so nothing breaks the moment you update.

### TL;DR checklist

- [ ] Replace the `@bcts/xid` dependency with `@blockchaincommons/xid`.
- [ ] Rewrite import specifiers: `@bcts/xid` becomes `@blockchaincommons/xid`.
- [ ] Raise your Node floor to **22.12**.
- [ ] Ensure TypeScript **>= 5.7** to consume the published types.
- [ ] If you relied on the `browser` field or a global-script build, switch to the ESM or CJS entry point.

### 1. Package name and imports

```diff
- import { /* ... */ } from "@bcts/xid";
+ import { /* ... */ } from "@blockchaincommons/xid";
```

```diff
  "dependencies": {
-   "@bcts/xid": "^1.0.0-beta.6"
+   "@blockchaincommons/xid": "^1.0.0-beta.1"
  }
```

### 2. Version numbering restarts

`@bcts/xid` versions moved in lockstep with every other package in the
monorepo, which is why it reached `1.0.0-beta.6`. Each extracted package now
versions independently and starts again at `1.0.0-beta.1`. A lower version
number here does **not** mean older code.

### 3. Node and TypeScript floors moved up

| | `@bcts/xid` | `@blockchaincommons/xid` |
|---|---|---|
| Node | `>= 18` | `>= 22.12` |
| TypeScript (consumers) | 6.x | `>= 5.7` |

### 4. The IIFE / global-script build is gone

`@bcts/xid` shipped an additional IIFE bundle exposed through the `browser`
field. That build is dropped: IIFE entry points cannot share chunks, which forks
module-level singletons across entry points. Use the ESM entry (`import`) or the
CJS entry (`require`); both are declared in `exports` and validated in CI by
`publint` and `@arethetypeswrong/cli`.

### 5. Peer packages renamed too

Every sibling library moved from the `@bcts` scope to `@blockchaincommons`. If
you depend on more than one, rename them together so a single copy of each
shared type is resolved:

| Old | New |
|---|---|
| `@bcts/dcbor` | `@blockchaincommons/dcbor` |
| `@bcts/<name>` | `@blockchaincommons/<name>` |

### 6. What did not change

- The public API: every exported name, signature and type is identical.
- The wire format. Encodings produced by `@bcts/xid` decode here, and the reverse.
- Parity with the Rust reference implementation. See [`RUST_DIVERGENCES.md`](./RUST_DIVERGENCES.md).
