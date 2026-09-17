/**
 * Builds a XID document, signs it into an envelope, parses it back
 * verified, and advances its provenance chain.
 *
 *   bun examples/document.ts
 */
import { PrivateKeyBase } from "@blockchaincommons/components";
import { CborDate } from "@blockchaincommons/dcbor";
import { format } from "@blockchaincommons/envelope/format";
import { registerTags } from "@blockchaincommons/provenance-mark";
import { Delegate, Key, Service, XIDDocument } from "@blockchaincommons/xid";

registerTags(); // once: the envelope and provenance-mark summarisers, for `format()`

// The inception key controls the document; a genesis mark starts its provenance chain.
const alice = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const doc = XIDDocument.from({
  inceptionKey: alice,
  genesis: { passphrase: "wolf", resolution: "low", date: new Date("2025-01-01T00:00:00Z") },
});
doc.addResolutionMethod("https://resolver.example.com");

// A second key, allowed to sign only.
const bob = PrivateKeyBase.from(Uint8Array.from({ length: 32 }, (_, i) => 255 - i));
const signing = Key.from(bob.schnorrPublicKeys(), { privateKeys: bob.schnorrPrivateKeys() });
signing.addAllow("Sign");
doc.addKey(signing);

// A service the inception key may use.
const service = Service.from("https://messaging.example.com", {
  capability: "com.example.messaging",
});
service.addKey(doc.inceptionKey ?? signing);
service.addAllow("All");
doc.addService(service);

// A delegate: another party's document (its public keys only), allowed to encrypt on this one's behalf.
const carol = XIDDocument.from({
  inceptionKey: PrivateKeyBase.from(
    Uint8Array.from({ length: 32 }, (_, i) => 2 * i + 1),
  ).schnorrPublicKeys(),
});
const delegate = Delegate.from(carol);
delegate.addAllow("Encrypt");
doc.addDelegate(delegate);

// Signed by the inception key, private keys encrypted with a password, generator kept.
const envelope = doc.toEnvelope({
  privateKeys: { encrypt: "password" },
  generator: { encrypt: "password" },
  sign: "inception",
});
console.log(format(envelope));
console.log(doc.toUR().toString());

// Parsed back with the signature verified and the material unlocked.
const back = XIDDocument.fromEnvelope(envelope, { password: "password", verify: "inception" });
console.log("round trip equal:", back.equals(doc));

// The next mark in the chain; the date is a `Date` or a `CborDate`.
back.nextProvenanceMarkWithEmbeddedGenerator({
  date: CborDate.fromString("2025-06-01T00:00:00Z"),
});
console.log("provenance seq:", back.provenance?.seq, back.provenance?.toString());
