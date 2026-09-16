//! Replays a vector file against the `bc-xid` reference crate.
//!
//!   cargo run --release --offline -- ../vectors/vectors.json
//!
//! Every recipe is materialised here with the reference and compared to the
//! TypeScript outcome textually. A rejection renders on both sides as
//! `throw:<code>[<inner code>]|<message>`: the reference's error variant,
//! the variant it wraps for the four wrapping variants, and its `Display`.
//! A row the reference cannot run because the input is JavaScript-only is
//! `js-only` in a named class; a row where the reference panics at a call
//! the port rejects with a typed error is `panic-mapped` when `PANIC_MAPPED`
//! names the port's code; a recipe field this program cannot read exactly
//! is `unparsable`. Anything else that differs is a MISMATCH. Unparsable
//! rows and mismatches make the process exit 1.
use bc_components::{
    EncapsulationPrivateKey, EncapsulationPublicKey, KeyDerivationMethod, PrivateKeyBase, PrivateKeys, PublicKeys,
    Reference, ReferenceProvider, Salt, URI, XIDProvider, XID,
};
use bc_envelope::prelude::*;
#[allow(unused_imports)]
use bc_ur::prelude::*;
use bc_xid::*;
#[allow(unused_imports)]
use dcbor::prelude::*;
use known_values::{DirectoryConfig, KnownValue};
use provenance_mark::{ProvenanceMark, ProvenanceMarkGenerator, ProvenanceMarkResolution, ProvenanceSeed};
use serde::Deserialize;
use serde_json::Value as J;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Rendering errors the way the TypeScript adapter renders them
// ---------------------------------------------------------------------------

/// The variant name of an error's `Debug` form.
fn variant(e: &impl std::fmt::Debug) -> String {
    let d = format!("{e:?}");
    d.split(|c| c == '(' || c == ' ' || c == '{').next().unwrap_or(&d).to_string()
}
trait Render {
    fn render(&self) -> String;
}
impl Render for Error {
    fn render(&self) -> String {
        let code = match self {
            Error::EnvelopeParsing(inner) => format!("EnvelopeParsing[{}]", variant(inner)),
            Error::Component(inner) => format!("Component[{}]", variant(inner)),
            Error::Cbor(inner) => format!("Cbor[{}]", variant(inner)),
            Error::ProvenanceMark(inner) => format!("ProvenanceMark[{}]", variant(inner)),
            other => variant(other),
        };
        format!("throw:{code}|{self}")
    }
}
/// A decoder entry point returns the dcbor error itself; the port throws its `Cbor` code with that message.
impl Render for dcbor::Error {
    fn render(&self) -> String { format!("throw:Cbor[{}]|{self}", variant(self)) }
}
/// A constructor's own input: the components error passes through on both sides.
impl Render for bc_components::Error {
    fn render(&self) -> String { format!("throw:{}|{self}", variant(self)) }
}
/// An envelope failure while assembling a hand-built envelope: the row cannot be built.
impl Render for bc_envelope::Error {
    fn render(&self) -> String { format!("unparsable:envelope assembly failed ({})", variant(self)) }
}
impl Render for bc_ur::Error {
    fn render(&self) -> String {
        let code = match self {
            bc_ur::Error::UR(_) => "Decoder".to_string(),
            bc_ur::Error::Cbor(inner) => format!("Cbor[{}]", variant(inner)),
            other => variant(other),
        };
        format!("throw:{code}|{self}")
    }
}
macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(e.render()),
        }
    };
}
/// A recipe field this program cannot read exactly is an `unparsable` row.
macro_rules! need {
    ($e:expr, $what:expr) => {
        match $e {
            Some(v) => v,
            None => return Err(format!("unparsable:{}", $what)),
        }
    };
}
fn attempt<T>(r: Result<T>, f: impl FnOnce(T) -> String) -> String {
    match r {
        Ok(v) => f(v),
        Err(e) => e.render(),
    }
}

// ---------------------------------------------------------------------------
// The vector file and the recipe fields
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct File { count: usize, vectors: Vec<Vector> }
#[derive(Deserialize, Clone)]
struct Vector { name: String, recipe: J, expect: String }
type R<T> = std::result::Result<T, String>;

fn s(v: &J, k: &str) -> Option<String> { v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string()) }
fn arr<'a>(v: &'a J, k: &str) -> &'a [J] { v.get(k).and_then(|a| a.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) }
fn unhex(h: &str) -> R<Vec<u8>> { hex::decode(h).map_err(|_| format!("unparsable:hex {h}")) }
fn res(r: Option<String>) -> ProvenanceMarkResolution {
    match r.as_deref() {
        Some("low") => ProvenanceMarkResolution::Low,
        Some("medium") => ProvenanceMarkResolution::Medium,
        Some("quartile") => ProvenanceMarkResolution::Quartile,
        _ => ProvenanceMarkResolution::High,
    }
}
fn date(iso: &str) -> R<Date> { Date::from_string(iso).map_err(|_| format!("unparsable:date {iso}")) }
fn uri(u: &str) -> R<URI> { URI::new(u).map_err(|e| e.render()) }
fn pkb(seed: &str) -> R<PrivateKeyBase> { Ok(PrivateKeyBase::from_data(unhex(seed)?)) }
fn pub_keys(p: &PrivateKeyBase, scheme: Option<&str>) -> PublicKeys {
    match scheme {
        Some("schnorr") => p.schnorr_public_keys(),
        Some("ecdsa") => p.ecdsa_public_keys(),
        _ => PublicKeys::new(
            p.ed25519_signing_private_key().public_key().unwrap(),
            EncapsulationPublicKey::X25519(p.x25519_private_key().public_key()),
        ),
    }
}
fn priv_keys(p: &PrivateKeyBase, scheme: Option<&str>) -> PrivateKeys {
    match scheme {
        Some("schnorr") => p.schnorr_private_keys(),
        Some("ecdsa") => p.ecdsa_private_keys(),
        _ => PrivateKeys::with_keys(p.ed25519_signing_private_key(), EncapsulationPrivateKey::X25519(p.x25519_private_key())),
    }
}
fn privilege(n: &str) -> R<Privilege> {
    Ok(match n {
        "All" => Privilege::All, "Auth" => Privilege::Auth, "Sign" => Privilege::Sign, "Encrypt" => Privilege::Encrypt,
        "Elide" => Privilege::Elide, "Issue" => Privilege::Issue, "Access" => Privilege::Access, "Delegate" => Privilege::Delegate,
        "Verify" => Privilege::Verify, "Update" => Privilege::Update, "Transfer" => Privilege::Transfer, "Elect" => Privilege::Elect,
        "Burn" => Privilege::Burn, "Revoke" => Privilege::Revoke, other => return Err(format!("unparsable:privilege {other}")),
    })
}
fn permissions(obj: &mut dyn HasPermissions, spec: &J) -> R<()> {
    for p in arr(spec, "allow") { obj.add_allow(privilege(need!(p.as_str(), "allow"))?); }
    for p in arr(spec, "deny") { obj.add_deny(privilege(need!(p.as_str(), "deny"))?); }
    Ok(())
}
fn kdf(v: &J) -> KeyDerivationMethod {
    match s(v, "method").as_deref() {
        Some("hkdf") => KeyDerivationMethod::HKDF,
        Some("pbkdf2") => KeyDerivationMethod::PBKDF2,
        Some("scrypt") => KeyDerivationMethod::Scrypt,
        _ => KeyDerivationMethod::Argon2id,
    }
}
fn priv_opt(v: Option<&J>) -> R<XIDPrivateKeyOptions> {
    Ok(match v {
        None => XIDPrivateKeyOptions::Omit,
        Some(J::String(x)) => match x.as_str() {
            "omit" => XIDPrivateKeyOptions::Omit,
            "include" => XIDPrivateKeyOptions::Include,
            "elide" => XIDPrivateKeyOptions::Elide,
            other => return Err(format!("unparsable:priv {other}")),
        },
        Some(o) => XIDPrivateKeyOptions::Encrypt { method: kdf(o), password: need!(s(o, "encrypt"), "encrypt").into_bytes() },
    })
}
fn gen_opt(v: Option<&J>) -> R<XIDGeneratorOptions> {
    Ok(match v {
        None => XIDGeneratorOptions::Omit,
        Some(J::String(x)) => match x.as_str() {
            "omit" => XIDGeneratorOptions::Omit,
            "include" => XIDGeneratorOptions::Include,
            "elide" => XIDGeneratorOptions::Elide,
            other => return Err(format!("unparsable:gen {other}")),
        },
        Some(o) => XIDGeneratorOptions::Encrypt { method: kdf(o), password: need!(s(o, "encrypt"), "encrypt").into_bytes() },
    })
}
fn sign_opt(v: Option<&J>) -> R<XIDSigningOptions> {
    Ok(match v {
        None => XIDSigningOptions::None,
        Some(J::String(x)) => match x.as_str() {
            "none" => XIDSigningOptions::None,
            "inception" => XIDSigningOptions::Inception,
            other => return Err(format!("unparsable:sign {other}")),
        },
        Some(o) => XIDSigningOptions::PrivateKeys(priv_keys(&pkb(&need!(s(o, "seed"), "seed"))?, Some("schnorr"))),
    })
}
fn password(out: &J) -> Option<Vec<u8>> {
    for k in ["priv", "gen"] {
        if let Some(o) = out.get(k) { if let Some(pw) = s(o, "encrypt") { return Some(pw.into_bytes()); } }
    }
    None
}
fn verify_of(v: Option<&str>) -> R<XIDVerifySignature> {
    Ok(match v {
        None | Some("none") => XIDVerifySignature::None,
        Some("inception") => XIDVerifySignature::Inception,
        Some(other) => return Err(format!("unparsable:verify {other}")),
    })
}
fn genesis(g: Option<&J>) -> R<XIDGenesisMarkOptions> {
    let Some(g) = g else { return Ok(XIDGenesisMarkOptions::None) };
    let r = Some(res(s(g, "res")));
    let d = match s(g, "date") { Some(x) => Some(date(&x)?), None => None };
    let info = s(g, "info").map(CBOR::from);
    Ok(match s(g, "passphrase") {
        Some(p) => XIDGenesisMarkOptions::Passphrase(p, r, d, info),
        None => {
            let seed = ProvenanceSeed::from_slice(&unhex(&need!(s(g, "seed"), "seed"))?).map_err(|_| "unparsable:seed".to_string())?;
            XIDGenesisMarkOptions::Seed(seed, r, d, info)
        }
    })
}
/// The generator and genesis mark of a `genesis` spec, as the port builds them.
fn genesis_generator(g: &J) -> R<(ProvenanceMarkGenerator, ProvenanceMark)> {
    let rs = res(s(g, "res"));
    let mut generator = match s(g, "passphrase") {
        Some(p) => ProvenanceMarkGenerator::new_with_passphrase(rs, &p),
        None => {
            let seed = ProvenanceSeed::from_slice(&unhex(&need!(s(g, "seed"), "seed"))?).map_err(|_| "unparsable:seed".to_string())?;
            ProvenanceMarkGenerator::new_with_seed(rs, seed)
        }
    };
    let d = date(&s(g, "date").unwrap_or_else(|| "2025-01-01T00:00:00Z".into()))?;
    let mark = match s(g, "info") { Some(i) => generator.next(d, Some(i)), None => generator.next(d, None::<String>) };
    Ok((generator, mark))
}
fn make_key(k: &J) -> R<Key> {
    let p = pkb(&need!(s(k, "seed"), "seed"))?;
    let scheme = s(k, "scheme");
    let mut key = if k.get("private").and_then(|b| b.as_bool()).unwrap_or(false) {
        Key::new_with_private_keys(priv_keys(&p, scheme.as_deref()), pub_keys(&p, scheme.as_deref()))
    } else {
        Key::new(pub_keys(&p, scheme.as_deref()))
    };
    if let Some(n) = s(k, "nickname") { key.set_nickname(n); }
    for e in arr(k, "endpoints") { key.add_endpoint(uri(need!(e.as_str(), "endpoint"))?); }
    permissions(&mut key, k)?;
    Ok(key)
}
fn xid_of(seed: &str) -> R<XID> {
    Ok(XIDDocument::new(XIDInceptionKeyOptions::PublicKeys(pub_keys(&pkb(seed)?, None)), XIDGenesisMarkOptions::None).xid())
}
fn edge(e: &J) -> R<Envelope> {
    Ok(Envelope::new(need!(s(e, "subject"), "subject"))
        .add_assertion(known_values::IS_A, need!(s(e, "isA"), "isA"))
        .add_assertion(known_values::SOURCE, Envelope::new(need!(s(e, "source"), "source")))
        .add_assertion(known_values::TARGET, Envelope::new(need!(s(e, "target"), "target"))))
}
fn inception_scheme(spec: &J) -> Option<String> {
    let inc = &spec["inception"];
    if s(inc, "kind").as_deref() == Some("privateKeyBase") { Some("schnorr".into()) } else { s(inc, "scheme") }
}
fn key_pub(spec: &J, i: i64) -> R<PublicKeys> {
    if i < 0 {
        Ok(pub_keys(&pkb(&need!(s(&spec["inception"], "seed"), "seed"))?, inception_scheme(spec).as_deref()))
    } else {
        let k = arr(spec, "keys").get(i as usize);
        let seed = match k.and_then(|k| s(k, "seed")) { Some(x) => x, None => need!(s(&spec["inception"], "seed"), "seed") };
        Ok(pub_keys(&pkb(&seed)?, k.and_then(|k| s(k, "scheme")).as_deref()))
    }
}
fn make_service(spec: &J, sv: &J, delegates: &[Delegate]) -> R<Service> {
    let mut service = Service::new(uri(&need!(s(sv, "uri"), "uri"))?);
    if let Some(c) = s(sv, "capability") { tri!(service.add_capability(&c)); }
    if let Some(n) = s(sv, "name") { tri!(service.set_name(n)); }
    for i in arr(sv, "keys") { tri!(service.add_key_reference(key_pub(spec, need!(i.as_i64(), "key index"))?.reference())); }
    for i in arr(sv, "delegates") {
        let d = need!(delegates.get(need!(i.as_u64(), "delegate index") as usize), "delegate");
        tri!(service.add_delegate_reference(d.reference()));
    }
    permissions(&mut service, sv)?;
    Ok(service)
}
fn build(spec: &J) -> R<(XIDDocument, Vec<Delegate>)> {
    let inc = &spec["inception"];
    let p = pkb(&need!(s(inc, "seed"), "seed"))?;
    let scheme = s(inc, "scheme");
    let mut doc = match need!(s(inc, "kind"), "kind").as_str() {
        "publicKeys" => XIDDocument::new(XIDInceptionKeyOptions::PublicKeys(pub_keys(&p, scheme.as_deref())), genesis(spec.get("genesis"))?),
        "privateKeyBase" => XIDDocument::new(XIDInceptionKeyOptions::PrivateKeyBase(p), genesis(spec.get("genesis"))?),
        "privateKeys" => {
            let pp = match s(inc, "privateSeed") { Some(seed) => pkb(&seed)?, None => p.clone() };
            XIDDocument::new(
                XIDInceptionKeyOptions::PublicAndPrivateKeys(pub_keys(&p, scheme.as_deref()), priv_keys(&pp, scheme.as_deref())),
                genesis(spec.get("genesis"))?,
            )
        }
        "xid" => XIDDocument::from_xid(xid_of(&need!(s(inc, "seed"), "seed"))?),
        other => return Err(format!("unparsable:kind {other}")),
    };
    for r in arr(spec, "resolution") { doc.add_resolution_method(uri(need!(r.as_str(), "resolution"))?); }
    for k in arr(spec, "keys") { tri!(doc.add_key(make_key(k)?)); }
    let mut delegates = Vec::new();
    for ds in arr(spec, "delegates") {
        let controller = match ds.get("doc") {
            Some(d) => build(d)?.0,
            None => XIDDocument::from_xid(xid_of(&need!(s(ds, "xidSeed"), "xidSeed"))?),
        };
        let mut delegate = Delegate::new(&controller);
        permissions(&mut delegate, ds)?;
        tri!(doc.add_delegate(delegate.clone()));
        delegates.push(delegate);
    }
    for sv in arr(spec, "services") { let service = make_service(spec, sv, &delegates)?; tri!(doc.add_service(service)); }
    for a in arr(spec, "attachments") {
        doc.add_attachment(need!(s(a, "payload"), "payload"), &need!(s(a, "vendor"), "vendor"), s(a, "conformsTo").as_deref());
    }
    for e in arr(spec, "edges") { doc.add_edge(edge(e)?); }
    if !arr(spec, "custom").is_empty() {
        let mut env = omit_envelope(&doc)?;
        for kv in arr(spec, "custom") {
            env = env.add_assertion(need!(kv[0].as_str(), "custom"), need!(kv[1].as_str(), "custom"));
        }
        doc = tri!(XIDDocument::try_from(env));
    }
    Ok((doc, delegates))
}
fn omit_envelope(doc: &XIDDocument) -> R<Envelope> {
    Ok(tri!(doc.to_envelope(XIDPrivilegeOmit::OMIT, XIDGeneratorOptions::Omit, XIDSigningOptions::None)))
}
/// `XIDPrivateKeyOptions::Omit` under a name the reference's option enums share.
struct XIDPrivilegeOmit;
impl XIDPrivilegeOmit { const OMIT: XIDPrivateKeyOptions = XIDPrivateKeyOptions::Omit; }
fn omit_format(doc: &XIDDocument) -> R<String> { Ok(omit_envelope(doc)?.format()) }
fn sorted(v: Vec<String>) -> String { let mut v = v; v.sort(); v.join(",") }
fn render(rows: &[(&str, String)]) -> String { rows.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n") }
fn privileges_of(set: &std::collections::HashSet<Privilege>) -> String { sorted(set.iter().map(|p| format!("{p:?}")).collect()) }
fn attachment_count(doc: &XIDDocument) -> R<usize> {
    Ok(omit_envelope(doc)?.assertions_with_predicate(known_values::ATTACHMENT).len())
}

// ---------------------------------------------------------------------------
// Hand-assembled envelopes
// ---------------------------------------------------------------------------

fn obj(o: &J) -> R<Envelope> {
    let seed_of = |o: &J| -> R<PrivateKeyBase> { pkb(&need!(s(o, "seed"), "seed")) };
    Ok(match need!(s(o, "t"), "t").as_str() {
        "text" => Envelope::new(need!(s(o, "v"), "v")),
        "int" => Envelope::new(need!(o.get("v").and_then(|v| v.as_i64()), "v")),
        "kv" => {
            let value = need!(KNOWN_VALUES.iter().find(|(n, _)| Some(*n) == s(o, "name").as_deref()).map(|(_, v)| *v), "known value name");
            Envelope::new(KnownValue::new(value))
        }
        "uri" => Envelope::new(uri(&need!(s(o, "v"), "v"))?),
        "bytes" => Envelope::new(CBOR::to_byte_string(unhex(&need!(s(o, "hex"), "hex"))?)),
        "xid" => Envelope::new(xid_of(&need!(s(o, "seed"), "seed"))?),
        "ref" => Envelope::new(pub_keys(&seed_of(o)?, s(o, "scheme").as_deref()).reference()),
        "xidRef" => Envelope::new(xid_of(&need!(s(o, "seed"), "seed"))?.reference()),
        "pub" => Envelope::new(pub_keys(&seed_of(o)?, s(o, "scheme").as_deref())),
        "priv" => Envelope::new(priv_keys(&seed_of(o)?, s(o, "scheme").as_deref())),
        "salt" => Envelope::new(Salt::from_data(unhex(&need!(s(o, "hex"), "hex"))?)),
        "mark" => Envelope::new(genesis_generator(need!(o.get("genesis"), "genesis"))?.1),
        "generatorEnv" => genesis_generator(need!(o.get("genesis"), "genesis"))?.0.into_envelope(),
        "doc" => omit_envelope(&build(need!(o.get("doc"), "doc"))?.0)?,
        "node" => {
            let mut env = obj(need!(o.get("subject"), "subject"))?;
            for a in arr(o, "assertions") { env = tri!(env.add_assertion_envelope(assertion(a)?)); }
            env
        }
        "wrapped" => obj(need!(o.get("inner"), "inner"))?.wrap(),
        "elided" => obj(need!(o.get("inner"), "inner"))?.elide(),
        "signed" => obj(need!(o.get("inner"), "inner"))?.sign(&priv_keys(&seed_of(o)?, Some("schnorr"))),
        other => return Err(format!("unparsable:obj {other}")),
    })
}
fn assertion(a: &J) -> R<Envelope> {
    let mut env = Envelope::new_assertion(obj(need!(a.get("pred"), "pred"))?, obj(need!(a.get("obj"), "obj"))?);
    for w in arr(a, "with") { env = tri!(env.add_assertion_envelope(assertion(w)?)); }
    Ok(if a.get("elide").and_then(|b| b.as_bool()).unwrap_or(false) { env.elide() } else { env })
}
fn with_assertions(mut env: Envelope, list: &[J]) -> R<Envelope> {
    for a in list { env = tri!(env.add_assertion_envelope(assertion(a)?)); }
    Ok(env)
}
/// The known values the recipe language names (`KNOWN_VALUES` in `tests/vectors/recipes.ts`).
const KNOWN_VALUES: &[(&str, u64)] = &[
    ("isA", 1), ("note", 4), ("key", 8), ("dereferenceVia", 9), ("name", 11), ("salt", 15), ("nickname", 24),
    ("attachment", 50), ("allow", 60), ("deny", 61), ("endpoint", 62), ("delegate", 63), ("provenance", 64),
    ("privateKey", 65), ("service", 66), ("capability", 67), ("provenanceGenerator", 68), ("edge", 701),
    ("All", 70), ("Sign", 72),
];

// ---------------------------------------------------------------------------
// The recipe kinds
// ---------------------------------------------------------------------------

fn doc_outputs(doc: &XIDDocument, out: &J) -> R<String> {
    let env = tri!(doc.to_envelope(priv_opt(out.get("priv"))?, gen_opt(out.get("gen"))?, sign_opt(out.get("sign"))?));
    let is_str = |k: &str, want: &str| match out.get(k) { None => want == "omit" || want == "none", Some(J::String(x)) => x == want, _ => false };
    let deterministic = is_str("priv", "omit") && is_str("gen", "omit") && is_str("sign", "none");
    let pw = password(out);
    let verify = if is_str("sign", "none") { XIDVerifySignature::None } else { XIDVerifySignature::Inception };
    let inception = doc.inception_key();
    let rows = [
        ("format", env.format()),
        ("cbor", if deterministic { hex::encode(env.tagged_cbor_data()) } else { String::new() }),
        ("ur", if deterministic { env.ur_string() } else { String::new() }),
        ("digest", if deterministic { hex::encode(env.digest().data()) } else { String::new() }),
        ("xid", doc.xid().to_hex()),
        ("reference", hex::encode(doc.reference().data())),
        ("isEmpty", doc.is_empty().to_string()),
        ("keys", doc.keys().len().to_string()),
        ("inception", match inception { None => "-".into(), Some(k) => format!("{}{}", hex::encode((&k).reference().data()), if k.has_private_keys() { " private" } else { "" }) }),
        ("resolution", sorted(doc.resolution_methods().iter().map(|u| u.to_string()).collect())),
        ("services", sorted(doc.services().iter().map(|sv| sv.uri().to_string()).collect())),
        ("delegates", sorted(doc.delegates().iter().map(|d| d.xid().to_hex()[..8].to_string()).collect())),
        ("attachments", attachment_count(doc)?.to_string()),
        ("edges", doc.edges().len().to_string()),
        ("provenance", doc.provenance().map(|m| m.ur_string()).unwrap_or_else(|| "-".into())),
        ("generator", doc.provenance_generator().map(|g| format!("nextSeq={}", g.next_seq())).unwrap_or_else(|| "-".into())),
        ("roundtrip", attempt(XIDDocument::from_envelope(&env, pw.as_deref(), verify), |d| (d == *doc).to_string())),
        ("verify", attempt(XIDDocument::from_envelope(&env, pw.as_deref(), XIDVerifySignature::Inception), |_| "ok".into())),
    ];
    Ok(render(&rows))
}
fn mutate(spec: &J, ops: &[J]) -> R<String> {
    let (mut doc, delegates) = build(spec)?;
    let mut lines = Vec::new();
    for op in ops {
        let name = need!(op[0].as_str(), "op");
        let idx = |i: usize| -> R<i64> { Ok(need!(op.get(i).and_then(|x| x.as_i64()), "op index")) };
        let delegate_at = |i: usize| -> R<&Delegate> { Ok(need!(delegates.get(idx(i)? as usize), "delegate")) };
        let line: String = match name {
            "removeKey" => attempt(doc.remove_key(&key_pub(spec, idx(1)?)?), |_| "ok".into()),
            "takeKey" => doc.take_key(&key_pub(spec, idx(1)?)?).map(|k| hex::encode((&k).reference().data())).unwrap_or_else(|| "undefined".into()),
            "removeInceptionKey" => doc.remove_inception_key().map(|k| hex::encode((&k).reference().data())).unwrap_or_else(|| "undefined".into()),
            "setNameForKey" => attempt(doc.set_name_for_key(&key_pub(spec, idx(1)?)?, need!(op[2].as_str(), "name")), |_| "ok".into()),
            "addKey" => match make_key(&op[1]) { Ok(k) => attempt(doc.add_key(k), |_| "ok".into()), Err(e) => e },
            "addResolution" => { doc.add_resolution_method(uri(need!(op[1].as_str(), "uri"))?); "ok".into() }
            "removeResolution" => doc.remove_resolution_method(uri(need!(op[1].as_str(), "uri"))?).is_some().to_string(),
            "addService" => match make_service(spec, &op[1], &delegates) { Ok(sv) => attempt(doc.add_service(sv), |_| "ok".into()), Err(e) => e },
            "removeService" => attempt(doc.remove_service(uri(need!(op[1].as_str(), "uri"))?), |_| "ok".into()),
            "takeService" => doc.take_service(uri(need!(op[1].as_str(), "uri"))?).map(|sv| sv.uri().to_string()).unwrap_or_else(|| "undefined".into()),
            "removeDelegate" => attempt(doc.remove_delegate(&delegate_at(1)?.xid()), |_| "ok".into()),
            "takeDelegate" => doc.take_delegate(&delegate_at(1)?.xid()).map(|d| d.xid().to_hex()[..8].to_string()).unwrap_or_else(|| "undefined".into()),
            "checkContainsKey" => attempt(doc.check_contains_key(&key_pub(spec, idx(1)?)?), |_| "ok".into()),
            "checkContainsDelegate" => attempt(doc.check_contains_delegate(&delegate_at(1)?.xid()), |_| "ok".into()),
            "checkServices" => attempt(doc.check_services_consistency(), |_| "ok".into()),
            "clearAttachments" => { doc.clear_attachments(); "ok".into() }
            "removeAttachment" => {
                let env = omit_envelope(&doc)?;
                let digests: Vec<Digest> = env.assertions_with_predicate(known_values::ATTACHMENT).iter().map(|a| a.digest()).collect();
                match digests.get(idx(1)? as usize) { Some(d) => if doc.remove_attachment(*d).is_some() { "removed".into() } else { "undefined".into() }, None => "undefined".into() }
            }
            "clearEdges" => { doc.clear_edges(); "ok".into() }
            "removeEdge" => {
                let digests: Vec<Digest> = doc.edges().iter().map(|(d, _)| *d).collect();
                match digests.get(idx(1)? as usize) { Some(d) => if doc.remove_edge(*d).is_some() { "removed".into() } else { "undefined".into() }, None => "undefined".into() }
            }
            "nextMark" => {
                let o = &op[1];
                let d = match s(o, "date") { Some(x) => Some(date(&x)?), None => None };
                attempt(doc.next_provenance_mark_with_embedded_generator(s(o, "password").map(|p| p.into_bytes()), d, s(o, "info").map(CBOR::from)), |_| "ok".into())
            }
            "clearProvenance" => { doc.set_provenance(None); "ok".into() }
            "clone" => { doc = doc.clone(); "ok".into() }
            other => return Err(format!("unparsable:op {other}")),
        };
        lines.push(format!("{name}={line}"));
    }
    Ok(format!("{}\n===\n{}", lines.join("\n"), omit_format(&doc)?))
}
/// The port's `decodeURWith(UR.parse(s), Envelope.codec)`, in the reference's three steps.
fn envelope_from_ur(text: &str) -> R<Envelope> {
    let ur = tri!(UR::from_ur_string(text));
    if let Err(err) = ur.check_type("envelope") {
        return Err(format!("throw:Custom|{err}"));
    }
    Ok(tri!(Envelope::from_untagged_cbor(ur.cbor())))
}
fn run(r: &J) -> R<String> {
    match need!(s(r, "k"), "k").as_str() {
        "doc" => { let (doc, _) = build(&r["doc"])?; doc_outputs(&doc, r.get("out").unwrap_or(&J::Null)) }
        "decode" => {
            let env = envelope_from_ur(&need!(s(r, "ur"), "ur"))?;
            let verify = verify_of(s(r, "verify").as_deref())?;
            let pw = s(r, "password").map(|p| p.into_bytes());
            let doc = tri!(XIDDocument::from_envelope(&env, pw.as_deref(), verify));
            omit_format(&doc)
        }
        "mutate" => mutate(&r["doc"], need!(r["ops"].as_array(), "ops")),
        "key" => {
            let key = make_key(&r["key"])?;
            let env = key.clone().into_envelope_opt(priv_opt(r.get("priv"))?);
            let pw = r.get("priv").and_then(|o| s(o, "encrypt")).map(|p| p.into_bytes());
            let back = tri!(Key::try_from_envelope(&env, pw.as_deref()));
            let deterministic = matches!(r.get("priv"), Some(J::String(x)) if x == "omit");
            Ok(render(&[
                ("format", env.format()),
                ("cbor", if deterministic { hex::encode(env.tagged_cbor_data()) } else { String::new() }),
                ("reference", hex::encode((&key).reference().data())),
                ("roundtrip", (key == back).to_string()),
                ("private", back.has_private_keys().to_string()),
                ("encrypted", back.has_encrypted_private_keys().to_string()),
                ("nickname", back.nickname().to_string()),
                ("endpoints", sorted(back.endpoints().iter().map(|u| u.to_string()).collect())),
            ]))
        }
        "provenance" => {
            let (generator, mark) = genesis_generator(&r["genesis"])?;
            let provenance = Provenance::new_with_generator(generator, mark.clone());
            let env = provenance.clone().into_envelope_opt(gen_opt(r.get("gen"))?);
            let pw = s(r, "password").map(|p| p.into_bytes());
            let back = tri!(Provenance::try_from_envelope(&env, pw.as_deref()));
            let deterministic = matches!(r.get("gen"), Some(J::String(x)) if x == "omit");
            Ok(render(&[
                ("format", env.format()),
                ("cbor", if deterministic { hex::encode(env.tagged_cbor_data()) } else { String::new() }),
                ("mark", mark.ur_string()),
                ("roundtrip", (provenance == back).to_string()),
                ("generator", back.generator().map(|g| format!("nextSeq={}", g.next_seq())).unwrap_or_else(|| "-".into())),
                ("encrypted", back.has_encrypted_generator().to_string()),
            ]))
        }
        "privileges" => Ok(["All", "Auth", "Sign", "Encrypt", "Elide", "Issue", "Access", "Delegate", "Verify", "Update", "Transfer", "Elect", "Burn", "Revoke"]
            .iter()
            .map(|n| { let p = privilege(n).unwrap(); let kv = KnownValue::from(&p); format!("{n}={}({}) {}", kv.name(), kv.value(), Envelope::from(&p).format()) })
            .collect::<Vec<_>>()
            .join("\n")),
        "docEnvelope" => {
            let mut env = match r.get("base") { Some(b) => omit_envelope(&build(b)?.0)?, None => obj(need!(r.get("subject"), "subject"))? };
            env = with_assertions(env, arr(r, "assertions"))?;
            for seed in arr(r, "sign") { env = env.sign(&priv_keys(&pkb(need!(seed.as_str(), "sign"))?, Some("schnorr"))); }
            if r.get("wrap").and_then(|b| b.as_bool()).unwrap_or(false) { env = env.wrap(); }
            env = with_assertions(env, arr(r, "outer"))?;
            let pw = s(r, "password").map(|p| p.into_bytes());
            let doc = tri!(XIDDocument::from_envelope(&env, pw.as_deref(), verify_of(s(r, "verify").as_deref())?));
            Ok(render(&[("format", omit_format(&doc)?), ("extra", doc.extra_assertions().len().to_string())]))
        }
        "keyEnvelope" => {
            let env = with_assertions(obj(need!(r.get("subject"), "subject"))?, arr(r, "assertions"))?;
            let pw = s(r, "password").map(|p| p.into_bytes());
            let key = tri!(Key::try_from_envelope(&env, pw.as_deref()));
            Ok(render(&[
                ("format", key.clone().into_envelope_opt(XIDPrivateKeyOptions::Include).format()),
                ("private", key.has_private_keys().to_string()),
                ("encrypted", key.has_encrypted_private_keys().to_string()),
                ("nickname", key.nickname().to_string()),
                ("endpoints", sorted(key.endpoints().iter().map(|u| u.to_string()).collect())),
                ("allow", privileges_of(key.allow())),
                ("deny", privileges_of(key.deny())),
            ]))
        }
        "serviceEnvelope" => {
            let env = with_assertions(obj(need!(r.get("subject"), "subject"))?, arr(r, "assertions"))?;
            let service = tri!(Service::try_from(&env));
            Ok(render(&[
                ("format", service.clone().into_envelope().format()),
                ("capability", service.capability().to_string()),
                ("name", service.name().to_string()),
                ("keys", service.key_references().len().to_string()),
                ("delegates", service.delegate_references().len().to_string()),
                ("allow", privileges_of(service.allow())),
                ("deny", privileges_of(service.deny())),
            ]))
        }
        "provenanceEnvelope" => {
            let env = with_assertions(obj(need!(r.get("subject"), "subject"))?, arr(r, "assertions"))?;
            let pw = s(r, "password").map(|p| p.into_bytes());
            let provenance = tri!(Provenance::try_from_envelope(&env, pw.as_deref()));
            Ok(render(&[
                ("format", provenance.clone().into_envelope_opt(XIDGeneratorOptions::Include).format()),
                ("generator", provenance.generator().map(|g| format!("nextSeq={}", g.next_seq())).unwrap_or_else(|| "-".into())),
                ("encrypted", provenance.has_encrypted_generator().to_string()),
            ]))
        }
        "cbor" => {
            let cbor = tri!(CBOR::try_from_data(unhex(&need!(s(r, "hex"), "hex"))?));
            // The port's codec decodes the tagged form, as the reference's `TryFrom<CBOR>`.
            let doc = match need!(s(r, "via"), "via").as_str() {
                "tagged" | "codec" => tri!(XIDDocument::try_from(cbor)),
                "untagged" => tri!(XIDDocument::from_untagged_cbor(cbor)),
                other => return Err(format!("unparsable:via {other}")),
            };
            Ok(render(&[("format", omit_format(&doc)?), ("cbor", hex::encode(doc.tagged_cbor_data())), ("isEmpty", doc.is_empty().to_string())]))
        }
        "ur" => {
            // The port's `fromUR(UR.parse(s))`: the UR grammar, the type check (a
            // `dcbor::Error::Custom`, as `from_ur` flattens it), the decoder.
            let ur = tri!(UR::from_ur_string(need!(s(r, "s"), "s")));
            if let Err(err) = ur.check_type("xid") {
                return Err(dcbor::Error::Custom(err.to_string()).render());
            }
            let doc = tri!(XIDDocument::from_untagged_cbor(ur.cbor()));
            Ok(render(&[("format", omit_format(&doc)?), ("isEmpty", doc.is_empty().to_string())]))
        }
        "nickname" => {
            let mut key = Key::new(pub_keys(&pkb("0000000000000000000000000000000000000000000000000000000000000001")?, Some("schnorr")));
            let mut lines = Vec::new();
            for op in arr(r, "ops") {
                let (name, v) = (need!(op[0].as_str(), "op"), need!(op[1].as_str(), "value"));
                let line = match name {
                    "add" => attempt(key.add_nickname(v), |_| "ok".into()),
                    "set" => { key.set_nickname(v); "ok".into() }
                    other => return Err(format!("unparsable:nickname op {other}")),
                };
                lines.push(format!("{name}({})={line}", serde_json::to_string(v).unwrap()));
            }
            Ok(format!("{}\nnickname={}", lines.join("\n"), key.nickname()))
        }
        "construct" => {
            let v = need!(s(r, "v"), "v");
            let mut doc = XIDDocument::new(
                XIDInceptionKeyOptions::PublicKeys(pub_keys(&pkb("0000000000000000000000000000000000000000000000000000000000000001")?, Some("schnorr"))),
                XIDGenesisMarkOptions::None,
            );
            Ok(match need!(s(r, "op"), "op").as_str() {
                "service" => Service::new(uri(&v)?).uri().to_string(),
                "resolution" => { doc.add_resolution_method(uri(&v)?); sorted(doc.resolution_methods().iter().map(|u| u.to_string()).collect()) }
                "endpoint" => {
                    let mut key = doc.inception_key().cloned().expect("the document has its inception key");
                    key.add_endpoint(uri(&v)?);
                    sorted(key.endpoints().iter().map(|u| u.to_string()).collect())
                }
                "keyRefHex" => { let mut sv = Service::new(uri("https://svc.example")?); tri!(sv.add_key_reference(Reference::from_hex(&v))); sv.key_references().len().to_string() }
                "delegateRefHex" => { let mut sv = Service::new(uri("https://svc.example")?); tri!(sv.add_delegate_reference(Reference::from_hex(&v))); sv.delegate_references().len().to_string() }
                other => return Err(format!("unparsable:construct op {other}")),
            })
        }
        "domain" => Ok(format!("js-only:{}", need!(s(r, "cls"), "cls"))),
        other => Err(format!("unparsable:kind {other}")),
    }
}

// ---------------------------------------------------------------------------
// Panics the port rejects with a typed error, by (recipe kind, panic text, port code)
// ---------------------------------------------------------------------------

const PANIC_MAPPED: &[(&str, &str, &str)] = &[
    // `Reference::from_hex` unwraps the hex decode and the size check; the port throws `Hex` / `InvalidSize`.
    ("construct", "InvalidHexCharacter", "Hex"),
    ("construct", "OddLength", "Hex"),
    ("construct", "InvalidSize", "InvalidSize"),
];
fn panic_mapped(kind: &str, text: &str) -> Option<&'static str> {
    PANIC_MAPPED.iter().find(|(k, needle, _)| *k == kind && text.contains(needle)).map(|(_, _, code)| *code)
}
/// The port's code in a `throw:<code>[<inner>]|<message>` outcome.
fn ts_code(want: &str) -> Option<&str> {
    let rest = want.strip_prefix("throw:")?;
    Some(rest.split(|c| c == '[' || c == '|').next().unwrap_or(rest))
}
fn payload(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() { return s.to_string(); }
    if let Some(s) = p.downcast_ref::<String>() { return s.clone(); }
    "non-string panic payload".into()
}
enum Got { Value(String), Panic(String), Hang }
fn run_guarded(v: &Vector, timeout: Duration) -> Got {
    let (tx, rx) = mpsc::channel();
    let recipe = v.recipe.clone();
    std::thread::spawn(move || {
        let got = match catch_unwind(AssertUnwindSafe(|| match run(&recipe) { Ok(s) => s, Err(e) => e })) {
            Ok(s) => Got::Value(s),
            Err(p) => Got::Panic(payload(p)),
        };
        let _ = tx.send(got);
    });
    rx.recv_timeout(timeout).unwrap_or(Got::Hang)
}

fn main() {
    assert_eq!(usize::BITS, 64, "the reference's usize fields are compared as 64-bit integers");
    // No registry directory: the vectors never depend on the runner's home.
    known_values::set_directory_config(DirectoryConfig::new()).expect("the directory configuration is set before any access");
    bc_envelope::register_tags();
    provenance_mark::register_tags();
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: xid-validation <vectors.json> [--verbose]");
    let verbose = args.iter().any(|a| a == "--verbose") || std::env::var("VERBOSE").is_ok();
    let file: File = serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors");
    assert_eq!(file.count, file.vectors.len(), "the file's count must equal its vectors");
    std::panic::set_hook(Box::new(|_| {}));

    let (mut ok, mut mapped, mut js_only, mut mismatch, mut unparsable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut js_by: BTreeMap<String, usize> = Default::default();
    let mut dump: BTreeMap<String, String> = Default::default();
    let cut = |x: &str| if verbose { x.to_string() } else { x.chars().take(200).collect::<String>() };
    let report_mismatch = |name: &str, detail: String| eprintln!("MISMATCH {name}\n  {detail}");

    for v in &file.vectors {
        let kind = s(&v.recipe, "k").unwrap_or_default();
        let want = v.expect.as_str();
        match run_guarded(v, Duration::from_secs(300)) {
            Got::Value(got) => {
                dump.insert(v.name.clone(), got.clone());
                if got == want { ok += 1; continue; }
                if let Some(class) = got.strip_prefix("js-only:") { js_only += 1; *js_by.entry(class.to_string()).or_default() += 1; continue; }
                if let Some(what) = got.strip_prefix("unparsable:") { unparsable += 1; eprintln!("UNPARSABLE {} ({what})", v.name); continue; }
                let (g, w): (Vec<&str>, Vec<&str>) = (got.lines().collect(), want.lines().collect());
                let line = (0..g.len().max(w.len())).find(|&i| g.get(i) != w.get(i)).unwrap_or(0);
                mismatch += 1;
                report_mismatch(&v.name, format!("[line {line}/{}]\n  rust: {}\n  ts:   {}", w.len(), cut(g.get(line).unwrap_or(&"")), cut(w.get(line).unwrap_or(&""))));
            }
            Got::Panic(text) => match panic_mapped(&kind, &text) {
                Some(code) if ts_code(want) == Some(code) => mapped += 1,
                Some(code) => { mismatch += 1; report_mismatch(&v.name, format!("reference panicked ({}) mapped to {code}\n  ts: {}", cut(&text), cut(want))) }
                None => { mismatch += 1; report_mismatch(&v.name, format!("unhandled reference panic: {}\n  ts: {}", cut(&text), cut(want))) }
            },
            Got::Hang => { mismatch += 1; report_mismatch(&v.name, format!("reference did not return within 300s\n  ts: {}", cut(want))) }
        }
    }
    if let Ok(path) = std::env::var("DUMP") { std::fs::write(path, serde_json::to_string_pretty(&dump).unwrap()).unwrap(); }
    let js_detail: Vec<String> = js_by.iter().map(|(k, n)| format!("{k} {n}")).collect();
    println!(
        "{} vectors - {ok} match, {mapped} panic-mapped, {js_only} js-only ({}), {unparsable} unparsable, {mismatch} MISMATCH",
        file.vectors.len(), js_detail.join(", ")
    );
    std::process::exit(if mismatch == 0 && unparsable == 0 { 0 } else { 1 });
}
