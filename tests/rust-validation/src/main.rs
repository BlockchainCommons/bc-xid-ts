//! Replays tests/vectors/vectors.json against bc-xid 0.23.0.
//!
//!   cargo run --release -- ../vectors/vectors.json
use bc_components::{
    EncapsulationPrivateKey, EncapsulationPublicKey, KeyDerivationMethod, PrivateKeyBase,
    PrivateKeys, PublicKeys, ReferenceProvider, URI, XIDProvider, XID,
};
use bc_envelope::prelude::*;
#[allow(unused_imports)]
use bc_ur::prelude::*;
use bc_xid::*;
#[allow(unused_imports)]
use dcbor::prelude::*;
use provenance_mark::{ProvenanceMarkGenerator, ProvenanceMarkResolution, ProvenanceSeed};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct File { count: usize, vectors: Vec<Vector> }
#[derive(Deserialize)]
struct Vector { name: String, recipe: Value, expect: String }

type R<T> = std::result::Result<T, String>;

/// `throw:<TS code>` for a bc-xid error: the variant name in SCREAMING_SNAKE, as the TS `XIDError.code`.
fn code(e: &Error) -> String {
    let d = format!("{e:?}");
    let name = d.split(|c| c == '(' || c == ' ' || c == '{').next().unwrap_or(&d).to_string();
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i > 0 { out.push('_'); }
        out.push(c.to_ascii_uppercase());
    }
    format!("throw:{out}")
}
fn xe<T>(r: Result<T>) -> R<T> { r.map_err(|e| code(&e)) }
fn attempt<T>(r: Result<T>, f: impl FnOnce(T) -> String) -> String { match r { Ok(v) => f(v), Err(e) => code(&e) } }

fn s(v: &Value, k: &str) -> Option<String> { v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string()) }
fn unhex(h: &str) -> Vec<u8> { hex::decode(h).unwrap() }
fn res(r: Option<String>) -> ProvenanceMarkResolution {
    match r.as_deref() { Some("low") => ProvenanceMarkResolution::Low, Some("medium") => ProvenanceMarkResolution::Medium, Some("quartile") => ProvenanceMarkResolution::Quartile, _ => ProvenanceMarkResolution::High }
}
fn date(iso: &str) -> Date { Date::from_string(iso).unwrap() }
fn uri(u: &str) -> URI { URI::new(u).unwrap() }

fn pkb(seed: &str) -> PrivateKeyBase { PrivateKeyBase::from_data(unhex(seed)) }
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
fn privilege(n: &str) -> Privilege {
    match n {
        "All" => Privilege::All, "Auth" => Privilege::Auth, "Sign" => Privilege::Sign, "Encrypt" => Privilege::Encrypt,
        "Elide" => Privilege::Elide, "Issue" => Privilege::Issue, "Access" => Privilege::Access, "Delegate" => Privilege::Delegate,
        "Verify" => Privilege::Verify, "Update" => Privilege::Update, "Transfer" => Privilege::Transfer, "Elect" => Privilege::Elect,
        "Burn" => Privilege::Burn, "Revoke" => Privilege::Revoke, _ => panic!("privilege {n}"),
    }
}
fn permissions(obj: &mut dyn HasPermissions, spec: &Value) {
    for p in spec.get("allow").and_then(|a| a.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) { obj.add_allow(privilege(p.as_str().unwrap())); }
    for p in spec.get("deny").and_then(|a| a.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) { obj.add_deny(privilege(p.as_str().unwrap())); }
}
fn kdf(v: &Value) -> KeyDerivationMethod {
    match s(v, "method").as_deref() { Some("hkdf") => KeyDerivationMethod::HKDF, Some("pbkdf2") => KeyDerivationMethod::PBKDF2, Some("scrypt") => KeyDerivationMethod::Scrypt, _ => KeyDerivationMethod::Argon2id }
}
fn priv_opt(v: Option<&Value>) -> XIDPrivateKeyOptions {
    match v {
        None => XIDPrivateKeyOptions::Omit,
        Some(Value::String(x)) => match x.as_str() { "include" => XIDPrivateKeyOptions::Include, "elide" => XIDPrivateKeyOptions::Elide, _ => XIDPrivateKeyOptions::Omit },
        Some(o) => XIDPrivateKeyOptions::Encrypt { method: kdf(o), password: s(o, "encrypt").unwrap().into_bytes() },
    }
}
fn gen_opt(v: Option<&Value>) -> XIDGeneratorOptions {
    match v {
        None => XIDGeneratorOptions::Omit,
        Some(Value::String(x)) => match x.as_str() { "include" => XIDGeneratorOptions::Include, "elide" => XIDGeneratorOptions::Elide, _ => XIDGeneratorOptions::Omit },
        Some(o) => XIDGeneratorOptions::Encrypt { method: kdf(o), password: s(o, "encrypt").unwrap().into_bytes() },
    }
}
fn sign_opt(v: Option<&Value>) -> XIDSigningOptions {
    match v {
        None => XIDSigningOptions::None,
        Some(Value::String(x)) if x == "inception" => XIDSigningOptions::Inception,
        Some(Value::String(_)) => XIDSigningOptions::None,
        Some(o) => XIDSigningOptions::PrivateKeys(priv_keys(&pkb(&s(o, "seed").unwrap()), Some("schnorr"))),
    }
}
fn password(out: &Value) -> Option<Vec<u8>> {
    for k in ["priv", "gen"] { if let Some(o) = out.get(k) { if let Some(pw) = s(o, "encrypt") { return Some(pw.into_bytes()); } } }
    None
}
fn genesis(g: Option<&Value>) -> XIDGenesisMarkOptions {
    let Some(g) = g else { return XIDGenesisMarkOptions::None };
    let r = Some(res(s(g, "res")));
    let d = s(g, "date").map(|x| date(&x));
    let info = s(g, "info").map(CBOR::from);
    match s(g, "passphrase") {
        Some(p) => XIDGenesisMarkOptions::Passphrase(p, r, d, info),
        None => XIDGenesisMarkOptions::Seed(ProvenanceSeed::from_slice(&unhex(&s(g, "seed").unwrap())[..32]).unwrap(), r, d, info),
    }
}
fn make_key(k: &Value) -> Key {
    let p = pkb(&s(k, "seed").unwrap());
    let scheme = s(k, "scheme");
    let mut key = if k.get("private").and_then(|b| b.as_bool()).unwrap_or(false) {
        Key::new_with_private_keys(priv_keys(&p, scheme.as_deref()), pub_keys(&p, scheme.as_deref()))
    } else { Key::new(pub_keys(&p, scheme.as_deref())) };
    if let Some(n) = s(k, "nickname") { key.set_nickname(n); }
    for e in k.get("endpoints").and_then(|a| a.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) { key.add_endpoint(uri(e.as_str().unwrap())); }
    permissions(&mut key, k);
    key
}
fn xid_of(seed: &str) -> XID { XIDDocument::new(XIDInceptionKeyOptions::PublicKeys(pub_keys(&pkb(seed), None)), XIDGenesisMarkOptions::None).xid() }
fn edge(e: &Value) -> Envelope {
    Envelope::new(s(e, "subject").unwrap())
        .add_assertion(known_values::IS_A, s(e, "isA").unwrap())
        .add_assertion(known_values::SOURCE, Envelope::new(s(e, "source").unwrap()))
        .add_assertion(known_values::TARGET, Envelope::new(s(e, "target").unwrap()))
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] { v.get(k).and_then(|a| a.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) }
fn inception_scheme(spec: &Value) -> Option<String> {
    let inc = &spec["inception"];
    if s(inc, "kind").as_deref() == Some("privateKeyBase") { Some("schnorr".into()) } else { s(inc, "scheme") }
}
fn key_pub(spec: &Value, i: i64) -> PublicKeys {
    if i < 0 { pub_keys(&pkb(&s(&spec["inception"], "seed").unwrap()), inception_scheme(spec).as_deref()) }
    else {
        let ks = arr(spec, "keys");
        let k = ks.get(i as usize);
        let seed = k.and_then(|k| s(k, "seed")).unwrap_or_else(|| s(&spec["inception"], "seed").unwrap());
        pub_keys(&pkb(&seed), k.and_then(|k| s(k, "scheme")).as_deref())
    }
}
fn make_service(spec: &Value, sv: &Value, delegates: &[Delegate]) -> R<Service> {
    let mut service = Service::new(uri(&s(sv, "uri").unwrap()));
    if let Some(c) = s(sv, "capability") { xe(service.add_capability(&c))?; }
    if let Some(n) = s(sv, "name") { xe(service.set_name(n))?; }
    for i in arr(sv, "keys") { xe(service.add_key_reference(key_pub(spec, i.as_i64().unwrap()).reference()))?; }
    for i in arr(sv, "delegates") { xe(service.add_delegate_reference(delegates[i.as_u64().unwrap() as usize].reference()))?; }
    permissions(&mut service, sv);
    Ok(service)
}
fn build(spec: &Value) -> R<(XIDDocument, Vec<Delegate>)> {
    let inc = &spec["inception"];
    let p = pkb(&s(inc, "seed").unwrap());
    let scheme = s(inc, "scheme");
    let mut doc = match s(inc, "kind").as_deref().unwrap() {
        "publicKeys" => XIDDocument::new(XIDInceptionKeyOptions::PublicKeys(pub_keys(&p, scheme.as_deref())), genesis(spec.get("genesis"))),
        "privateKeyBase" => XIDDocument::new(XIDInceptionKeyOptions::PrivateKeyBase(p), genesis(spec.get("genesis"))),
        "privateKeys" => XIDDocument::new(XIDInceptionKeyOptions::PublicAndPrivateKeys(pub_keys(&p, scheme.as_deref()), priv_keys(&p, scheme.as_deref())), genesis(spec.get("genesis"))),
        _ => XIDDocument::from_xid(xid_of(&s(inc, "seed").unwrap())),
    };
    for r in arr(spec, "resolution") { doc.add_resolution_method(uri(r.as_str().unwrap())); }
    for k in arr(spec, "keys") { xe(doc.add_key(make_key(k)))?; }
    let mut delegates = Vec::new();
    for ds in arr(spec, "delegates") {
        let controller = match ds.get("doc") { Some(d) => build(d)?.0, None => XIDDocument::from_xid(xid_of(&s(ds, "xidSeed").unwrap())) };
        let mut delegate = Delegate::new(&controller);
        permissions(&mut delegate, ds);
        xe(doc.add_delegate(delegate.clone()))?;
        delegates.push(delegate);
    }
    for sv in arr(spec, "services") { let service = make_service(spec, sv, &delegates)?; xe(doc.add_service(service))?; }
    for a in arr(spec, "attachments") { doc.add_attachment(s(a, "payload").unwrap(), &s(a, "vendor").unwrap(), s(a, "conformsTo").as_deref()); }
    for e in arr(spec, "edges") { doc.add_edge(edge(e)); }
    if !arr(spec, "custom").is_empty() {
        let mut env = xe(doc.to_envelope(XIDPrivateKeyOptions::Omit, XIDGeneratorOptions::Omit, XIDSigningOptions::None))?;
        for kv in arr(spec, "custom") { env = env.add_assertion(kv[0].as_str().unwrap(), kv[1].as_str().unwrap()); }
        doc = xe(XIDDocument::try_from(env))?;
    }
    Ok((doc, delegates))
}
fn omit_format(doc: &XIDDocument) -> R<String> {
    Ok(xe(doc.to_envelope(XIDPrivateKeyOptions::Omit, XIDGeneratorOptions::Omit, XIDSigningOptions::None))?.format())
}
fn sorted(v: Vec<String>) -> String { let mut v = v; v.sort(); v.join(",") }
fn render(rows: &[(&str, String)]) -> String { rows.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n") }
fn attachment_count(doc: &XIDDocument) -> R<usize> {
    let env = xe(doc.to_envelope(XIDPrivateKeyOptions::Omit, XIDGeneratorOptions::Omit, XIDSigningOptions::None))?;
    Ok(env.assertions_with_predicate(known_values::ATTACHMENT).len())
}
fn doc_outputs(doc: &XIDDocument, out: &Value) -> R<String> {
    let env = xe(doc.to_envelope(priv_opt(out.get("priv")), gen_opt(out.get("gen")), sign_opt(out.get("sign"))))?;
    let is_str = |k: &str, want: &str| match out.get(k) { None => want == "omit" || want == "none", Some(Value::String(x)) => x == want, _ => false };
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
fn mutate(spec: &Value, ops: &[Value]) -> R<String> {
    let (mut doc, delegates) = build(spec)?;
    let mut lines = Vec::new();
    for op in ops {
        let name = op[0].as_str().unwrap();
        let idx = |i: usize| op[i].as_i64().unwrap();
        let line: String = match name {
            "removeKey" => attempt(doc.remove_key(&key_pub(spec, idx(1))), |_| "ok".into()),
            "takeKey" => doc.take_key(&key_pub(spec, idx(1))).map(|k| hex::encode((&k).reference().data())).unwrap_or_else(|| "undefined".into()),
            "removeInceptionKey" => doc.remove_inception_key().map(|k| hex::encode((&k).reference().data())).unwrap_or_else(|| "undefined".into()),
            "setNameForKey" => attempt(doc.set_name_for_key(&key_pub(spec, idx(1)), op[2].as_str().unwrap()), |_| "ok".into()),
            "addKey" => attempt(doc.add_key(make_key(&op[1])), |_| "ok".into()),
            "addResolution" => { doc.add_resolution_method(uri(op[1].as_str().unwrap())); "ok".into() }
            "removeResolution" => doc.remove_resolution_method(uri(op[1].as_str().unwrap())).is_some().to_string(),
            "addService" => match make_service(spec, &op[1], &delegates) { Ok(sv) => attempt(doc.add_service(sv), |_| "ok".into()), Err(e) => e },
            "removeService" => attempt(doc.remove_service(uri(op[1].as_str().unwrap())), |_| "ok".into()),
            "takeService" => doc.take_service(uri(op[1].as_str().unwrap())).map(|sv| sv.uri().to_string()).unwrap_or_else(|| "undefined".into()),
            "removeDelegate" => attempt(doc.remove_delegate(&delegates[idx(1) as usize].xid()), |_| "ok".into()),
            "takeDelegate" => doc.take_delegate(&delegates[idx(1) as usize].xid()).map(|d| d.xid().to_hex()[..8].to_string()).unwrap_or_else(|| "undefined".into()),
            "checkContainsKey" => attempt(doc.check_contains_key(&key_pub(spec, idx(1))), |_| "ok".into()),
            "checkContainsDelegate" => attempt(doc.check_contains_delegate(&delegates[idx(1) as usize].xid()), |_| "ok".into()),
            "checkServices" => attempt(doc.check_services_consistency(), |_| "ok".into()),
            "clearAttachments" => { doc.clear_attachments(); "ok".into() }
            "removeAttachment" => {
                let env = xe(doc.to_envelope(XIDPrivateKeyOptions::Omit, XIDGeneratorOptions::Omit, XIDSigningOptions::None))?;
                let digests: Vec<Digest> = env.assertions_with_predicate(known_values::ATTACHMENT).iter().map(|a| a.digest()).collect();
                match digests.get(idx(1) as usize) { Some(d) => if doc.remove_attachment(*d).is_some() { "removed".into() } else { "undefined".into() }, None => "undefined".into() }
            }
            "clearEdges" => { doc.clear_edges(); "ok".into() }
            "removeEdge" => {
                let digests: Vec<Digest> = doc.edges().iter().map(|(d, _)| *d).collect();
                match digests.get(idx(1) as usize) { Some(d) => if doc.remove_edge(*d).is_some() { "removed".into() } else { "undefined".into() }, None => "undefined".into() }
            }
            "nextMark" => {
                let o = &op[1];
                attempt(doc.next_provenance_mark_with_embedded_generator(s(o, "password").map(|p| p.into_bytes()), s(o, "date").map(|d| date(&d)), s(o, "info").map(CBOR::from)), |_| "ok".into())
            }
            "clearProvenance" => { doc.set_provenance(None); "ok".into() }
            "clone" => { doc = doc.clone(); "ok".into() }
            _ => panic!("op {name}"),
        };
        lines.push(format!("{name}={line}"));
    }
    Ok(format!("{}\n===\n{}", lines.join("\n"), omit_format(&doc)?))
}
fn run(r: &Value) -> R<String> {
    match s(r, "k").unwrap().as_str() {
        "doc" => { let (doc, _) = build(&r["doc"])?; doc_outputs(&doc, r.get("out").unwrap_or(&Value::Null)) }
        "decode" => {
            let env = Envelope::from_ur_string(s(r, "ur").unwrap()).map_err(|e| format!("throw:{e}"))?;
            let verify = if s(r, "verify").as_deref() == Some("none") { XIDVerifySignature::None } else { XIDVerifySignature::Inception };
            let pw = s(r, "password").map(|p| p.into_bytes());
            let doc = xe(XIDDocument::from_envelope(&env, pw.as_deref(), verify))?;
            omit_format(&doc)
        }
        "mutate" => mutate(&r["doc"], r["ops"].as_array().unwrap()),
        "key" => {
            let key = make_key(&r["key"]);
            let env = key.clone().into_envelope_opt(priv_opt(r.get("priv")));
            let pw = r.get("priv").and_then(|o| s(o, "encrypt")).map(|p| p.into_bytes());
            let back = xe(Key::try_from_envelope(&env, pw.as_deref()))?;
            let deterministic = matches!(r.get("priv"), Some(Value::String(x)) if x == "omit");
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
            let g = &r["genesis"];
            let rs = res(s(g, "res"));
            let mut generator = match s(g, "passphrase") {
                Some(p) => ProvenanceMarkGenerator::new_with_passphrase(rs, &p),
                None => ProvenanceMarkGenerator::new_with_seed(rs, ProvenanceSeed::from_slice(&unhex(&s(g, "seed").unwrap())).unwrap()),
            };
            let d = date(&s(g, "date").unwrap_or_else(|| "2025-01-01T00:00:00Z".into()));
            let mark = match s(g, "info") { Some(i) => generator.next(d, Some(i)), None => generator.next(d, None::<String>) };
            let provenance = Provenance::new_with_generator(generator, mark.clone());
            let env = provenance.clone().into_envelope_opt(gen_opt(r.get("gen")));
            let pw = s(r, "password").map(|p| p.into_bytes());
            let back = xe(Provenance::try_from_envelope(&env, pw.as_deref()))?;
            let deterministic = matches!(r.get("gen"), Some(Value::String(x)) if x == "omit");
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
            .iter().map(|n| { let p = privilege(n); let kv = known_values::KnownValue::from(&p); format!("{n}={}({}) {}", kv.name(), kv.value(), Envelope::from(&p).format()) })
            .collect::<Vec<_>>().join("\n")),
        k => Err(format!("unknown recipe {k}")),
    }
}

/// `ECPublicKey(<hex>)` summaries: the TypeScript components package shows the first 16 hex characters and an
/// ellipsis, the reference the 8-character short reference (documented in bc-components-ts's RUST_DIVERGENCES).
fn neutral_ec(text: &str) -> String {
    // S1: `ECPublicKey(<hex>)`; S2: the private-key summaries `SigningPrivateKey(…)` and
    // `EncapsulationPrivateKey(…)` (TypeScript repeats the outer reference / prints the raw bytes, the
    // reference prints the inner key's own short reference). Nested parentheses are consumed.
    let mut out = String::new();
    let mut rest = text;
    loop {
        let hit = ["ECPublicKey(", "SigningPrivateKey(", "EncapsulationPrivateKey("]
            .iter()
            .filter_map(|m| rest.find(m).map(|i| (i, *m)))
            .min_by_key(|(i, _)| *i);
        let Some((i, m)) = hit else { break };
        out.push_str(&rest[..i + m.len()]);
        rest = &rest[i + m.len()..];
        let mut depth = 1usize;
        let mut j = 0usize;
        for (k, c) in rest.char_indices() {
            if c == '(' { depth += 1; } else if c == ')' { depth -= 1; if depth == 0 { j = k; break; } }
        }
        out.push_str("…");
        rest = &rest[j..];
    }
    out.push_str(rest);
    out
}
fn summary_class(want: &str, got: &str) -> Option<&'static str> {
    let has = |t: &str, m: &str| t.contains(m);
    if has(want, "SigningPrivateKey(") || has(want, "EncapsulationPrivateKey(") || has(got, "SigningPrivateKey(") { Some("S2") }
    else if has(want, "ECPublicKey(") || has(got, "ECPublicKey(") { Some("S1") }
    else { None }
}
fn fields(text: &str) -> Vec<(String, String)> {
    // Outcomes are `name=value` rows; a value may span lines (the format string) until the next known row.
    const NAMES: [&str; 26] = ["format", "cbor", "ur", "digest", "xid", "reference", "isEmpty", "keys", "inception", "resolution", "services", "delegates", "attachments", "edges", "provenance", "generator", "roundtrip", "verify", "private", "encrypted", "nickname", "endpoints", "mark", "removeKey", "takeKey", "addKey"];
    let mut rows: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(eq) = line.find('=') {
            let name = &line[..eq];
            if NAMES.contains(&name) && !line.starts_with(' ') { rows.push((name.to_string(), line[eq + 1..].to_string())); continue; }
        }
        if let Some(last) = rows.last_mut() { last.1.push('\n'); last.1.push_str(line); }
        else { rows.push((String::new(), line.to_string())); }
    }
    rows
}
/// Classifies a difference; `None` means a real mismatch.
fn expected_divergence(_recipe: &Value, got: &str, want: &str) -> Option<&'static str> {
    if got == want { return None; }
    // E1: a non-XID error's message (envelope, UR, bytewords) has no reference wording.
    let is_code = |t: &str| t.trim_start_matches("throw:").chars().all(|c| c.is_ascii_uppercase() || c == '_');
    if want.starts_with("throw:") && got.starts_with("throw:") && !is_code(want) { return Some("E1"); }
    let a = fields(&neutral_ec(want));
    let b = fields(&neutral_ec(got));
    if a.len() != b.len() { return None; }
    let rendering = want.lines().zip(got.lines()).any(|(x, y)| x != y && neutral_ec(x) == neutral_ec(y));
    let mut class = if rendering { summary_class(want, got) } else { None };
    for ((ka, va), (kb, vb)) in a.iter().zip(b.iter()) {
        if ka != kb { return None; }
        if va == vb { continue; }
        // D1: TypeScript equality ignores private-key and generator material; the reference compares it.
        if ka == "roundtrip" && va == "true" && vb == "false" { if class.is_none() { class = Some("D1"); } continue; }
        return None;
    }
    class
}
fn main() {
    bc_envelope::register_tags();
    let path = std::env::args().nth(1).expect("vectors.json");
    let file: File = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(file.count, file.vectors.len());
    let (mut mismatches, mut expected) = (0, 0);
    let mut classes: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dump: BTreeMap<String, String> = BTreeMap::new();
    for v in &file.vectors {
        let got = std::panic::catch_unwind(|| match run(&v.recipe) { Ok(s) => s, Err(e) => e }).unwrap_or_else(|_| "throw:panic".to_string());
        dump.insert(v.name.clone(), got.clone());
        if got == v.expect { continue; }
        if let Some(class) = expected_divergence(&v.recipe, &got, &v.expect) {
            if class != "D0" {
                expected += 1; *classes.entry(class).or_default() += 1;
                if std::env::var("VERBOSE").is_ok() { eprintln!("expected [{class}] {}\n  rust: {got}\n  ts:   {}", v.name, v.expect); }
                continue;
            }
        }
        mismatches += 1;
        if mismatches <= 60 || std::env::var("VERBOSE").is_ok() { eprintln!("MISMATCH {}\n  rust: {}\n  ts:   {}", v.name, got.replace('\n', "\\n"), v.expect.replace('\n', "\\n")); }
    }
    if let Ok(path) = std::env::var("DUMP") { std::fs::write(path, serde_json::to_string_pretty(&dump).unwrap()).unwrap(); }
    for (c, n) in &classes { println!("expected-divergence [{c}] x{n}"); }
    println!("{} vectors - {} match, {} expected-divergence, {} MISMATCH", file.vectors.len(), file.vectors.len() - mismatches - expected, expected, mismatches);
    if mismatches > 0 { std::process::exit(1); }
}
