//! Replays the node's golden vector (`tests/data/vault_vectors.json`, ycash-dd
//! `upgrade/quantum-vaults` `d41026209` = ycash6 `0c6c5fdf2`: the post-quantum owner of quantum
//! spec §1, both registered schemes). Hawkeye holds no post-quantum signature code, so the
//! SLH-DSA and Falcon signature bytes of `ownerSpends` are never verified here: what is checked
//! is everything around them (the chunked scriptSig shape, the public key's hash against the
//! template's owner, the ZIP-243 sighash the signature is over).

use hawkeye_core::bytes::{OutPoint, from_hex, from_hex_array};
use hawkeye_core::keys::SecretKey;
use hawkeye_core::pq::PqKeyId;
use hawkeye_core::script::{OP_CHECKSEQUENCEVERIFY, OP_CHECKSETDORMANT, OP_CHECKSETSIG};
use hawkeye_core::setsig::{
    act_msg, recover_compact, recover_compact_lenient, set_sig_msg, sign_compact,
};
use hawkeye_core::sighash::zip243;
use hawkeye_core::template::{
    TemplateKind, TemplateShape, bond_redeem, bond_spk, intent_for, parse_bond, parse_intent,
    parse_selector, parse_vault, template_shape,
};
use hawkeye_core::tx::Transaction;
use hawkeye_core::{IntentParams, VaultParams};
use serde_json::Value;

fn vectors() -> Value {
    let text = include_str!("data/vault_vectors.json");
    serde_json::from_str(text).expect("vault_vectors.json parses")
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
}

fn hx(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().expect("hex string")).expect("hex")
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    from_hex_array("field", v.as_str().expect("hex string")).expect("hex of the right size")
}

fn int(v: &Value) -> u64 {
    v.as_u64().expect("unsigned integer")
}

fn owner(o: &Value) -> PqKeyId {
    PqKeyId::new(int(&o["scheme"]) as u8, arr(&o["hash"])).expect("a registered scheme")
}

fn vault_params(p: &Value) -> VaultParams {
    VaultParams {
        tag: arr(&p["tag"]),
        set_id: arr(&p["setId"]),
        cancel_set_id: arr(&p["cancelSetId"]),
        delay: int(&p["delay"]) as u16,
        owner_height: int(&p["ownerHeight"]) as u32,
        app_height: int(&p["appHeight"]) as u32,
        owner: owner(&p["owner"]),
    }
}

fn intent_params(p: &Value) -> IntentParams {
    IntentParams {
        tag: arr(&p["tag"]),
        recipient_hash: arr(&p["recipientHash"]),
        vault_hash: arr(&p["vaultHash"]),
        delay: int(&p["delay"]) as u16,
        cancel_set_id: arr(&p["cancelSetId"]),
        set_id: arr(&p["setId"]),
        owner: owner(&p["owner"]),
    }
}

#[test]
fn constants() {
    let v = vectors();
    assert_eq!(int(&v["branchId"]), 0x6d5b_7a31);
    assert_eq!(
        int(&v["opcodes"]["CHECKSEQUENCEVERIFY"]),
        u64::from(OP_CHECKSEQUENCEVERIFY)
    );
    assert_eq!(int(&v["opcodes"]["CHECKSETSIG"]), u64::from(OP_CHECKSETSIG));
    assert_eq!(
        int(&v["opcodes"]["CHECKSETDORMANT"]),
        u64::from(OP_CHECKSETDORMANT)
    );
}

#[test]
fn keys() {
    let v = vectors();
    let mut labels = vec![];
    for k in list(&v, "keys") {
        let sk = SecretKey::from_bytes(&arr(&k["secret"])).unwrap();
        assert_eq!(sk.public_key().to_vec(), hx(&k["pubkey"]), "{}", k["label"]);
        labels.push(k["label"].as_str().unwrap().to_owned());
    }
    // no secp256k1 key is an owner any more: `ec-legacy` only builds the rejected former shape
    assert!(labels.iter().any(|l| l == "ec-legacy"));
    assert!(!labels.iter().any(|l| l == "owner"));
}

#[test]
fn vaults() {
    let v = vectors();
    let cases = list(&v, "vaults");
    assert!(!cases.is_empty());
    for c in cases {
        let name = &c["name"];
        let p = vault_params(&c["params"]);
        let script = hx(&c["script"]);
        assert_eq!(p.script().unwrap(), script, "build {name}");
        assert_eq!(parse_vault(&script).unwrap(), p, "parse {name}");
        assert_eq!(
            template_shape(&script),
            Some(TemplateShape::Vault(p)),
            "{name}"
        );
        assert!(parse_intent(&script).is_err(), "{name} is not an intent");
    }
}

/// The PQ owner: `owner = scheme ‖ SHA256(scheme ‖ pk)`; the SLH-DSA public key begins with
/// `PK.seed`, the last 16 bytes of the 48-byte seed (`SK.seed ‖ SK.prf ‖ PK.seed`).
#[test]
fn pq_owner() {
    let v = vectors();
    let o = &v["pqOwner"];
    let pk = hx(&o["pk"]);
    let seed = hx(&o["seed"]);
    assert_eq!((pk.len(), seed.len()), (32, 48));
    assert_eq!(pk[..16], seed[32..]);
    let id = owner(&o["owner"]);
    assert_eq!(id.scheme, 1);
    assert_eq!(PqKeyId::of_public_key(1, &pk).unwrap(), id);
    // every vault and intent of the vector is owned by it, or by the Falcon owner
    let falcon = owner(&v["falconOwner"]["owner"]);
    let mut schemes = vec![];
    for c in list(&v, "vaults").iter().chain(list(&v, "intents")) {
        let p = owner(&c["params"]["owner"]);
        let want = if p.scheme == 2 { falcon } else { id };
        assert_eq!(p, want, "{}", c["name"]);
        schemes.push(p.scheme);
    }
    assert!(
        schemes.contains(&2),
        "the vector covers a Falcon (scheme 2) owner"
    );
}

/// The Falcon owner (`falconOwner`, FN-DSA-512): `owner = 2 ‖ SHA256(2 ‖ pk)` over the 897-byte
/// public key the node's `pq::KeyGen(2, seed)` drew; it owns the `owner-falcon-scheme-2` V and I
/// (A-1: both registered schemes are templates, whatever the node's Falcon flag). The key
/// derivation itself is the node's: only the id is recomputed here.
#[test]
fn falcon_owner() {
    let v = vectors();
    let o = &v["falconOwner"];
    let pk = hx(&o["pk"]);
    assert_eq!((pk.len(), hx(&o["seed"]).len()), (897, 48));
    let id = owner(&o["owner"]);
    assert_eq!(id.scheme, 2);
    assert_ne!(id.hash, owner(&v["pqOwner"]["owner"]).hash);
    assert_eq!(PqKeyId::of_public_key(2, &pk).unwrap(), id);
    let mut seen = 0;
    type OwnerOf = fn(&[u8]) -> Option<PqKeyId>;
    let sections: [(&str, OwnerOf); 2] = [
        ("vaults", |s| parse_vault(s).ok().map(|p| p.owner)),
        ("intents", |s| parse_intent(s).ok().map(|p| p.owner)),
    ];
    for (section, parse) in sections {
        let c = list(&v, section)
            .iter()
            .find(|c| c["name"] == "owner-falcon-scheme-2")
            .unwrap_or_else(|| panic!("{section}: owner-falcon-scheme-2"));
        assert_eq!(owner(&c["params"]["owner"]), id, "{section}");
        assert_eq!(parse(&hx(&c["script"])), Some(id), "{section}");
        seen += 1;
    }
    assert_eq!(seen, 2);
}

/// The cases whose skeleton matches but whose fields do not are `Malformed` (the node rejects
/// the transaction); the former secp256k1 owner shape is not a template at all.
const MALFORMED_V: [&str; 6] = [
    "owner-scheme-0",
    "owner-scheme-3",
    "owner-scheme-16",
    "owner-scheme-as-data-push",
    "owner-schemes-differ",
    "owner-hashes-differ",
];

#[test]
fn vaults_invalid() {
    let v = vectors();
    let cases = list(&v, "vaultsInvalid");
    assert!(!cases.is_empty());
    let mut seen = 0;
    for c in cases {
        let script = hx(&c["script"]);
        let name = c["name"].as_str().unwrap();
        if MALFORMED_V.contains(&name) {
            assert_eq!(
                template_shape(&script),
                Some(TemplateShape::Malformed),
                "{name}"
            );
            seen += 1;
        }
        if name == "owner-ec-key-checksig" {
            assert_eq!(template_shape(&script), None, "{name}");
            seen += 1;
        }
        assert!(
            parse_vault(&script).is_err(),
            "{} ({}) must not parse",
            c["name"],
            c["reason"]
        );
        assert!(
            !matches!(template_shape(&script), Some(TemplateShape::Vault(_))),
            "{}",
            c["name"]
        );
    }
    assert_eq!(
        seen,
        MALFORMED_V.len() + 1,
        "the PQ owner cases are in the vector"
    );
}

#[test]
fn intents() {
    let v = vectors();
    let cases = list(&v, "intents");
    assert!(!cases.is_empty());
    for c in cases {
        let name = &c["name"];
        let p = intent_params(&c["params"]);
        let script = hx(&c["script"]);
        assert_eq!(p.script().unwrap(), script, "build {name}");
        assert_eq!(parse_intent(&script).unwrap(), p, "parse {name}");
        assert_eq!(
            template_shape(&script),
            Some(TemplateShape::Intent(p)),
            "{name}"
        );
        // IntentFor(vault, recipient)
        let vault = parse_vault(&hx(&c["vaultScript"])).expect("vaultScript is a V");
        assert_eq!(
            intent_for(&vault, &hx(&c["recipientScript"])).unwrap(),
            p,
            "intentFor {name}"
        );
    }
}

/// The I owner-slot cases whose skeleton matches but whose fields do not (a scheme outside the
/// registry or pushed as data, a hash of the wrong size) are `Malformed`; the former secp256k1
/// owner shape is not a template at all.
const MALFORMED_I: [&str; 5] = [
    "owner-scheme-0",
    "owner-scheme-3",
    "owner-scheme-as-data-push",
    "owner-hash-31-bytes",
    "owner-hash-33-bytes",
];

#[test]
fn intents_invalid() {
    let v = vectors();
    let cases = list(&v, "intentsInvalid");
    assert!(!cases.is_empty());
    let mut seen = 0;
    for c in cases {
        let script = hx(&c["script"]);
        let name = c["name"].as_str().unwrap();
        assert!(parse_intent(&script).is_err(), "{name} ({})", c["reason"]);
        assert!(
            !matches!(template_shape(&script), Some(TemplateShape::Intent(_))),
            "{name}"
        );
        if MALFORMED_I.contains(&name) {
            assert_eq!(
                template_shape(&script),
                Some(TemplateShape::Malformed),
                "{name}"
            );
            seen += 1;
        }
        if name == "owner-ec-key-checksig" {
            assert_eq!(template_shape(&script), None, "{name}");
            seen += 1;
        }
    }
    assert_eq!(
        seen,
        MALFORMED_I.len() + 1,
        "the PQ owner cases are in the vector"
    );
}

/// A small script number as `parse_selector` returns it (`OP_1..OP_16` as one byte).
fn small(a: &[u8]) -> usize {
    assert_eq!(a.len(), 1, "a small number");
    usize::from(a[0])
}

/// The post-quantum owner spends (quantum plan §4.2): the scriptSig is
/// `<sig_1>…<sig_s> <s> <pk_1>…<pk_p> <p> <selector>`, the signature (with its hashtype byte)
/// and the public key each cut into 520-byte pushes with a shorter last one — SLH-DSA-SHA2-128s
/// 15 × 520 + 57 and one 32-byte key push (7,939 bytes, 19 arguments); FN-DSA-512 520 + 147 and
/// 520 + 377 (1,578 bytes, 6 arguments). Each parses as its `selector` (2 OWNER on a V; 3
/// OWNER-RELEASED on a V and on an I), it is the scriptSig of input `nIn`, the reassembled key
/// hashes to the template's owner, and the input's ZIP-243 sighash is the vector's.
///
/// Not checked: that the signature verifies (`pq::Verify` in the node — Hawkeye has no SLH-DSA or
/// Falcon code and needs none), nor `verify` itself (`script`: the whole spend passes
/// `VerifyScript`; `signature`: selector 3's `OP_CHECKSETDORMANT` needs set state), nor the
/// Falcon signer's `falconEntropy` beyond its presence and size.
#[test]
fn owner_spends() {
    let v = vectors();
    let cases = list(&v, "ownerSpends");
    assert!(
        cases.len() >= 4,
        "selector 2 and 3 on V, selector 3 on I, Falcon"
    );
    let mut selectors = vec![];
    for c in cases {
        let name = &c["name"];
        let script_sig = hx(&c["scriptSig"]);
        let k = kind(&c["kind"]);
        let s = parse_selector(k, &script_sig).unwrap();
        assert_eq!(u64::from(s.selector), int(&c["selector"]), "{name}");
        selectors.push((k, s.selector));
        // <sig chunks> <s> <pk chunks> <p>
        let n = s.args.len();
        let p = small(&s.args[n - 1]);
        let sig_chunks = small(&s.args[n - 2 - p]);
        assert_eq!(n, sig_chunks + 1 + p + 1, "{name}: argument count");
        let pk_chunks = &s.args[n - 1 - p..n - 1];
        let sig_chunks = &s.args[..sig_chunks];
        for (what, chunks) in [("sig", sig_chunks), ("pk", pk_chunks)] {
            let (last, full) = chunks.split_last().unwrap();
            assert!(full.iter().all(|a| a.len() == 520), "{name}: {what} chunks");
            assert!((1..=520).contains(&last.len()), "{name}: last {what} chunk");
        }
        let sig = sig_chunks.concat();
        let pk = pk_chunks.concat();

        // the template and its owner
        let script_code = hx(&c["scriptCode"]);
        let owner = match k {
            TemplateKind::Vault => parse_vault(&script_code).unwrap().owner,
            TemplateKind::Intent => parse_intent(&script_code).unwrap().owner,
        };
        assert_eq!(
            PqKeyId::of_public_key(owner.scheme, &pk).unwrap(),
            owner,
            "{name}"
        );
        let (owner_section, sig_len, script_sig_len) = match owner.scheme {
            1 => ("pqOwner", 7856 + 1, 7939),
            2 => ("falconOwner", 666 + 1, 1578),
            s => panic!("{name}: scheme {s}"),
        };
        assert_eq!(owner, self::owner(&v[owner_section]["owner"]), "{name}");
        assert_eq!(pk, hx(&v[owner_section]["pk"]), "{name}: pk");
        assert_eq!(sig.len(), sig_len, "{name}: signature size");
        assert_eq!(script_sig.len(), script_sig_len, "{name}");
        match &c["falconEntropy"] {
            Value::Null => assert_eq!(owner.scheme, 1, "{name}: an SLH-DSA spend"),
            e => {
                assert_eq!(owner.scheme, 2, "{name}: a Falcon spend");
                assert_eq!(hx(e).len(), 88, "{name}: falconEntropy");
            }
        }
        let verify = c["verify"].as_str().unwrap();
        assert_eq!(
            verify,
            if s.selector == 3 {
                "signature"
            } else {
                "script"
            },
            "{name}"
        );

        // the transaction and the sighash the signature is over
        let tx = Transaction::parse(&hx(&c["tx"])).unwrap();
        let n_in = int(&c["nIn"]) as usize;
        assert_eq!(tx.vin[n_in].script_sig, script_sig, "{name}");
        let sighash = zip243(
            &tx,
            n_in,
            &script_code,
            int(&c["amount"]),
            // the hashtype is the signature's last byte (the end of its last chunk)
            u32::from(*sig.last().unwrap()),
            int(&c["branchId"]) as u32,
        )
        .unwrap();
        assert_eq!(sighash, arr::<32>(&c["sighash"]), "{name}");
    }
    for want in [
        (TemplateKind::Vault, 2),
        (TemplateKind::Vault, 3),
        (TemplateKind::Intent, 3),
    ] {
        assert!(selectors.contains(&want), "{want:?} is in the vector");
    }
}

#[test]
fn bonds() {
    let v = vectors();
    let cases = list(&v, "bonds");
    assert!(!cases.is_empty());
    for c in cases {
        let key = arr(&c["memberKey"]);
        let lt = int(&c["locktime"]) as u32;
        let redeem = hx(&c["redeem"]);
        assert_eq!(bond_redeem(&key, lt), redeem);
        assert_eq!(bond_spk(&key, lt), hx(&c["spk"]));
        assert_eq!(parse_bond(&redeem).unwrap(), (key, lt));
    }
}

fn kind(v: &Value) -> TemplateKind {
    match v.as_str() {
        Some("V") => TemplateKind::Vault,
        Some("I") => TemplateKind::Intent,
        other => panic!("unknown kind {other:?}"),
    }
}

#[test]
fn selectors() {
    let v = vectors();
    let cases = list(&v, "selectors");
    assert!(!cases.is_empty());
    for c in cases {
        let s = parse_selector(kind(&c["kind"]), &hx(&c["scriptSig"])).unwrap();
        assert_eq!(u64::from(s.selector), int(&c["selector"]), "{c}");
        assert_eq!(s.args.len() as u64, int(&c["nArgs"]), "{c}");
    }
    let cases = list(&v, "selectorsInvalid");
    assert!(!cases.is_empty());
    for c in cases {
        assert!(
            parse_selector(kind(&c["kind"]), &hx(&c["scriptSig"])).is_err(),
            "{}",
            c["reason"]
        );
    }
}

#[test]
fn set_sig_msgs() {
    let v = vectors();
    let cases = list(&v, "setSigMsgs");
    assert!(!cases.is_empty());
    for c in cases {
        let prevout = OutPoint::from_bytes(&hx(&c["prevout"])).unwrap();
        let msg = set_sig_msg(
            &arr(&c["setId"]),
            int(&c["role"]) as u8,
            &prevout,
            &arr(&c["sighash"]),
        );
        assert_eq!(msg.to_vec(), hx(&c["msg"]));
    }
}

#[test]
fn signatures() {
    let v = vectors();
    let cases = list(&v, "signatures");
    assert!(!cases.is_empty());
    let mut flipped = 0;
    for c in cases {
        let label = &c["label"];
        let key = SecretKey::from_bytes(&arr(&c["secret"])).unwrap();
        let msg = arr(&c["msg"]);
        let sig = hx(&c["sig"]);
        assert_eq!(
            sign_compact(&key, &msg).unwrap().to_vec(),
            sig,
            "SignCompact {label}"
        );
        assert_eq!(
            recover_compact(&sig, &msg).unwrap().to_vec(),
            hx(&c["pubkey"]),
            "{label}"
        );
        if c["lowSFlipped"].as_bool().unwrap() {
            flipped += 1;
        }
    }
    assert!(
        flipped > 0,
        "the vector covers the high-S normalisation branch"
    );
}

#[test]
fn signatures_invalid() {
    let v = vectors();
    let cases = list(&v, "signaturesInvalid");
    assert!(!cases.is_empty());
    for c in cases {
        let name = &c["name"];
        let msg = arr(&c["msg"]);
        let sig = hx(&c["sig"]);
        assert!(recover_compact(&sig, &msg).is_err(), "strict {name}");
        match &c["nonStrictRecovers"] {
            Value::Null => assert!(
                recover_compact_lenient(&sig, &msg).is_err(),
                "lenient {name}"
            ),
            k => assert_eq!(
                recover_compact_lenient(&sig, &msg).unwrap(),
                hx(k),
                "lenient {name}"
            ),
        }
    }
}

#[test]
fn act_messages_and_signatures() {
    let v = vectors();
    let cases = list(&v, "acts");
    assert!(!cases.is_empty());
    let mut checked = 0;
    for c in cases {
        let name = &c["name"];
        let prevout = OutPoint::from_bytes(&hx(&c["prevout"])).unwrap();
        let msg = act_msg(&hx(&c["payload"]), &prevout);
        assert_eq!(msg.to_vec(), hx(&c["actMsg"]), "actMsg {name}");
        let sigs = list(c, "sigs");
        let recovered = list(c, "recovered");
        assert_eq!(sigs.len(), recovered.len());
        for (s, k) in sigs.iter().zip(recovered) {
            assert_eq!(
                recover_compact(&hx(s), &msg).unwrap().to_vec(),
                hx(k),
                "{name}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
}

/// §4.5 attribution end to end: the set signatures in a template spend's scriptSig recover, over
/// `SetSigMsg(setId, role, prevout of input nIn, sighash)`, to the signers.
#[test]
fn spends_attribution() {
    let v = vectors();
    let keys: Vec<(String, Vec<u8>)> = list(&v, "keys")
        .iter()
        .map(|k| (k["label"].as_str().unwrap().to_owned(), hx(&k["pubkey"])))
        .collect();
    let cases = list(&v, "spends");
    assert!(!cases.is_empty());
    for c in cases {
        let name = &c["name"];
        let tx = hx(&c["tx"]);
        let n_in = int(&c["nIn"]) as usize;
        // v4 header (4) + nVersionGroupId (4) + compact-size vin count (< 0xfd here), then the
        // inputs: prevout (36) + scriptSig (compact size + bytes) + nSequence (4).
        assert!(tx[8] < 0xfd);
        let mut pos = 9;
        for _ in 0..n_in {
            pos += 36;
            let len = usize::from(tx[pos]);
            assert!(len < 0xfd);
            pos += 1 + len + 4;
        }
        let prevout = OutPoint::from_bytes(&tx[pos..pos + 36]).unwrap();
        let role = int(&c["role"]) as u8;
        let msg = set_sig_msg(&arr(&c["setId"]), role, &prevout, &arr(&c["sighash"]));
        assert_eq!(msg.to_vec(), hx(&c["setSigMsg"]), "setSigMsg {name}");

        let script_sig = hx(&c["scriptSig"]);
        let k = if role == 1 {
            TemplateKind::Vault
        } else {
            TemplateKind::Intent
        };
        let spend = parse_selector(k, &script_sig).unwrap();
        assert_eq!(u64::from(spend.selector), u64::from(role), "{name}");
        let sigs: Vec<Vec<u8>> = list(c, "sigs").iter().map(hx).collect();
        assert_eq!(spend.args, sigs, "{name}");
        for (sig, signer) in sigs.iter().zip(list(c, "signers")) {
            let want = &keys
                .iter()
                .find(|(l, _)| l == signer.as_str().unwrap())
                .unwrap()
                .1;
            assert_eq!(
                &recover_compact(sig, &msg).unwrap().to_vec(),
                want,
                "{name} {signer}"
            );
        }
    }
}
