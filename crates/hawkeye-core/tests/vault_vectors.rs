//! Replays the node's golden vector (`tests/data/vault_vectors.json`, ycash-dd `q/tmpl`
//! `a8572900f`: the post-quantum owner of quantum spec §1).

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
    for k in list(&v, "keys") {
        let sk = SecretKey::from_bytes(&arr(&k["secret"])).unwrap();
        assert_eq!(sk.public_key().to_vec(), hx(&k["pubkey"]), "{}", k["label"]);
    }
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
    // every vault and intent of the vector but the scheme-2 case is owned by it
    let mut schemes = vec![];
    for c in list(&v, "vaults").iter().chain(list(&v, "intents")) {
        let p = owner(&c["params"]["owner"]);
        assert_eq!(p.hash, id.hash);
        schemes.push(p.scheme);
    }
    assert!(
        schemes.contains(&2),
        "the vector covers a Falcon (scheme 2) owner"
    );
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

#[test]
fn intents_invalid() {
    let v = vectors();
    let cases = list(&v, "intentsInvalid");
    assert!(!cases.is_empty());
    for c in cases {
        let script = hx(&c["script"]);
        assert!(
            parse_intent(&script).is_err(),
            "{} ({})",
            c["name"],
            c["reason"]
        );
        match c["name"].as_str().unwrap() {
            "owner-ec-key-checksig" => assert_eq!(template_shape(&script), None),
            "owner-scheme-3" => assert_eq!(template_shape(&script), Some(TemplateShape::Malformed)),
            _ => {}
        }
    }
}

/// A post-quantum owner spend (V selector 2): the chunked scriptSig `<sig_1>…<sig_16> OP_16
/// <pk> OP_1 OP_2` (7,939 bytes) parses as selector 2 with 19 arguments, it is the scriptSig of
/// input `nIn`, and the input's ZIP-243 sighash is the vector's.
#[test]
fn owner_spends() {
    let v = vectors();
    let cases = list(&v, "ownerSpends");
    assert!(!cases.is_empty());
    let pk = hx(&v["pqOwner"]["pk"]);
    for c in cases {
        let name = &c["name"];
        let script_sig = hx(&c["scriptSig"]);
        assert_eq!(script_sig.len(), 7939, "{name}");
        let s = parse_selector(TemplateKind::Vault, &script_sig).unwrap();
        assert_eq!(u64::from(s.selector), int(&c["selector"]), "{name}");
        assert_eq!(s.args.len(), 19, "{name}");
        assert!(s.args[..15].iter().all(|a| a.len() == 520), "{name}");
        assert_eq!(s.args[15].len(), 57, "{name}");
        assert_eq!(s.args[16], vec![16], "{name}: s");
        assert_eq!(s.args[17], pk, "{name}: pk");
        assert_eq!(s.args[18], vec![1], "{name}: p");
        let tx = Transaction::parse(&hx(&c["tx"])).unwrap();
        let n_in = int(&c["nIn"]) as usize;
        assert_eq!(tx.vin[n_in].script_sig, script_sig, "{name}");
        let script_code = hx(&c["scriptCode"]);
        assert!(
            parse_vault(&script_code).is_ok(),
            "{name}: scriptCode is a V"
        );
        let sighash = zip243(
            &tx,
            n_in,
            &script_code,
            int(&c["amount"]),
            // the hashtype is the signature's last byte (the end of its last chunk)
            u32::from(*s.args[15].last().unwrap()),
            int(&c["branchId"]) as u32,
        )
        .unwrap();
        assert_eq!(sighash, arr::<32>(&c["sighash"]), "{name}");
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
