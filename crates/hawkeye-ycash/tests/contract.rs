//! Every result shape of `doc/vault-rpc-contract.json` (copied from ycash-dd into tests/data)
//! deserializes into its Rust type and serializes back to the same JSON: samples are generated
//! from the contract itself — every `oneOf` branch, with and without the optional fields — so a
//! field added to, removed from or retyped in the contract fails here. Parameters are checked
//! against the declared parameter objects.

use hawkeye_ycash::types::*;
use hawkeye_ycash::{Amount, Hash256, HexBytes, OutPoint, PubKey, json};
use serde_json::Value;

fn contract() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vault-rpc-contract.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

const HASH: &str = "8f1a6d5b7a31000000000000000000000000000000000000000000000000ab01";
const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// JSON text samples of a contract type: one per `oneOf` branch / optional-field choice.
fn samples(c: &Value, t: &Value, with_optional: bool) -> Vec<String> {
    if let Some(r) = t.get("ref") {
        let shape = &c["shapes"][r.as_str().unwrap()];
        return samples(c, shape, with_optional);
    }
    if let Some(k) = t.get("const") {
        return vec![k.to_string()];
    }
    if let Some(branches) = t.get("oneOf") {
        return branches
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|b| samples(c, b, with_optional))
            .collect();
    }
    match t["type"].as_str().unwrap() {
        "str" => vec!["\"WYEC\"".into()],
        "hex" => vec!["\"57594543\"".into()],
        "hash" => vec![format!("\"{HASH}\"")],
        "key" => vec![format!("\"{KEY}\"")],
        "outpoint" => vec![format!("\"{HASH}:1\"")],
        "address" => vec!["\"tmRGc4CD1UyUdbSJmTUzcB6oDqk4qUaHnnh\"".into()],
        "int" => vec!["3".into()],
        "height" => vec!["120".into()],
        "bool" => vec!["true".into()],
        "yec" => vec!["20999999.99999999".into()],
        "zat" => vec!["2099999999999999".into()],
        "null" => vec!["null".into()],
        "any" => vec!["null".into()],
        "array" => samples(c, &t["items"], with_optional)
            .into_iter()
            .map(|s| format!("[{s}]"))
            .collect(),
        "object" => {
            let optional: Vec<&str> = t["optional"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o.as_str().unwrap())
                .collect();
            let mut out = vec![String::new()];
            for (k, ft) in t["fields"].as_object().unwrap() {
                if optional.contains(&k.as_str()) && !with_optional {
                    continue;
                }
                let vs = samples(c, ft, with_optional);
                out = out
                    .iter()
                    .flat_map(|prefix| {
                        vs.iter().map(move |v| {
                            format!(
                                "{prefix}{}\"{k}\":{v}",
                                if prefix.is_empty() { "" } else { "," }
                            )
                        })
                    })
                    .collect();
            }
            out.into_iter().map(|s| format!("{{{s}}}")).collect()
        }
        other => panic!("contract type {other}"),
    }
}

/// Deserialize `text` (through the crate's decimal-preserving reader) into the method's result
/// type and serialize it back.
fn through(method: &str, text: &str) -> Result<Value, String> {
    fn rt<T: serde::de::DeserializeOwned + serde::Serialize>(text: &str) -> Result<Value, String> {
        let t: T = json::from_str(text).map_err(|e| e.to_string())?;
        serde_json::to_value(&t).map_err(|e| e.to_string())
    }
    match method {
        "vault_getinfo" => rt::<VaultInfo>(text),
        "set_list" => rt::<Vec<Set>>(text),
        "set_getinfo" => rt::<SetInfo>(text),
        "vault_list" => rt::<Vec<TemplateOut>>(text),
        "vault_decodescript" => rt::<DecodedScript>(text),
        "set_create" => rt::<SetCreateResult>(text),
        "set_join" => rt::<SetJoinResult>(text),
        "set_heartbeat" => rt::<HeartbeatResult>(text),
        "set_buildact" | "set_signact" => rt::<ActResult>(text),
        "set_sendact" | "set_equivocation" | "vault_send" | "vault_release" => rt::<Hash256>(text),
        "vault_lock" => rt::<VaultLockResult>(text),
        "vault_buildunlock" => rt::<BuildUnlockResult>(text),
        "set_signunlock" | "set_signcancel" => rt::<SetSigResult>(text),
        "vault_buildcancel" => rt::<BuildCancelResult>(text),
        "vault_ownerspend" => rt::<OwnerSpendResult>(text),
        "vault_app" => rt::<AppResult>(text),
        other => panic!("no Rust type for {other}"),
    }
}

#[test]
fn contract_is_the_node_copy() {
    let c = contract();
    assert_eq!(c["contract"], "vault-rpc");
    assert_eq!(c["branchid"], "6d5b7a31");
    assert_eq!(
        c["source"]["sha256"],
        "744c041915b05f6d850904fbfd44734aea13373f27b9c0aa1bcfe63c32f48819"
    );
    assert_eq!(c["methods"].as_object().unwrap().len(), 21);
}

#[test]
fn every_result_shape_roundtrips() {
    let c = contract();
    let mut checked = 0;
    for (method, m) in c["methods"].as_object().unwrap() {
        for with_optional in [true, false] {
            for text in samples(&c, &m["result"], with_optional) {
                let want = json::to_value(&text).unwrap();
                let got =
                    through(method, &text).unwrap_or_else(|e| panic!("{method}: {e}\n{text}"));
                assert_eq!(
                    got, want,
                    "{method}: serialize(deserialize(x)) != x\n{text}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 60, "{checked} samples");
}

#[test]
fn undocumented_or_missing_fields_are_noticed() {
    // a required field missing is an error; an extra field is dropped (so the roundtrip above
    // would catch a shape that the node grows)
    assert!(
        through(
            "vault_lock",
            &format!(r#"{{"txid":"{HASH}","vout":0,"outpoint":"{HASH}:0","script":"00"}}"#)
        )
        .is_err()
    );
    let extra = format!(r#"{{"txid":"{HASH}","selector":2,"extra":1}}"#);
    assert_eq!(
        through("vault_ownerspend", &extra).unwrap(),
        serde_json::json!({"txid": HASH, "selector": 2})
    );
}

#[test]
fn amounts_are_exact() {
    let c = contract();
    let text = &samples(&c, &c["methods"]["set_getinfo"]["result"], true)[0];
    let s: SetInfo = json::from_str(text).unwrap();
    assert_eq!(s.set.lockedvalue, Amount(2_099_999_999_999_999));
    assert_eq!(s.set.params.bondmin, Amount(2_099_999_999_999_999));
    assert_eq!(s.memberlist[0].bondvalue.zat(), 2_099_999_999_999_999);
    let t: Vec<TemplateOut> = json::from_str(r#"[{"txid":"00000000000000000000000000000000000000000000000000000000000000aa","vout":0,
        "outpoint":"00000000000000000000000000000000000000000000000000000000000000aa:0","kind":"vault","value":0.30000000,
        "valuezat":30000000,"height":5,"script":"00","tag":"57594543","tagtext":"WYEC",
        "setid":"00000000000000000000000000000000000000000000000000000000000000bb",
        "cancelsetid":"00000000000000000000000000000000000000000000000000000000000000bb","delay":6,"ownerheight":400,
        "appheight":0,"ownerkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","wallet":false}]"#)
    .unwrap();
    let v = t[0].as_vault().unwrap();
    assert_eq!(v.value.zat(), v.valuezat);
    assert_eq!(
        v.fields.setid.0[0], 0xbb,
        "set ids are kept in internal order"
    );
}

// ------------------------------------------------------------------------------- parameters

fn param_object<'a>(c: &'a Value, method: &str, index: usize) -> &'a Value {
    let t = &c["methods"][method]["params"][index]["type"];
    match t.get("ref") {
        Some(r) => &c["shapes"][r.as_str().unwrap()],
        None => t,
    }
}

/// Every key we send is declared, every required key is present, and values have the JSON kind
/// the contract names (`yec` as a decimal string, which `AmountFromValue` accepts).
fn check_object(c: &Value, decl: &Value, sent: &Value, what: &str) {
    let fields = decl["fields"].as_object().unwrap();
    let optional: Vec<&str> = decl["optional"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_str().unwrap())
        .collect();
    let sent = sent
        .as_object()
        .unwrap_or_else(|| panic!("{what}: not an object"));
    for (k, v) in sent {
        let ft = fields
            .get(k)
            .unwrap_or_else(|| panic!("{what}: {k} is not a declared parameter"));
        check_value(c, ft, v, &format!("{what}.{k}"));
    }
    for k in fields.keys() {
        assert!(
            sent.contains_key(k) || optional.contains(&k.as_str()),
            "{what}: required {k} missing"
        );
    }
}

fn check_value(c: &Value, t: &Value, v: &Value, what: &str) {
    if let Some(r) = t.get("ref") {
        return check_value(c, &c["shapes"][r.as_str().unwrap()], v, what);
    }
    if let Some(k) = t.get("const") {
        return assert_eq!(v, k, "{what}");
    }
    if let Some(bs) = t.get("oneOf") {
        assert!(
            bs.as_array()
                .unwrap()
                .iter()
                .any(|b| b.get("const").is_none_or(|k| k == v)),
            "{what}"
        );
        return;
    }
    match t["type"].as_str().unwrap() {
        "str" | "address" => assert!(v.is_string(), "{what}"),
        "hex" => assert!(v.as_str().is_some_and(|s| hex::decode(s).is_ok()), "{what}"),
        "hash" => assert!(v.as_str().is_some_and(|s| s.len() == 64), "{what}"),
        "key" => assert!(v.as_str().is_some_and(|s| s.len() == 66), "{what}"),
        "outpoint" => assert!(
            v.as_str().is_some_and(|s| s.parse::<OutPoint>().is_ok()),
            "{what}"
        ),
        "int" | "height" => assert!(v.is_u64() || v.is_i64(), "{what}"),
        "bool" => assert!(v.is_boolean(), "{what}"),
        "yec" => assert!(
            v.as_str().is_some_and(|s| s.parse::<Amount>().is_ok()),
            "{what}: {v}"
        ),
        "array" => v
            .as_array()
            .unwrap()
            .iter()
            .for_each(|i| check_value(c, &t["items"], i, what)),
        "object" => check_object(c, t, v, what),
        other => panic!("{other}"),
    }
}

#[test]
fn parameters_match_the_contract() {
    let c = contract();
    let h: Hash256 = HASH.parse().unwrap();
    let k: PubKey = KEY.parse().unwrap();
    let full = SetCreateParams {
        seats: 3,
        unlockthreshold: 1,
        cancelthreshold: Some(1),
        slashthreshold: Some(2),
        open: Some(false),
        ratelimitbps: Some(5000),
        ratewindow: Some(20),
        livenesswindow: Some(60),
        bondmin: Some(Amount(100_000_000)),
        bondlockmin: Some(50),
        maturity: Some(2),
        admitkey: Some(k),
    };
    let minimal = SetCreateParams {
        seats: 3,
        unlockthreshold: 1,
        ..Default::default()
    };
    for p in [&full, &minimal] {
        check_object(
            &c,
            param_object(&c, "set_create", 0),
            &serde_json::to_value(p).unwrap(),
            "set_create",
        );
    }
    let lock = VaultLockParams {
        tag: "WYEC".into(),
        setid: h,
        cancelsetid: Some(h),
        delay: 6,
        ownerheight: 400,
        appheight: None,
        amount: Amount(1_000_000_000),
        ownerkey: Some(k),
    };
    check_object(
        &c,
        param_object(&c, "vault_lock", 0),
        &serde_json::to_value(&lock).unwrap(),
        "vault_lock",
    );
    let filter = VaultListFilter {
        tag: Some("WYEC".into()),
        setid: Some(h),
        owner: Some(k),
        kind: Some(TemplateKind::Intent),
        mine: Some(true),
    };
    check_object(
        &c,
        param_object(&c, "vault_list", 0),
        &serde_json::to_value(&filter).unwrap(),
        "vault_list",
    );
    let recips = vec![
        Recipient::address("tmX", Amount(1)),
        Recipient::script(vec![0x51], Amount(2)),
    ];
    let rv = serde_json::to_value(&recips).unwrap();
    check_value(
        &c,
        &c["methods"]["vault_buildunlock"]["params"][1]["type"],
        &rv,
        "vault_buildunlock.recipients",
    );
    assert_eq!(
        rv,
        serde_json::json!([{"address": "tmX", "amount": "0.00000001"}, {"script": "51", "amount": "0.00000002"}])
    );
    let proof = Proof {
        setid: h,
        prevout: OutPoint::new(h, 0),
        rolea: 1,
        sighasha: HASH.parse().unwrap(),
        siga: HexBytes(vec![0x1f; 65]),
        roleb: 2,
        sighashb: HASH.parse().unwrap(),
        sigb: HexBytes(vec![0x20; 65]),
    };
    check_object(
        &c,
        param_object(&c, "set_equivocation", 0),
        &serde_json::to_value(&proof).unwrap(),
        "set_equivocation",
    );
    let acts = [
        BuildAct::Create(full.clone()),
        BuildAct::Join {
            setid: h,
            bondamount: Amount(100_000_000),
            bondlocktime: 500,
            memberkey: Some(k),
        },
        BuildAct::Join {
            setid: h,
            bondamount: Amount(100_000_000),
            bondlocktime: 500,
            memberkey: None,
        },
        BuildAct::Heartbeat {
            setid: h,
            memberkey: k,
        },
        BuildAct::Remove {
            setid: h,
            memberkey: k,
            burn: true,
        },
        BuildAct::Equivocation(proof),
        BuildAct::Winddown { setid: h },
    ];
    for a in &acts {
        // set_buildact's params object declares every field optional; check the kinds
        check_object(
            &c,
            param_object(&c, "set_buildact", 1),
            &a.params().unwrap(),
            a.act_type().as_str(),
        );
        check_value(
            &c,
            &c["methods"]["set_buildact"]["params"][0]["type"],
            &a.act_type().as_str().into(),
            "type",
        );
    }
    // `burn` is a bool on the way in (src/rpc/vault.cpp:922 get_bool), an int on the way out
    assert_eq!(
        BuildAct::Remove {
            setid: h,
            memberkey: k,
            burn: true
        }
        .params()
        .unwrap()["burn"],
        true
    );
}
