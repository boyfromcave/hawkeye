//! The v4 codec against fixtures produced by the node's Python serialiser
//! (`yellowback_model.serialize_tx_v4`), the node's `sighash.json` random transactions (every
//! format, shielded parts included) and `vault_vectors.json` spends. Regenerate with
//! `tests/data/gen_fixtures.py`.

use hawkeye_ycash::tx::{self, CodecError, Format, Transaction};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}")))
        .unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} in {v}"))
}

fn roundtrip(hex_str: &str, txid: &str, name: &str) -> Transaction {
    let t = Transaction::decode_hex(hex_str).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        t.encode_hex(),
        hex_str,
        "{name}: re-encoding is not byte-exact"
    );
    assert_eq!(t.txid().to_string(), txid, "{name}: txid");
    assert_eq!(tx::txid_of_hex(hex_str).unwrap().to_string(), txid);
    t
}

#[test]
fn python_v4_fixtures_roundtrip() {
    let f = load("v4_transparent.json");
    let cases = f["transactions"].as_array().unwrap();
    assert!(cases.len() >= 12);
    for c in cases {
        let name = s(c, "name");
        let t = roundtrip(s(c, "hex"), s(c, "txid"), name);
        assert_eq!(t.format().unwrap(), Format::SaplingV4, "{name}");
        assert_eq!(
            t.inputs.len() as u64,
            c["inputs"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            t.outputs.len() as u64,
            c["outputs"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(t.lock_time),
            c["lockTime"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(t.expiry_height),
            c["expiryHeight"].as_u64().unwrap(),
            "{name}"
        );
        assert!(!t.has_shielded(), "{name}");
        // rebuilding from the parts gives the same bytes
        let rebuilt = Transaction::new_v4(
            t.inputs.clone(),
            t.outputs.clone(),
            t.lock_time,
            t.expiry_height,
        );
        assert_eq!(rebuilt.encode_hex(), s(c, "hex"), "{name}: new_v4");
    }
    let coinbase = cases.iter().find(|c| c["name"] == "coinbase").unwrap();
    assert!(Transaction::decode_hex(s(coinbase, "hex")).unwrap().inputs[0].is_coinbase());
}

#[test]
fn insert_op_return_matches_python() {
    let f = load("v4_insert_op_return.json");
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for c in cases {
        let name = s(c, "name");
        let data = hex::decode(s(c, "data")).unwrap();
        let out =
            tx::insert_op_return(s(c, "base"), &data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(out, s(c, "expected"), "{name}");
        let t = Transaction::decode_hex(&out).unwrap();
        assert_eq!(t.txid().to_string(), s(c, "expectedTxid"), "{name}");
        let ops: Vec<_> = t.op_returns().collect();
        assert_eq!(ops, vec![(t.outputs.len() - 1, &data[..])], "{name}");
        assert_eq!(t.outputs.last().unwrap().value, 0);
        // a second insertion is refused
        assert!(
            matches!(
                tx::insert_op_return(&out, &data),
                Err(CodecError::AlreadyHasOpReturn(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn insert_refusals_on_fixtures() {
    let f = load("v4_transparent.json");
    let get = |n: &str| {
        s(
            f["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == n)
                .unwrap(),
            "hex",
        )
        .to_owned()
    };
    let memo = [0x48u8; 74];
    // the bridge-sim lock already carries the destination OP_RETURN
    assert_eq!(
        tx::insert_op_return(&get("lock"), &memo),
        Err(CodecError::AlreadyHasOpReturn(1))
    );
    // signatures present: the set signature on vin[0], or fee signatures
    assert_eq!(
        tx::insert_op_return(&get("unlock-signed"), &memo),
        Err(CodecError::InputSigned(0))
    );
    assert_eq!(
        tx::insert_op_return(&get("unlock-set-signed"), &memo),
        Err(CodecError::InputSigned(0))
    );
    // unsigned, or only a bare selector: accepted
    assert!(tx::insert_op_return(&get("unlock-unsigned"), &memo).is_ok());
    assert!(tx::insert_op_return(&get("unlock-selector-only"), &memo).is_ok());
    assert!(
        tx::insert_op_return(&get("release"), &memo).is_ok(),
        "OP_1 alone is a selector"
    );
    assert_eq!(
        tx::insert_op_return(&get("cancel"), &memo),
        Err(CodecError::InputSigned(0))
    );
    assert_eq!(
        tx::insert_op_return(&get("unlock-unsigned"), &[0u8; 81]),
        Err(CodecError::DataSize(81))
    );
}

#[test]
fn node_sighash_vectors_roundtrip() {
    let f = load("sighash_txs.json");
    let txs = f["transactions"].as_array().unwrap();
    let (mut v4, mut v3, mut legacy, mut with_js, mut with_spends, mut with_outputs) =
        (0, 0, 0, 0, 0, 0);
    for (i, c) in txs.iter().enumerate() {
        let name = format!("sighash[{i}] {}", s(c, "format"));
        let t = roundtrip(s(c, "hex"), s(c, "txid"), &name);
        let n = |k: &str| c[k].as_u64().unwrap() as usize;
        assert_eq!(t.inputs.len(), n("inputs"), "{name}");
        assert_eq!(t.outputs.len(), n("outputs"), "{name}");
        assert_eq!(t.version as usize, n("version"), "{name}");
        let sap = t.sapling.clone().unwrap_or_default();
        assert_eq!(sap.spends.len(), n("spends"), "{name}");
        assert_eq!(sap.outputs.len(), n("shieldedOutputs"), "{name}");
        assert_eq!(
            sap.binding_sig.is_some(),
            n("spends") + n("shieldedOutputs") > 0,
            "{name}"
        );
        let js = t.joinsplits.as_ref().map_or(0, |j| j.descriptions.len());
        assert_eq!(js, n("joinSplits"), "{name}");
        match t.format().unwrap() {
            Format::SaplingV4 => v4 += 1,
            Format::OverwinterV3 => v3 += 1,
            Format::Sprout | Format::SproutJoinSplit => legacy += 1,
        }
        with_js += usize::from(js > 0);
        with_spends += usize::from(!sap.spends.is_empty());
        with_outputs += usize::from(!sap.outputs.is_empty());
        if t.has_shielded() {
            // never accepted: whichever rule trips first (random scripts may start with OP_RETURN)
            assert!(tx::insert_op_return(s(c, "hex"), b"m").is_err(), "{name}");
            let mut t2 = t.clone();
            t2.outputs.retain(|o| !o.is_op_return());
            t2.inputs.iter_mut().for_each(|i| i.script_sig.clear());
            assert_eq!(
                t2.insert_op_return(b"m"),
                Err(CodecError::Shielded),
                "{name}"
            );
        }
    }
    assert!(v4 >= 20 && v3 >= 6 && legacy >= 6, "{v4} {v3} {legacy}");
    assert!(with_js >= 6 && with_spends >= 20 && with_outputs >= 20);
}

#[test]
fn node_vault_spends_roundtrip() {
    let f = load("vault_spends.json");
    for c in f["spends"].as_array().unwrap() {
        let name = s(c, "name");
        let t = roundtrip(s(c, "hex"), s(c, "txid"), name);
        let n_in = c["nIn"].as_u64().unwrap() as usize;
        assert_eq!(
            hex::encode(&t.inputs[n_in].script_sig),
            s(c, "scriptSig"),
            "{name}"
        );
        assert!(t.inputs[n_in].has_signature());
    }
}

#[test]
fn truncations_never_panic() {
    let f = load("sighash_txs.json");
    for c in f["transactions"].as_array().unwrap().iter().take(8) {
        let b = hex::decode(s(c, "hex")).unwrap();
        for cut in 0..b.len() {
            assert!(
                Transaction::decode(&b[..cut]).is_err(),
                "prefix {cut} decoded"
            );
        }
    }
}
