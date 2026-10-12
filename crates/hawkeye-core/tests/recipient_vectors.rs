//! The `ycashRecipient` golden vectors (`tests/data/recipient_vectors.json`, plan §4.2 revision
//! 2; format in `tests/data/README.md`), derived independently in Python: for every valid case
//! the field bytes, the recipient script, `recipientHash = SHA256(script)` and the address on
//! each network must come out of `hawkeye-core` byte for byte, and in both directions; every
//! invalid field and script must be refused with the recorded reason.

use hawkeye_core::address::{Network, decode_address, decode_pq_address, encode_address};
use hawkeye_core::bytes::{from_hex, from_hex_array, sha256};
use hawkeye_core::recipient::{RecipientKind, YcashRecipient, parse_pqpkh};
use hawkeye_core::{Error, PqKeyId};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("data/recipient_vectors.json")).expect("parses")
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
}

fn hx(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().expect("hex string")).expect("hex")
}

fn network(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        other => panic!("network {other}"),
    }
}

fn recipient_of(case: &Value) -> YcashRecipient {
    let kind = case["kind"].as_u64().expect("kind") as u8;
    match RecipientKind::from_byte(kind).expect("a known kind") {
        RecipientKind::P2pkh => {
            YcashRecipient::p2pkh(from_hex_array("hash", case["hash"].as_str().unwrap()).unwrap())
        }
        RecipientKind::P2sh => {
            YcashRecipient::p2sh(from_hex_array("hash", case["hash"].as_str().unwrap()).unwrap())
        }
        RecipientKind::Pqpkh => YcashRecipient::pqpkh(
            case["scheme"].as_u64().expect("scheme") as u8,
            from_hex_array("hash", case["hash"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    }
}

#[test]
fn file_is_revision_2() {
    let v = vectors();
    assert_eq!(v["version"], 2);
    assert_eq!(list(&v, "valid").len(), 8);
    assert!(list(&v, "invalid").len() >= 20);
    assert!(list(&v, "scriptsInvalid").len() >= 12);
}

#[test]
fn valid_cases_encode_decode_and_hash() {
    let v = vectors();
    for case in list(&v, "valid") {
        let note = case["note"].as_str().unwrap();
        let r = recipient_of(case);
        let bytes = hx(&case["bytes"]);
        let script = hx(&case["script"]);
        assert_eq!(r.to_bytes(), bytes, "{note}: bytes");
        assert_eq!(
            YcashRecipient::from_bytes(&bytes).unwrap(),
            r,
            "{note}: decode"
        );
        assert_eq!(r.script(), script, "{note}: script");
        assert_eq!(
            YcashRecipient::from_script(&script).unwrap(),
            r,
            "{note}: parse"
        );
        assert_eq!(
            hex::encode(r.recipient_hash()),
            case["recipientHash"].as_str().unwrap(),
            "{note}: recipientHash"
        );
        assert_eq!(r.recipient_hash(), sha256(&script));
        assert_eq!(
            case["kindName"].as_str().unwrap().to_lowercase(),
            r.kind().name()
        );
        assert_eq!(bytes.len(), r.kind().field_len());
        for (net, addr) in case["addresses"].as_object().unwrap() {
            let addr = addr.as_str().unwrap();
            let net = network(net);
            assert_eq!(encode_address(&r, net), addr, "{note}: {net:?} address");
            assert_eq!(
                decode_address(addr, net).unwrap(),
                r,
                "{note}: {net:?} decode"
            );
            if r.kind() == RecipientKind::Pqpkh {
                assert_eq!(addr.len(), 53);
                let lead = match net {
                    Network::Mainnet => "sq",
                    Network::Testnet => "tq",
                    Network::Regtest => "rq",
                };
                assert!(addr.starts_with(lead), "{note}: {addr}");
                assert!(
                    decode_pq_address(addr, net).is_err(),
                    "not an owner address"
                );
            }
        }
    }
}

#[test]
fn invalid_fields_are_refused_with_the_recorded_reason() {
    let v = vectors();
    for case in list(&v, "invalid") {
        let note = case["note"].as_str().unwrap();
        let bytes = hx(&case["bytes"]);
        let reason = case["reason"].as_str().unwrap();
        assert_eq!(
            YcashRecipient::from_bytes(&bytes),
            Err(Error::Recipient(match reason {
                "wrong length" => "wrong length",
                "unknown version" => "unknown version",
                "unknown kind" => "unknown kind",
                "unknown scheme" => "unknown scheme",
                other => panic!("reason {other}"),
            })),
            "{note}"
        );
    }
}

#[test]
fn invalid_scripts_are_refused() {
    let v = vectors();
    for case in list(&v, "scriptsInvalid") {
        let note = case["note"].as_str().unwrap();
        let script = hx(&case["script"]);
        assert!(YcashRecipient::from_script(&script).is_err(), "{note}");
        assert_eq!(parse_pqpkh(&script), None, "{note}");
    }
}

/// The PQ owner address of a key (`yb…`/`yt…`/`yr…`) is never a burn recipient; the same key's
/// `sq…` form is.
#[test]
fn owner_addresses_are_not_recipients() {
    let v = vectors();
    let owner = PqKeyId::from_hex(&format!(
        "01{}",
        "c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258"
    ))
    .unwrap();
    for (net, addr) in v["ownerAddressesNotRecipients"]["addresses"]
        .as_object()
        .unwrap()
    {
        let net = network(net);
        let addr = addr.as_str().unwrap();
        assert_eq!(decode_pq_address(addr, net).unwrap(), owner);
        assert_eq!(
            decode_address(addr, net),
            Err(Error::Address(
                "a post-quantum owner address is not a recipient"
            ))
        );
        let as_recipient = YcashRecipient::Pqpkh(owner);
        assert_ne!(encode_address(&as_recipient, net), addr);
        assert_eq!(
            decode_address(&encode_address(&as_recipient, net), net).unwrap(),
            as_recipient
        );
    }
}
