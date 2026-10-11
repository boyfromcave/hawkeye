//! Golden vectors for `vectors/messages.json` (plan §2.3, §2.4), built from fixed secrets so the
//! file is reproducible byte for byte, and the cross-check against hawkeye-core's own vectors.

use super::{Guardian, guardian, sign_raw};
use crate::encoding::{BridgeMessage, BurnRecord, burn_record_bytes, digest_preimage};
use near_sdk::borsh;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn lock_id(n: u8) -> [u8; 32] {
    sha(&[b"wyec-near vector lock ".as_slice(), &[n]].concat())
}

/// A §4.2 revision-2 P2PKH (kind 0) or P2SH (kind 1) recipient: 22 bytes.
fn hash160_recipient(kind: u8, hash160: [u8; 20]) -> Vec<u8> {
    [&[0x02, kind][..], &hash160].concat()
}

/// A §4.2 revision-2 PQPKH recipient (kind 2) of `scheme`: 35 bytes.
fn pqpkh_recipient(scheme: u8, key_hash: [u8; 32]) -> Vec<u8> {
    [&[0x02, 0x02, scheme][..], &key_hash].concat()
}

fn msg_json(m: &BridgeMessage) -> Value {
    match m {
        BridgeMessage::Mint {
            lock_id,
            amount,
            receiver_id,
        } => json!({
            "Mint": {"lock_id": hex::encode(lock_id), "amount": amount.to_string(), "receiver_id": receiver_id}
        }),
        BridgeMessage::Challenge {
            lock_id,
            proposal_id,
        } => json!({
            "Challenge": {"lock_id": hex::encode(lock_id), "proposal_id": proposal_id}
        }),
        BridgeMessage::SetGuardians {
            guardians,
            threshold,
            admin_nonce,
        } => json!({
            "SetGuardians": {
                "guardians": guardians.iter().map(hex::encode).collect::<Vec<_>>(),
                "threshold": threshold, "admin_nonce": admin_nonce,
            }
        }),
        BridgeMessage::SetPaused {
            paused,
            admin_nonce,
        } => json!({
            "SetPaused": {"paused": paused, "admin_nonce": admin_nonce}
        }),
        BridgeMessage::SetMintLimit {
            mint_cap,
            cap_window_sec,
            admin_nonce,
        } => json!({
            "SetMintLimit": {
                "mint_cap": mint_cap.to_string(), "cap_window_sec": cap_window_sec,
                "admin_nonce": admin_nonce,
            }
        }),
    }
}

/// The vector cases: (name, network_id, contract_id, message).
pub(crate) fn cases(
    gs: &[Guardian],
) -> Vec<(&'static str, &'static str, &'static str, BridgeMessage)> {
    vec![
        (
            "mint",
            "testnet",
            "wyec.testnet",
            BridgeMessage::Mint {
                lock_id: lock_id(1),
                amount: 123_456_789,
                receiver_id: "alice.testnet".into(),
            },
        ),
        (
            "mint_implicit_account_max_supply",
            "mainnet",
            "wyec.near",
            BridgeMessage::Mint {
                lock_id: lock_id(2),
                amount: 2_100_000_000_000_000,
                receiver_id: "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de"
                    .into(),
            },
        ),
        (
            "mint_evm_implicit_account",
            "sandbox",
            "wyec.test.near",
            BridgeMessage::Mint {
                lock_id: lock_id(3),
                amount: 1,
                receiver_id: "0x85f17cf997934a597031b2e18a9ab6ebd4b9f6a4".into(),
            },
        ),
        (
            "challenge",
            "testnet",
            "wyec.testnet",
            BridgeMessage::Challenge {
                lock_id: lock_id(1),
                proposal_id: 1,
            },
        ),
        (
            "challenge_large_id",
            "testnet",
            "wyec.testnet",
            BridgeMessage::Challenge {
                lock_id: lock_id(1),
                proposal_id: 0x0102_0304_0506_0708,
            },
        ),
        (
            "set_guardians",
            "testnet",
            "wyec.testnet",
            BridgeMessage::SetGuardians {
                guardians: gs.iter().map(|g| g.pk).collect(),
                threshold: 2,
                admin_nonce: 0,
            },
        ),
        (
            "set_paused",
            "testnet",
            "wyec.testnet",
            BridgeMessage::SetPaused {
                paused: true,
                admin_nonce: 1,
            },
        ),
        (
            "set_unpaused",
            "testnet",
            "wyec.testnet",
            BridgeMessage::SetPaused {
                paused: false,
                admin_nonce: 2,
            },
        ),
        (
            "set_mint_limit",
            "testnet",
            "wyec.testnet",
            BridgeMessage::SetMintLimit {
                mint_cap: 100_000_000_000,
                cap_window_sec: 86_400,
                admin_nonce: 3,
            },
        ),
    ]
}

/// BurnRecord v2 cases: a 22-byte P2PKH, a 22-byte P2SH, and 35-byte PQPKH recipients of scheme
/// 1 (SLH-DSA-SHA2-128s) and scheme 2 (FN-DSA-512). Every recipient passes
/// [`crate::validate_recipient`].
pub(crate) fn burn_cases() -> Vec<BurnRecord> {
    let cases = vec![
        BurnRecord {
            nonce: 0,
            from: "alice.testnet".into(),
            amount: 50_000_000,
            ycash_recipient: hash160_recipient(0x00, [0xab; 20]),
            block_height: 187_654_321,
            timestamp_ns: 1_760_000_000_123_456_789,
        },
        BurnRecord {
            nonce: 7,
            from: "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de".into(),
            amount: 2_100_000_000_000_000,
            ycash_recipient: hash160_recipient(0x01, [0x11; 20]),
            block_height: 1,
            timestamp_ns: 0,
        },
        BurnRecord {
            nonce: 8,
            from: "bob.testnet".into(),
            amount: 100_000_000,
            ycash_recipient: pqpkh_recipient(0x01, sha(b"wyec-near vector pq key 1")),
            block_height: 187_654_400,
            timestamp_ns: 1_760_000_100_000_000_000,
        },
        BurnRecord {
            nonce: 9,
            from: "0x85f17cf997934a597031b2e18a9ab6ebd4b9f6a4".into(),
            amount: 1,
            ycash_recipient: pqpkh_recipient(0x02, sha(b"wyec-near vector pq key 2")),
            block_height: 187_654_401,
            timestamp_ns: 1_760_000_101_000_000_000,
        },
    ];
    for c in &cases {
        crate::validate_recipient(&c.ycash_recipient).expect("a valid vector recipient");
    }
    cases
}

pub(crate) fn build() -> Value {
    let gs: Vec<Guardian> = (0..3).map(guardian).collect();
    let guardians: Vec<Value> = gs
        .iter()
        .enumerate()
        .map(|(i, g)| {
            json!({
                "index": i,
                "secret": hex::encode(g.sk.to_bytes()),
                "pubkey": hex::encode(g.pk),
            })
        })
        .collect();
    let messages: Vec<Value> = cases(&gs)
        .iter()
        .map(|(name, net, contract, msg)| {
            let pre = digest_preimage(net, contract, msg);
            let d = sha(&pre);
            json!({
                "name": name,
                "network_id": net,
                "contract_id": contract,
                "message": msg_json(msg),
                "borsh": hex::encode(borsh::to_vec(msg).unwrap()),
                "preimage": hex::encode(&pre),
                "digest": hex::encode(d),
                "signatures": gs.iter().enumerate().map(|(i, g)| json!({
                    "guardian": i,
                    "signature": hex::encode(sign_raw(g, &d)),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let burns: Vec<Value> = burn_cases()
        .iter()
        .map(|r| {
            let b = burn_record_bytes(r);
            json!({
                "record": {
                    "nonce": r.nonce, "from": r.from, "amount": r.amount.to_string(),
                    "ycash_recipient": hex::encode(&r.ycash_recipient),
                    "block_height": r.block_height, "timestamp_ns": r.timestamp_ns.to_string(),
                },
                "borsh": hex::encode(&b),
                "sha256": hex::encode(sha(&b)),
            })
        })
        .collect();
    json!({
        "description": "wyec-near golden vectors (docs/hawkeye-near-plan.md §2.3, §2.4). digest = SHA256(preimage), preimage = \"HawkeyeNear-v1\" || borsh(network_id) || borsh(contract_id) || borsh(message); signature = r || s || v (v in {0,1}, low-S, RFC 6979). Guardian secrets are SHA256(\"wyec-near test guardian \" || index). burn_records are BurnRecord v2 (ycash_recipient a borsh Vec<u8>: the main plan's §4.2 revision-2 recipient, 22 or 35 bytes); record_hash = SHA256(borsh). Written by `WYEC_NEAR_WRITE_VECTORS=1 cargo test vectors_file`.",
        "domain": "HawkeyeNear-v1",
        "guardians": guardians,
        "messages": messages,
        "burn_records": burns,
    })
}

/// hawkeye-core's NEAR vectors (NH1), if present in this checkout.
const HAWKEYE_CORE_VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crates/hawkeye-core/tests/data/near_vectors.json"
);

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    h(v).try_into().expect("length")
}

fn dec<T: std::str::FromStr>(v: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    v.as_str()
        .expect("decimal string")
        .parse()
        .expect("decimal")
}

/// Builds the message from hawkeye-core's JSON spelling, independently of its `borsh` field.
fn core_message(m: &Value) -> BridgeMessage {
    match m["type"].as_str().unwrap() {
        "Mint" => BridgeMessage::Mint {
            lock_id: arr(&m["lockId"]),
            amount: dec(&m["amount"]),
            receiver_id: m["receiverId"].as_str().unwrap().into(),
        },
        "Challenge" => BridgeMessage::Challenge {
            lock_id: arr(&m["lockId"]),
            proposal_id: dec(&m["proposalId"]),
        },
        "SetGuardians" => BridgeMessage::SetGuardians {
            guardians: m["guardians"].as_array().unwrap().iter().map(arr).collect(),
            threshold: m["threshold"].as_u64().unwrap().try_into().unwrap(),
            admin_nonce: dec(&m["adminNonce"]),
        },
        "SetPaused" => BridgeMessage::SetPaused {
            paused: m["paused"].as_bool().unwrap(),
            admin_nonce: dec(&m["adminNonce"]),
        },
        "SetMintLimit" => BridgeMessage::SetMintLimit {
            mint_cap: dec(&m["mintCap"]),
            cap_window_sec: dec(&m["capWindowSec"]),
            admin_nonce: dec(&m["adminNonce"]),
        },
        t => panic!("unknown message type {t}"),
    }
}

/// Checks hawkeye-core's NEAR vectors (NH1) against this contract: Borsh bytes, preimages, the
/// digest the contract computes in the mocked runtime (with `current_account_id` = the vector's
/// contract id), the guardian each signature recovers to through the host's `ecrecover`, and the
/// burn-record hashes. Returns the number of entries checked; 0 if the file is absent.
pub(crate) fn check_hawkeye_core() -> usize {
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    let Ok(text) = std::fs::read_to_string(HAWKEYE_CORE_VECTORS) else {
        eprintln!("skipped: {HAWKEYE_CORE_VECTORS} not present");
        return 0;
    };
    let v: Value = serde_json::from_str(&text).expect("near_vectors.json parses");
    assert_eq!(v["digestDomain"].as_str(), Some("HawkeyeNear-v1"));
    let mut checked = 0;

    // Keys: the guardian id is the 64-byte uncompressed key of the secret.
    let mut guardians = Vec::new();
    for k in v["keys"].as_array().unwrap() {
        let sk = k256::ecdsa::SigningKey::from_bytes(&arr::<32>(&k["secret"]).into()).unwrap();
        let pk = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
        assert_eq!(hex::encode(&pk), k["guardian"].as_str().unwrap());
        guardians.push(hex::encode(pk));
        checked += 1;
    }

    for (i, m) in v["messages"].as_array().unwrap().iter().enumerate() {
        let net = m["domain"]["networkId"].as_str().unwrap();
        let contract = m["domain"]["contractId"].as_str().unwrap();
        let msg = core_message(&m["message"]);
        let ctx = format!("messages[{i}] {}", m["message"]["type"]);
        assert_eq!(
            hex::encode(borsh::to_vec(&msg).unwrap()),
            m["borsh"].as_str().unwrap(),
            "{ctx} borsh"
        );
        assert_eq!(
            borsh::to_vec(&msg).unwrap()[0] as u64,
            m["tag"].as_u64().unwrap(),
            "{ctx} tag"
        );
        let pre = digest_preimage(net, contract, &msg);
        assert_eq!(
            hex::encode(&pre),
            m["preimage"].as_str().unwrap(),
            "{ctx} preimage"
        );

        testing_env!(
            VMContextBuilder::new()
                .current_account_id(contract.parse().unwrap())
                .build()
        );
        let c = Contract::new(
            net.into(),
            guardians.clone(),
            1,
            1,
            near_sdk::json_types::U128(0),
            0,
        );
        let d = c.digest(&msg);
        assert_eq!(
            hex::encode(d),
            m["digest"].as_str().unwrap(),
            "{ctx} digest"
        );
        for s in m["signatures"].as_array().unwrap() {
            let signer = crate::recover(&d, s["signature"].as_str().unwrap());
            assert_eq!(
                hex::encode(signer),
                s["guardian"].as_str().unwrap(),
                "{ctx} ecrecover"
            );
            let key = s["key"].as_u64().unwrap() as usize;
            assert_eq!(
                hex::encode(signer),
                guardians[key],
                "{ctx} signer is keys[{key}]"
            );
        }
        checked += 1;
    }

    for (i, b) in v["burns"].as_array().unwrap().iter().enumerate() {
        let r = &b["record"];
        let record = BurnRecord {
            nonce: dec(&r["nonce"]),
            from: r["from"].as_str().unwrap().into(),
            amount: dec(&r["amount"]),
            ycash_recipient: h(&r["ycashRecipient"]),
            block_height: dec(&r["blockHeight"]),
            timestamp_ns: dec(&r["timestampNs"]),
        };
        // hawkeye-core's burns are all recipients this contract would have accepted
        crate::validate_recipient(&record.ycash_recipient)
            .unwrap_or_else(|e| panic!("burns[{i}] recipient: {e}"));
        let bytes = burn_record_bytes(&record);
        assert_eq!(
            hex::encode(&bytes),
            b["borsh"].as_str().unwrap(),
            "burns[{i}] borsh"
        );
        assert_eq!(
            hex::encode(sha(&bytes)),
            b["sha256"].as_str().unwrap(),
            "burns[{i}] sha256"
        );
        // The contract's own view hash (host sha256) agrees.
        let view = crate::burn_view(&record);
        assert_eq!(
            view.record_hash,
            b["sha256"].as_str().unwrap(),
            "burns[{i}] record_hash"
        );
        checked += 1;
    }
    checked
}
