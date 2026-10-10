//! The NEAR golden vectors (`tests/data/near_vectors.json`, NEAR plan §2; format in
//! `tests/data/README.md`).
//!
//! `vectors_match_file` rebuilds the file from fixed inputs with `hawkeye-core` and compares;
//! `HAWKEYE_WRITE_NEAR_VECTORS=1 cargo test -p hawkeye-core --test near_vectors` rewrites it.
//! The `independent_*` tests re-derive every entry of the file without `hawkeye-core`'s
//! encoders: the `borsh` crate's derive (what `near-sdk` uses), NEAR's `near-account-id`
//! validation, and raw `k256` verification and recovery.

use std::path::PathBuf;

use borsh::BorshSerialize;
use hawkeye_core::bridge::BridgeKind;
use hawkeye_core::bytes::{OutPoint, sha256};
use hawkeye_core::lock::{Destination, lock_id, near_destination_script, parse_near_destination};
use hawkeye_core::memo::{Deployment, HawkeyeMemo, MemoKind, parse_any_memo_script};
use hawkeye_core::near::{
    AccountId, AccountKind, BridgeMessage, BurnRecord, Domain, guardian_key_of, recover_guardian,
    sign_digest, validate_account_id,
};
use hawkeye_core::script::op_return_script;
use hawkeye_core::{EthAddress, SecretKey, YcashRecipient};
use serde_json::{Value, json};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/near_vectors.json")
}

fn keys() -> Vec<SecretKey> {
    (1u8..=3)
        .map(|i| SecretKey::from_bytes(&[i; 32]).unwrap())
        .collect()
}

fn acct(s: &str) -> AccountId {
    AccountId::parse(s).unwrap()
}

const IMPLICIT: &str = "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de";
const ETH_IMPLICIT: &str = "0xb794f5ea0ba39494ce839613fffba74279579268";

/// NEAR's own lists (`near-account-id` 3.0.0 `src/test_data.rs`), plus the implicit forms and
/// the ids the vectors use.
const VALID_IDS: &[&str] = &[
    "aa",
    "a-a",
    "a-aa",
    "100",
    "0o",
    "com",
    "near",
    "bowen",
    "b-o_w_e-n",
    "b.owen",
    "bro.wen",
    "a.ha",
    "a.b-a.ra",
    "system",
    "over.9000",
    "google.com",
    "illia.cheapaccounts.near",
    "0o0ooo00oo00o",
    "alex-skidanov",
    "10-4.8-2",
    "no_lols",
    "0123456789012345678901234567890123456789012345678901234567890123",
    "near.a",
    "alice.near",
    "wyec.near",
    "wyec-bridge.testnet",
    "wyec.test.near",
    "intents.near",
    IMPLICIT,
    ETH_IMPLICIT,
    "0s1234567890abcdef1234567890abcdef12345678",
];

const INVALID_IDS: &[&str] = &[
    "",
    "a",
    "A",
    "Abc",
    "-near",
    "near-",
    "-near-",
    "near.",
    ".near",
    "near@",
    "@near",
    "неар",
    "@@@@@",
    "0__0",
    "0_-_0",
    "..",
    "a..near",
    "nEar",
    "_bowen",
    "hello world",
    "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
    "01234567890123456789012345678901234567890123456789012345678901234",
    "some-complex-address@gmail.com",
    "sub.buy_d1gitz@atata@b0-rg.c_0_m",
    "0xB794F5EA0BA39494CE839613FFFBA74279579268",
    "98793CD91A3F870FB126F66285808C7E094AFCFC4EDA8A970F6648CDF0DBD6DE",
    "alice.near\n",
    "alice\u{0}near",
];

fn kind_name(k: AccountKind) -> &'static str {
    match k {
        AccountKind::Named => "named",
        AccountKind::NearImplicit => "near-implicit",
        AccountKind::EthImplicit => "eth-implicit",
    }
}

fn domains() -> Vec<Domain> {
    [
        ("mainnet", "wyec.near"),
        ("testnet", "wyec-bridge.testnet"),
        ("sandbox", "wyec.test.near"),
        ("localnet", "wyec.node0"),
    ]
    .into_iter()
    .map(|(n, c)| Domain::new(n, acct(c)).unwrap())
    .collect()
}

fn burns() -> Vec<BurnRecord> {
    vec![
        BurnRecord {
            nonce: 0,
            from: acct("alice.near"),
            amount: 250_000_000,
            ycash_recipient: YcashRecipient::p2pkh([0x77; 20]).to_bytes32(),
            block_height: 123_456_789,
            timestamp_ns: 1_760_000_000_000_000_000,
        },
        BurnRecord {
            nonce: 1,
            from: acct(IMPLICIT),
            amount: 1,
            ycash_recipient: YcashRecipient::p2sh([0x01; 20]).to_bytes32(),
            block_height: 1,
            timestamp_ns: 0,
        },
        BurnRecord {
            // an orphaned burn (recipient does not decode) still hashes
            nonce: u64::MAX,
            from: acct(ETH_IMPLICIT),
            amount: u128::from(u64::MAX) + 1,
            ycash_recipient: [0xff; 32],
            block_height: u64::MAX,
            timestamp_ns: u64::MAX,
        },
    ]
}

fn messages() -> Vec<(usize, BridgeMessage)> {
    let g: Vec<[u8; 64]> = keys().iter().map(guardian_key_of).collect();
    vec![
        (
            0,
            BridgeMessage::Mint {
                lock_id: lock_id(&OutPoint::new([0xaa; 32], 0)),
                amount: 250_000_000,
                receiver_id: acct("alice.near"),
            },
        ),
        (
            1,
            BridgeMessage::Mint {
                lock_id: lock_id(&OutPoint::new([0xbb; 32], 7)),
                amount: 1,
                receiver_id: acct(IMPLICIT),
            },
        ),
        (
            2,
            BridgeMessage::Mint {
                lock_id: [0x42; 32],
                amount: u128::from(u64::MAX) + 5,
                receiver_id: acct(ETH_IMPLICIT),
            },
        ),
        (
            0,
            BridgeMessage::Challenge {
                lock_id: lock_id(&OutPoint::new([0xaa; 32], 0)),
                proposal_id: 1,
            },
        ),
        (
            1,
            BridgeMessage::Challenge {
                lock_id: [0x42; 32],
                proposal_id: u64::MAX,
            },
        ),
        (
            0,
            BridgeMessage::SetGuardians {
                guardians: g.clone(),
                threshold: 2,
                admin_nonce: 0,
            },
        ),
        (
            3,
            BridgeMessage::SetGuardians {
                guardians: vec![g[0]],
                threshold: 1,
                admin_nonce: 7,
            },
        ),
        (
            0,
            BridgeMessage::SetPaused {
                paused: true,
                admin_nonce: 1,
            },
        ),
        (
            2,
            BridgeMessage::SetPaused {
                paused: false,
                admin_nonce: 2,
            },
        ),
        (
            0,
            BridgeMessage::SetMintLimit {
                mint_cap: 100_000_000_000,
                cap_window_sec: 86_400,
                admin_nonce: 3,
            },
        ),
        (
            1,
            BridgeMessage::SetMintLimit {
                mint_cap: u128::MAX,
                cap_window_sec: 0,
                admin_nonce: u64::MAX,
            },
        ),
    ]
}

fn message_json(m: &BridgeMessage) -> Value {
    match m {
        BridgeMessage::Mint {
            lock_id,
            amount,
            receiver_id,
        } => json!({"type": "Mint", "lockId": hex::encode(lock_id),
                    "amount": amount.to_string(), "receiverId": receiver_id.as_str()}),
        BridgeMessage::Challenge {
            lock_id,
            proposal_id,
        } => json!({"type": "Challenge", "lockId": hex::encode(lock_id),
                    "proposalId": proposal_id.to_string()}),
        BridgeMessage::SetGuardians {
            guardians,
            threshold,
            admin_nonce,
        } => json!({"type": "SetGuardians",
                    "guardians": guardians.iter().map(hex::encode).collect::<Vec<_>>(),
                    "threshold": threshold, "adminNonce": admin_nonce.to_string()}),
        BridgeMessage::SetPaused {
            paused,
            admin_nonce,
        } => json!({"type": "SetPaused", "paused": paused,
                    "adminNonce": admin_nonce.to_string()}),
        BridgeMessage::SetMintLimit {
            mint_cap,
            cap_window_sec,
            admin_nonce,
        } => json!({"type": "SetMintLimit", "mintCap": mint_cap.to_string(),
                    "capWindowSec": cap_window_sec.to_string(),
                    "adminNonce": admin_nonce.to_string()}),
    }
}

fn deployment_json(d: &Domain) -> Value {
    let dep = d.deployment();
    json!({
        "networkId": d.network_id,
        "contractId": d.contract_id.as_str(),
        "chainId": dep.chain_id.to_string(),
        "chainIdLe": hex::encode(dep.chain_id.to_le_bytes()),
        "bridge": hex::encode(dep.bridge.as_bytes()),
    })
}

fn memo_json(m: &HawkeyeMemo) -> Value {
    json!({
        "bridgeKind": m.bridge_kind.name(),
        "kind": m.kind as u8,
        "chainId": m.deployment.chain_id.to_string(),
        "bridge": hex::encode(m.deployment.bridge.as_bytes()),
        "ref": m.reference.to_string(),
        "data": hex::encode(m.data),
        "payload": hex::encode(m.encode()),
        "script": hex::encode(m.to_script()),
    })
}

fn build() -> Value {
    let keys = keys();
    let doms = domains();
    let burns = burns();

    let key_rows: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({"secret": hex::encode(k.to_bytes()), "compressed": hex::encode(k.public_key()),
                   "guardian": hex::encode(guardian_key_of(k))})
        })
        .collect();

    let valid: Vec<Value> = VALID_IDS
        .iter()
        .map(|s| json!({"id": s, "kind": kind_name(acct(s).kind())}))
        .collect();
    let invalid: Vec<Value> = INVALID_IDS
        .iter()
        .map(|s| {
            let hawkeye_core::Error::Near(reason) = validate_account_id(s).unwrap_err() else {
                unreachable!()
            };
            json!({"id": s, "reason": reason})
        })
        .collect();

    let dest_ids = [
        "alice.near",
        "wyec-bridge.testnet",
        IMPLICIT,
        ETH_IMPLICIT,
        "aa",
        &"z".repeat(64),
    ];
    let destinations: Vec<Value> = dest_ids
        .iter()
        .map(|s| json!({"accountId": s, "script": hex::encode(near_destination_script(&acct(s)))}))
        .collect();
    let mut nc = vec![0x6a, 0x4c, 13];
    nc.extend_from_slice(b"NR1alice.near");
    let mut two = near_destination_script(&acct("alice.near"));
    two.extend_from_slice(&[0x01, 0x00]);
    let bad_scripts: Vec<Vec<u8>> = vec![
        op_return_script(b"NR2alice.near"),
        op_return_script(b"nr1alice.near"),
        op_return_script(b"NR1"),
        op_return_script(b"NR1a"),
        op_return_script(b"NR1Alice.near"),
        op_return_script(b"NR1alice..near"),
        op_return_script(&[&b"NR1"[..], &[b'a'; 65]].concat()),
        op_return_script(&EthAddress([0x11; 20]).to_word()),
        nc,
        two,
        near_destination_script(&acct("alice.near"))[1..].to_vec(),
    ];
    let destinations_invalid: Vec<Value> = bad_scripts
        .iter()
        .map(|s| {
            let hawkeye_core::Error::Destination(reason) = parse_near_destination(s).unwrap_err()
            else {
                unreachable!()
            };
            json!({"script": hex::encode(s), "reason": reason})
        })
        .collect();

    let eth_dep = Deployment {
        chain_id: 11_155_111,
        bridge: EthAddress([0xbb; 20]),
    };
    let memos = [
        HawkeyeMemo::burn_release_for(
            BridgeKind::Near,
            doms[0].deployment(),
            burns[0].nonce,
            burns[0].hash(),
        ),
        HawkeyeMemo::burn_release_for(
            BridgeKind::Near,
            doms[2].deployment(),
            burns[2].nonce,
            burns[2].hash(),
        ),
        HawkeyeMemo {
            bridge_kind: BridgeKind::Near,
            kind: MemoKind::Roll,
            deployment: doms[1].deployment(),
            reference: 3_000_000,
            data: sha256(b"new V scriptPubKey"),
        },
        HawkeyeMemo::burn_release(eth_dep, 258, [0xcc; 32]),
        HawkeyeMemo {
            bridge_kind: BridgeKind::Ethereum,
            kind: MemoKind::Roll,
            deployment: eth_dep,
            reference: 3_000_000,
            data: sha256(b"new V scriptPubKey"),
        },
    ];

    let msgs: Vec<Value> = messages()
        .iter()
        .map(|(d, m)| {
            let dom = &doms[*d];
            let digest = dom.digest(m);
            let sigs: Vec<Value> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let sig = sign_digest(k, &digest).unwrap();
                    json!({"key": i, "signature": hex::encode(sig),
                           "guardian": hex::encode(recover_guardian(&digest, &sig).unwrap())})
                })
                .collect();
            json!({
                "domain": {"networkId": dom.network_id, "contractId": dom.contract_id.as_str()},
                "message": message_json(m),
                "tag": m.tag(),
                "borsh": hex::encode(m.borsh()),
                "preimage": hex::encode(dom.preimage(m)),
                "digest": hex::encode(digest),
                "signatures": sigs,
            })
        })
        .collect();

    let burn_rows: Vec<Value> = burns
        .iter()
        .map(|b| {
            json!({
                "record": {"nonce": b.nonce.to_string(), "from": b.from.as_str(),
                           "amount": b.amount.to_string(),
                           "ycashRecipient": hex::encode(b.ycash_recipient),
                           "blockHeight": b.block_height.to_string(),
                           "timestampNs": b.timestamp_ns.to_string()},
                "borsh": hex::encode(b.borsh()),
                "sha256": hex::encode(b.hash()),
            })
        })
        .collect();

    json!({
        "comment": "Hawkeye NEAR golden vectors (docs/hawkeye-near-plan.md §2). Generated by crates/hawkeye-core/tests/near_vectors.rs; format in tests/data/README.md. Hex is lowercase without 0x; u64/u128 are decimal strings.",
        "version": 1,
        "digestDomain": "HawkeyeNear-v1",
        "keys": key_rows,
        "accountIds": {"valid": valid, "invalid": invalid},
        "destinations": destinations,
        "destinationsInvalid": destinations_invalid,
        "deployments": doms.iter().map(deployment_json).collect::<Vec<_>>(),
        "memos": memos.iter().map(memo_json).collect::<Vec<_>>(),
        "messages": msgs,
        "burns": burn_rows,
    })
}

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(path()).expect("near_vectors.json")).unwrap()
}

#[test]
fn vectors_match_file() {
    let built = build();
    if std::env::var_os("HAWKEYE_WRITE_NEAR_VECTORS").is_some() {
        let mut s = serde_json::to_string_pretty(&built).unwrap();
        s.push('\n');
        std::fs::write(path(), s).unwrap();
    }
    assert_eq!(
        load(),
        built,
        "near_vectors.json is stale: HAWKEYE_WRITE_NEAR_VECTORS=1 rewrites it (an encoding \
         change changes the plan first)"
    );
}

// ---------------------------------------------------------------------------------------------
// Independent re-derivation from the file

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).unwrap()
}
fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}
fn dec<T: std::str::FromStr>(v: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    v.as_str().expect("decimal string").parse().unwrap()
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}

/// The contract's message type, as `near-sdk` serialises it.
#[derive(BorshSerialize)]
enum RefMessage {
    Mint {
        lock_id: [u8; 32],
        amount: u128,
        receiver_id: String,
    },
    Challenge {
        lock_id: [u8; 32],
        proposal_id: u64,
    },
    SetGuardians {
        guardians: Vec<[u8; 64]>,
        threshold: u8,
        admin_nonce: u64,
    },
    SetPaused {
        paused: bool,
        admin_nonce: u64,
    },
    SetMintLimit {
        mint_cap: u128,
        cap_window_sec: u64,
        admin_nonce: u64,
    },
}

#[derive(BorshSerialize)]
struct RefBurnRecord {
    nonce: u64,
    from: String,
    amount: u128,
    ycash_recipient: [u8; 32],
    block_height: u64,
    timestamp_ns: u64,
}

fn ref_message(m: &Value) -> RefMessage {
    match m["type"].as_str().unwrap() {
        "Mint" => RefMessage::Mint {
            lock_id: h32(&m["lockId"]),
            amount: dec(&m["amount"]),
            receiver_id: s(&m["receiverId"]),
        },
        "Challenge" => RefMessage::Challenge {
            lock_id: h32(&m["lockId"]),
            proposal_id: dec(&m["proposalId"]),
        },
        "SetGuardians" => RefMessage::SetGuardians {
            guardians: arr(&m["guardians"])
                .iter()
                .map(|g| h(g).try_into().unwrap())
                .collect(),
            threshold: u8::try_from(m["threshold"].as_u64().unwrap()).unwrap(),
            admin_nonce: dec(&m["adminNonce"]),
        },
        "SetPaused" => RefMessage::SetPaused {
            paused: m["paused"].as_bool().unwrap(),
            admin_nonce: dec(&m["adminNonce"]),
        },
        "SetMintLimit" => RefMessage::SetMintLimit {
            mint_cap: dec(&m["mintCap"]),
            cap_window_sec: dec(&m["capWindowSec"]),
            admin_nonce: dec(&m["adminNonce"]),
        },
        t => panic!("unknown message type {t}"),
    }
}

#[test]
fn independent_messages_digests_and_signatures() {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    use sha2::Digest;

    let v = load();
    let keys = arr(&v["keys"]);
    let msgs = arr(&v["messages"]);
    assert_eq!(msgs.len(), 11);
    let mut tags = std::collections::BTreeSet::new();
    for case in msgs {
        let m = ref_message(&case["message"]);
        let body = borsh::to_vec(&m).unwrap();
        assert_eq!(body, h(&case["borsh"]));
        assert_eq!(u64::from(body[0]), case["tag"].as_u64().unwrap());
        tags.insert(body[0]);
        let network_id = s(&case["domain"]["networkId"]);
        let contract_id = s(&case["domain"]["contractId"]);
        let mut pre = b"HawkeyeNear-v1".to_vec();
        pre.extend(borsh::to_vec(&network_id).unwrap());
        pre.extend(borsh::to_vec(&contract_id).unwrap());
        pre.extend(&body);
        assert_eq!(pre, h(&case["preimage"]));
        let digest: [u8; 32] = sha2::Sha256::digest(&pre).into();
        assert_eq!(digest.to_vec(), h(&case["digest"]));

        let sigs = arr(&case["signatures"]);
        assert_eq!(sigs.len(), keys.len());
        for sig in sigs {
            let k = &keys[usize::try_from(sig["key"].as_u64().unwrap()).unwrap()];
            assert_eq!(sig["guardian"], k["guardian"]);
            let raw = h(&sig["signature"]);
            assert_eq!(raw.len(), 65);
            let rs = Signature::from_slice(&raw[..64]).unwrap();
            // low S, v ∈ {0, 1}
            assert!(rs.normalize_s().is_none());
            assert!(raw[64] <= 1);
            let mut full = vec![4u8];
            full.extend(h(&sig["guardian"]));
            let vk = VerifyingKey::from_sec1_bytes(&full).unwrap();
            vk.verify_prehash(&digest, &rs).unwrap();
            let rec = VerifyingKey::recover_from_prehash(
                &digest,
                &rs,
                RecoveryId::from_byte(raw[64]).unwrap(),
            )
            .unwrap();
            assert_eq!(rec, vk);
            // the compressed member key is the same key
            assert_eq!(
                VerifyingKey::from_sec1_bytes(&h(&k["compressed"])).unwrap(),
                vk
            );
            // and hawkeye-core recovers it
            assert_eq!(
                recover_guardian(&digest, &raw).unwrap().to_vec(),
                h(&sig["guardian"])
            );
        }
    }
    assert_eq!(tags.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);
}

#[test]
fn independent_burns() {
    use sha2::Digest;
    let v = load();
    for case in arr(&v["burns"]) {
        let r = &case["record"];
        let rec = RefBurnRecord {
            nonce: dec(&r["nonce"]),
            from: s(&r["from"]),
            amount: dec(&r["amount"]),
            ycash_recipient: h32(&r["ycashRecipient"]),
            block_height: dec(&r["blockHeight"]),
            timestamp_ns: dec(&r["timestampNs"]),
        };
        let b = borsh::to_vec(&rec).unwrap();
        assert_eq!(b, h(&case["borsh"]));
        assert_eq!(sha2::Sha256::digest(&b).to_vec(), h(&case["sha256"]));
    }
}

#[test]
fn independent_account_ids() {
    use near_account_id::{AccountId as NearId, AccountType};
    let v = load();
    let valid = arr(&v["accountIds"]["valid"]);
    let invalid = arr(&v["accountIds"]["invalid"]);
    assert!(valid.len() >= 24 && invalid.len() >= 24);
    for c in valid {
        let id = c["id"].as_str().unwrap();
        let theirs: NearId = id.parse().unwrap_or_else(|e| panic!("{id}: {e}"));
        assert!(AccountId::parse(id).is_ok(), "{id}");
        let want = match theirs.get_account_type() {
            AccountType::NearImplicitAccount => "near-implicit",
            AccountType::EthImplicitAccount => "eth-implicit",
            _ => "named",
        };
        assert_eq!(c["kind"], want, "{id}");
    }
    for c in invalid {
        let id = c["id"].as_str().unwrap();
        assert!(id.parse::<NearId>().is_err(), "{id:?}");
        assert!(AccountId::parse(id).is_err(), "{id:?}");
    }
    // every id the other sections use is valid by NEAR's rules
    for c in arr(&v["destinations"]) {
        assert!(c["accountId"].as_str().unwrap().parse::<NearId>().is_ok());
    }
    for c in arr(&v["deployments"]) {
        assert!(c["contractId"].as_str().unwrap().parse::<NearId>().is_ok());
    }
}

#[test]
fn independent_destinations_deployments_memos() {
    use sha2::Digest;
    let v = load();
    for c in arr(&v["destinations"]) {
        let id = c["accountId"].as_str().unwrap();
        let script = h(&c["script"]);
        let mut want = vec![0x6a, u8::try_from(3 + id.len()).unwrap()];
        want.extend_from_slice(b"NR1");
        want.extend_from_slice(id.as_bytes());
        assert_eq!(script, want);
        assert!(script.len() <= 69);
        assert_eq!(
            Destination::parse(BridgeKind::Near, &script).unwrap(),
            Destination::Near(acct(id))
        );
    }
    for c in arr(&v["destinationsInvalid"]) {
        assert!(parse_near_destination(&h(&c["script"])).is_err());
    }
    let mut deployments = Vec::new();
    for c in arr(&v["deployments"]) {
        let pre = format!("near:{}", s(&c["networkId"]));
        let chain: [u8; 32] = sha2::Sha256::digest(pre.as_bytes()).into();
        assert_eq!(h(&c["chainIdLe"]), chain[..8]);
        assert_eq!(
            dec::<u64>(&c["chainId"]),
            u64::from_le_bytes(chain[..8].try_into().unwrap())
        );
        let bridge: [u8; 32] = sha2::Sha256::digest(s(&c["contractId"]).as_bytes()).into();
        assert_eq!(h(&c["bridge"]), bridge[..20]);
        deployments.push((dec::<u64>(&c["chainId"]), h(&c["bridge"])));
    }
    let mut kinds = std::collections::BTreeSet::new();
    for c in arr(&v["memos"]) {
        let payload = h(&c["payload"]);
        assert_eq!(payload.len(), 73);
        let magic: &[u8] = if c["bridgeKind"] == "near" {
            b"HKN1"
        } else {
            b"HKB1"
        };
        let mut want = magic.to_vec();
        want.push(u8::try_from(c["kind"].as_u64().unwrap()).unwrap());
        want.extend(dec::<u64>(&c["chainId"]).to_le_bytes());
        want.extend(h(&c["bridge"]));
        want.extend(dec::<u64>(&c["ref"]).to_le_bytes());
        want.extend(h(&c["data"]));
        assert_eq!(payload, want);
        let script = h(&c["script"]);
        assert_eq!(&script[..2], &[0x6a, 73]);
        assert_eq!(script[2..], payload[..]);
        let m = parse_any_memo_script(&script).unwrap().unwrap();
        assert_eq!(m.bridge_kind.name(), c["bridgeKind"].as_str().unwrap());
        if c["bridgeKind"] == "near" {
            assert!(deployments.contains(&(dec::<u64>(&c["chainId"]), h(&c["bridge"]))));
        }
        kinds.insert((s(&c["bridgeKind"]), c["kind"].as_u64().unwrap()));
    }
    assert_eq!(kinds.len(), 4);
    // the NEAR burn-release memos carry the burn record hash of the burns section
    let hashes: Vec<Value> = arr(&v["burns"])
        .iter()
        .map(|b| b["sha256"].clone())
        .collect();
    for c in arr(&v["memos"]) {
        if c["bridgeKind"] == "near" && c["kind"] == 1 {
            assert!(hashes.contains(&c["data"]));
        }
    }
}
