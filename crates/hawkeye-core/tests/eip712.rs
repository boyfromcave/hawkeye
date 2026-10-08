//! EIP-712 digests against independently computed values.
//!
//! The expected signatures were produced by Foundry's `cast` 1.7.1, which hashes the typed data
//! itself (`cast wallet sign --data --from-file <typed.json>`); both sides use RFC 6979, so a
//! byte-equal signature from [`sign_digest`] over our digest proves the digest equal. The `Mint`
//! and `Challenge` digests are also pinned literally (`cast abi-encode` + `cast keccak`). The
//! Foundry-generated `eth/vectors/eip712.json` (every case accepted by the pinned WyecBridge) is
//! replayed by [`eth_vectors`]; optional older-format vector files by [`foundry_vectors`].

use hawkeye_core::bytes::{from_hex, from_hex_array};
use hawkeye_core::eip712::Domain;
use hawkeye_core::eth::{EthAddress, recover_address, sign_digest, sort_signatures};
use hawkeye_core::keys::SecretKey;
use serde_json::Value;

/// Foundry / anvil account 0.
const KEY0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Accounts 1 and 2.
const KEY1: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const KEY2: &str = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const BRIDGE: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ADDR1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ADDR2: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

fn addr(s: &str) -> EthAddress {
    EthAddress::parse(s).unwrap()
}

fn sig(s: &str) -> [u8; 65] {
    from_hex_array("sig", s).unwrap()
}

fn key(s: &str) -> SecretKey {
    SecretKey::from_hex(s).unwrap()
}

#[test]
fn mint_digest_and_signature() {
    let d = Domain::new(31337, addr(BRIDGE));
    assert_eq!(
        hex::encode(d.separator()),
        "64713a5bf5a2b649e4e50463067e359be49aa82278cea08b18b7da72c1fd6fd3"
    );
    let lock_id: [u8; 32] = from_hex_array(
        "lockId",
        "3c8f1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    )
    .unwrap();
    assert_eq!(
        hex::encode(hawkeye_core::eip712::mint_struct_hash(
            &lock_id,
            250_000_000,
            &addr(ADDR1)
        )),
        "856ced319372d8a698562e02bea699dcc84c0db7ff1265165b5a009246dd0004"
    );
    let digest = d.mint_digest(&lock_id, 250_000_000, &addr(ADDR1));
    assert_eq!(
        hex::encode(digest),
        "40202ec4d398e71e2856642b8f22c9db4adb22edea81d882ce486f9a406b0a16"
    );
    let expected = [
        (
            KEY0,
            ADDR0,
            "aaba80d099748fc3fc7dec27a99b46d8f4d759c1ac686920eea15a4b9efb2ad634abcdc56c0413c41373e3e5189ee90cc9394e7cbaaad440f9b6934d1d42a9691c",
        ),
        (
            KEY1,
            ADDR1,
            "4e3319759fa19e097347605e4af0f9b5cdd039d301ea531bfdc93b9e612d59f95fd4a37f92c4cb704a04f3669ceebb9be23442cbc310ec8578ec82917d4e2b6f1c",
        ),
        (
            KEY2,
            ADDR2,
            "5601c98415f425a466b87518fd72e17d7da6118d0e7d04d9dd6bb3da8bbd8eee691c6398c2f6ce1194312bdb6c25fd41cc1200c2ac590bca20f2fac9a0f04aa21b",
        ),
    ];
    let mut sigs = Vec::new();
    for (k, a, s) in expected {
        let k = key(k);
        assert_eq!(k.eth_address(), addr(a));
        assert_eq!(sign_digest(&k, &digest).unwrap(), sig(s));
        assert_eq!(recover_address(&digest, &sig(s)).unwrap(), addr(a));
        sigs.push(sig(s));
    }
    // ascending signer order: ADDR2 (0x3C..) < ADDR1 (0x70..) < ADDR0 (0xf3..)
    let sorted = sort_signatures(&digest, &sigs).unwrap();
    assert_eq!(sorted, vec![sigs[2], sigs[1], sigs[0]]);
    // the digest binds every field
    assert_ne!(d.mint_digest(&lock_id, 250_000_001, &addr(ADDR1)), digest);
    assert_ne!(d.mint_digest(&lock_id, 250_000_000, &addr(ADDR2)), digest);
    assert_ne!(
        Domain::new(1, addr(BRIDGE)).mint_digest(&lock_id, 250_000_000, &addr(ADDR1)),
        digest
    );
}

#[test]
fn admin_digests() {
    let k = key(KEY0);
    let guardians = Domain::new(11_155_111, addr(BRIDGE)).set_guardians_digest(
        &[addr(ADDR1), addr(ADDR0), addr(ADDR2)],
        2,
        7,
    );
    assert_eq!(
        sign_digest(&k, &guardians).unwrap(),
        sig(
            "c869098c2fea9eff639672dc127eb3308f4678e86ee91bfe37f1b8384621afbc7fbaf12e69aa1eb73d65b840047dd743e7243fd3a872577af9a240a58ab4aa7a1b"
        )
    );
    let paused = Domain::new(1, addr(BRIDGE)).set_paused_digest(true, 3);
    assert_eq!(
        sign_digest(&k, &paused).unwrap(),
        sig(
            "2a28e2de272a05e99ab7ad497da67ef99cd2fdb746de83ddd89114cb2ebd9c2c52f4baf5fa53b5c9a7f1164b4214cdc9cc0be14eb5e0586d4a89f70a9d91fef11c"
        )
    );
    let bridge = Domain::new(31337, addr(BRIDGE)).set_bridge_digest(&addr(ADDR2), 0);
    assert_eq!(
        sign_digest(&k, &bridge).unwrap(),
        sig(
            "de1b40003afaa7c5339c3eee2f79cda884b38e3ac67bb4d6f291fedef3a6609b5fac821b666b7369147534c35cedcaf149d4f9cdaa87e43df7c6b3c4f9652b221c"
        )
    );
}

/// The optimistic path's veto: `Challenge(bytes32 lockId,uint256 proposalId)`. Struct hash and
/// digest from `cast abi-encode` + `cast keccak`, signatures from `cast wallet sign --data`.
#[test]
fn challenge_digest_and_signature() {
    let d = Domain::new(31337, addr(BRIDGE));
    let lock_id: [u8; 32] = from_hex_array(
        "lockId",
        "3c8f1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    )
    .unwrap();
    assert_eq!(
        hex::encode(hawkeye_core::eip712::challenge_struct_hash(&lock_id, 7)),
        "0105653a7affd5bd49a237508d47d6648886e45e065adac8ef29c9dd846d9b56"
    );
    let digest = d.challenge_digest(&lock_id, 7);
    assert_eq!(
        hex::encode(digest),
        "c7ca7f53da988c8347eaea82f190c91c512c6176514ff22e9d385db89136b704"
    );
    for (k, a, s) in [
        (
            KEY0,
            ADDR0,
            "105766cd30f99eeb48f70fa1668162e2345c2ad80444bafb84c00a31fd2ba1a5155c57b877b7586d71144f7c0e00bdca325020580292fe70bc0fea6f67e3b3ea1b",
        ),
        (
            KEY1,
            ADDR1,
            "6d51ffce71dfb354444884e31fc9310342a3c73ab490fd7bb3cd1cd1d7c13fad1834919a1cf8eeb27f168c29612cb40cf40f99f6d19d0aae6446f7fd1cc818d91c",
        ),
    ] {
        assert_eq!(sign_digest(&key(k), &digest).unwrap(), sig(s));
        assert_eq!(recover_address(&digest, &sig(s)).unwrap(), addr(a));
    }
    // the id is bound: a challenge of proposal 7 is not one of proposal 8, nor a Mint digest
    assert_ne!(d.challenge_digest(&lock_id, 8), digest);
    assert_ne!(d.mint_digest(&lock_id, 7, &EthAddress::ZERO), digest);
    // SetMintLimit (mainnet domain): cast wallet sign --data
    assert_eq!(
        sign_digest(
            &key(KEY0),
            &Domain::new(1, addr(BRIDGE)).set_mint_limit_digest(100_000_000_000, 86_400, 4)
        )
        .unwrap(),
        sig(
            "09e7058e7c03d8ff53e986352fffa05a793e990f907b9452a51493d847fde9047f53182844d28d008dc825bab1c48ab68f3504e981ef10be23323ede2bee58d31b"
        )
    );
}

fn u128_of(v: &Value) -> u128 {
    match v {
        Value::Number(n) => u128::from(n.as_u64().expect("u64")),
        Value::String(s) => s.parse().expect("decimal string"),
        other => panic!("not an integer: {other}"),
    }
}

/// `eth/vectors/eip712.json`: generated by Foundry (`eth/test/Vectors.t.sol`) against wyec at the
/// pinned commit, every signing case submitted to and accepted by the real WyecBridge. Every
/// digest and every (deterministic, RFC 6979) signature must be reproduced byte for byte.
#[test]
fn eth_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../eth/vectors/eip712.json");
    let root: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("eth/vectors/eip712.json"))
            .unwrap();
    let cases = root["cases"].as_array().expect("cases");
    let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
    for c in cases {
        let kind = c["kind"].as_str().unwrap();
        *kinds.entry(kind).or_default() += 1;
        let d = Domain::new(
            c["chainId"].as_u64().unwrap(),
            addr(c["verifyingContract"].as_str().unwrap()),
        );
        let h32 =
            |k: &'static str| -> [u8; 32] { from_hex_array(k, c[k].as_str().unwrap()).unwrap() };
        let digest = match kind {
            "Domain" => {
                assert_eq!(d.separator(), h32("digest"), "{c}");
                continue;
            }
            "Mint" => d.mint_digest(
                &h32("lockId"),
                u64_of(&c["amount"]),
                &addr(c["to"].as_str().unwrap()),
            ),
            "Challenge" => d.challenge_digest(&h32("lockId"), u128_of(&c["proposalId"])),
            "SetGuardians" => {
                let g: Vec<EthAddress> = c["guardians"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| addr(a.as_str().unwrap()))
                    .collect();
                d.set_guardians_digest(
                    &g,
                    u8::try_from(c["threshold"].as_u64().unwrap()).unwrap(),
                    u64_of(&c["adminNonce"]),
                )
            }
            "SetPaused" => {
                d.set_paused_digest(c["paused"].as_bool().unwrap(), u64_of(&c["adminNonce"]))
            }
            "SetMintLimit" => d.set_mint_limit_digest(
                u128_of(&c["mintCap"]),
                u64_of(&c["capWindow"]),
                u64_of(&c["adminNonce"]),
            ),
            "SetBridge" => d.set_bridge_digest(
                &addr(c["newBridge"].as_str().unwrap()),
                u64_of(&c["adminNonce"]),
            ),
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(digest, h32("digest"), "{c}");
        let k = SecretKey::from_bytes(&h32("privateKey")).unwrap();
        assert_eq!(k.eth_address(), addr(c["signer"].as_str().unwrap()), "{c}");
        assert_eq!(
            hex::encode(k.public_key()),
            c["publicKey"].as_str().unwrap().trim_start_matches("0x"),
            "{c}"
        );
        let want = sig(c["signature"].as_str().unwrap().trim_start_matches("0x"));
        assert_eq!(sign_digest(&k, &digest).unwrap(), want, "{c}");
        assert_eq!(recover_address(&digest, &want).unwrap(), k.eth_address());
    }
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        vec![
            ("Challenge", 6),
            ("Domain", 2),
            ("Mint", 18),
            ("SetBridge", 2),
            ("SetGuardians", 4),
            ("SetMintLimit", 4),
            ("SetPaused", 4),
        ]
    );
}

fn u64_of(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n.as_u64().expect("u64"),
        Value::String(s) => s.parse().expect("decimal string"),
        other => panic!("not an integer: {other}"),
    }
}

/// Foundry-generated `Mint` vectors (H3), replayed when the file exists.
#[test]
fn foundry_vectors() {
    let path = std::env::var("HAWKEYE_EIP712_VECTORS").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/eip712_vectors.json"
        )
        .to_owned()
    });
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("no EIP-712 vector file at {path}; skipped");
        return;
    };
    let root: Value = serde_json::from_str(&text).expect("vector file parses");
    let cases = match &root {
        Value::Array(a) => a,
        Value::Object(o) => o
            .get("mint")
            .or_else(|| o.get("cases"))
            .and_then(Value::as_array)
            .expect("an array under \"mint\" or \"cases\""),
        _ => panic!("vector file is neither an array nor an object"),
    };
    assert!(!cases.is_empty(), "{path} has no cases");
    for (i, c) in cases.iter().enumerate() {
        let dom = &c["domain"];
        if let Some(n) = dom.get("name") {
            assert_eq!(n, "WyecBridge", "case {i}");
        }
        if let Some(v) = dom.get("version") {
            assert_eq!(v, "1", "case {i}");
        }
        let d = Domain::new(
            u64_of(&dom["chainId"]),
            addr(dom["verifyingContract"].as_str().unwrap()),
        );
        let lock_id = from_hex_array("lockId", c["lockId"].as_str().unwrap()).unwrap();
        let to = addr(c["to"].as_str().unwrap());
        let want = from_hex(c["digest"].as_str().unwrap()).unwrap();
        assert_eq!(
            d.mint_digest(&lock_id, u64_of(&c["amount"]), &to).to_vec(),
            want,
            "case {i}"
        );
    }
}
