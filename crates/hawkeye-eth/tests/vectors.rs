//! `eth/vectors/eip712.json` (Foundry-generated, every signing case accepted by the pinned
//! WyecBridge): this crate's digests and signatures must reproduce it byte for byte.

use std::str::FromStr;

use hawkeye_eth::eip712;
use hawkeye_eth::{Address, B256, Bytes, PrivateKeySigner, U256};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../eth/vectors/eip712.json");
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn s<'a>(c: &'a Value, k: &str) -> &'a str {
    c[k].as_str().unwrap_or_else(|| panic!("field {k} in {c}"))
}
fn addr(c: &Value, k: &str) -> Address {
    Address::from_str(s(c, k)).unwrap()
}
fn b256(c: &Value, k: &str) -> B256 {
    B256::from_str(s(c, k)).unwrap()
}
fn dec(c: &Value, k: &str) -> U256 {
    U256::from_str_radix(s(c, k), 10).unwrap()
}

#[test]
fn eip712_vectors() {
    let cases = vectors();
    assert_eq!(cases.len(), 40);
    let mut kinds = std::collections::BTreeMap::<String, usize>::new();
    for c in &cases {
        let kind = s(c, "kind");
        *kinds.entry(kind.to_string()).or_default() += 1;
        let chain_id = c["chainId"].as_u64().unwrap();
        let vc = addr(c, "verifyingContract");
        let digest = match kind {
            "Domain" => {
                assert_eq!(
                    eip712::domain_separator(chain_id, vc),
                    b256(c, "digest"),
                    "{c}"
                );
                continue;
            }
            "Mint" => eip712::mint_digest(
                chain_id,
                vc,
                b256(c, "lockId"),
                dec(c, "amount"),
                addr(c, "to"),
            ),
            "SetGuardians" => {
                let g: Vec<Address> = c["guardians"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| Address::from_str(a.as_str().unwrap()).unwrap())
                    .collect();
                let t = u8::try_from(c["threshold"].as_u64().unwrap()).unwrap();
                eip712::set_guardians_digest(chain_id, vc, &g, t, dec(c, "adminNonce"))
            }
            "Challenge" => {
                eip712::challenge_digest(chain_id, vc, b256(c, "lockId"), dec(c, "proposalId"))
            }
            "SetMintLimit" => eip712::set_mint_limit_digest(
                chain_id,
                vc,
                dec(c, "mintCap"),
                dec(c, "capWindow"),
                dec(c, "adminNonce"),
            ),
            "SetPaused" => eip712::set_paused_digest(
                chain_id,
                vc,
                c["paused"].as_bool().unwrap(),
                dec(c, "adminNonce"),
            ),
            "SetBridge" => {
                eip712::set_bridge_digest(chain_id, vc, addr(c, "newBridge"), dec(c, "adminNonce"))
            }
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(digest, b256(c, "digest"), "{c}");

        let key = PrivateKeySigner::from_bytes(&b256(c, "privateKey")).unwrap();
        assert_eq!(key.address(), addr(c, "signer"), "{c}");
        let compressed = key.credential().verifying_key().to_encoded_point(true);
        assert_eq!(
            Bytes::copy_from_slice(compressed.as_bytes()),
            Bytes::from_str(s(c, "publicKey")).unwrap(),
            "{c}"
        );
        let sig = eip712::sign_digest(&key, digest).unwrap();
        assert_eq!(
            sig,
            Bytes::from_str(s(c, "signature")).unwrap(),
            "deterministic signature {c}"
        );
        assert_eq!(eip712::recover(digest, &sig).unwrap(), key.address());
    }
    let want: Vec<(String, usize)> = [
        ("Challenge", 6),
        ("Domain", 2),
        ("Mint", 18),
        ("SetBridge", 2),
        ("SetGuardians", 4),
        ("SetMintLimit", 4),
        ("SetPaused", 4),
    ]
    .into_iter()
    .map(|(k, n)| (k.to_string(), n))
    .collect();
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), want);
}
