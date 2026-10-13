//! `eth/vectors/eip712.json` (Foundry-generated against the pinned WyecBridge): every
//! `expectAccepted` case is reproduced byte for byte by this crate's digests and signatures, and
//! every refused case (audit 05/T-4) is refused here too, for the reason the case names.

use std::str::FromStr;

use hawkeye_eth::eip712;
use hawkeye_eth::{Address, B256, Bytes, Error, PrivateKeySigner, U256};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../eth/vectors/eip712.json");
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn accepted(c: &Value) -> bool {
    c["expectAccepted"]
        .as_bool()
        .unwrap_or_else(|| panic!("expectAccepted in {c}"))
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
    let all = vectors();
    let cases: Vec<&Value> = all.iter().filter(|c| accepted(c)).collect();
    assert_eq!(cases.len(), 40);
    let mut kinds = std::collections::BTreeMap::<String, usize>::new();
    for c in cases {
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

fn bytes(c: &Value, k: &str) -> Bytes {
    Bytes::from_str(s(c, k)).unwrap()
}

/// The refused cases: Foundry proved the contract refuses each with the named error; this crate
/// must refuse the same bytes (or, for `not-ascending`, put them in the order the contract takes).
#[test]
fn eip712_negative_vectors() {
    let all = vectors();
    let negatives: Vec<&Value> = all.iter().filter(|c| !accepted(c)).collect();
    let mut seen = Vec::new();
    for c in negatives {
        let reject = s(c, "reject");
        seen.push(reject.to_string());
        assert_eq!(s(c, "kind"), "Mint", "{c}");
        let chain_id = c["chainId"].as_u64().unwrap();
        let vc = addr(c, "verifyingContract");
        // The digest the contract computes from the submitted fields.
        let digest = eip712::mint_digest(
            chain_id,
            vc,
            b256(c, "lockId"),
            dec(c, "amount"),
            addr(c, "to"),
        );
        assert_eq!(digest, b256(c, "digest"), "{c}");
        match reject {
            "wrong-chain-id" | "wrong-verifying-contract" | "wrong-struct" => {
                let signed = if reject == "wrong-struct" {
                    eip712::challenge_digest(
                        chain_id,
                        vc,
                        b256(c, "lockId"),
                        dec(c, "signedProposalId"),
                    )
                } else {
                    eip712::mint_digest(
                        c["signedChainId"].as_u64().unwrap(),
                        addr(c, "signedVerifyingContract"),
                        b256(c, "lockId"),
                        dec(c, "amount"),
                        addr(c, "to"),
                    )
                };
                assert_eq!(signed, b256(c, "signedDigest"), "{c}");
                assert_ne!(signed, digest, "{c}");
                let sig = bytes(c, "signature");
                // Over what was signed, the signer; over the submission's digest, exactly the
                // non-guardian the contract named in NotGuardian(recovered).
                assert_eq!(
                    eip712::recover(signed, &sig).unwrap(),
                    addr(c, "signer"),
                    "{c}"
                );
                let r = eip712::recover(digest, &sig).unwrap();
                assert_eq!(r, addr(c, "recovered"), "{c}");
                assert_ne!(r, addr(c, "signer"), "{c}");
            }
            "high-s" | "bad-v" => {
                let sig = bytes(c, "signature");
                assert!(
                    matches!(
                        eip712::recover(digest, &sig),
                        Err(Error::BadSignature { .. })
                    ),
                    "{c}"
                );
                assert!(
                    matches!(
                        eip712::sort_signatures(digest, &[sig]),
                        Err(Error::BadSignature { .. })
                    ),
                    "{c}"
                );
            }
            "duplicate-signer" | "not-ascending" => {
                let sigs: Vec<Bytes> = c["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Bytes::from_str(v.as_str().unwrap()).unwrap())
                    .collect();
                let signers: Vec<Address> = c["signers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Address::from_str(v.as_str().unwrap()).unwrap())
                    .collect();
                for (sig, who) in sigs.iter().zip(&signers) {
                    assert_eq!(eip712::recover(digest, sig).unwrap(), *who, "{c}");
                }
                let sorted = eip712::sort_signatures(digest, &sigs);
                if c["acceptedAfterSort"].as_bool().unwrap() {
                    let sorted = sorted.unwrap();
                    assert!(signers[0] > signers[1], "case is not descending: {c}");
                    assert_eq!(sorted[0].signer, signers[1], "{c}");
                    assert_eq!(sorted[1].signer, signers[0], "{c}");
                    assert_eq!(sorted[0].signature, sigs[1], "{c}");
                } else {
                    assert!(
                        matches!(sorted, Err(Error::DuplicateSigner(a)) if a == signers[0]),
                        "{c}"
                    );
                }
            }
            other => panic!("unknown reject {other}"),
        }
    }
    assert_eq!(
        seen,
        [
            "wrong-chain-id",
            "wrong-verifying-contract",
            "high-s",
            "bad-v",
            "wrong-struct",
            "duplicate-signer",
            "not-ascending"
        ]
    );
}
