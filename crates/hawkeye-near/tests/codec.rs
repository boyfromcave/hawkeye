//! The hand-rolled transaction codec against the golden vectors built and signed by
//! `near-primitives` / `near-crypto` 0.37.4 (`near/tests/tx_vectors.rs` writes
//! `tests/data/tx_vectors.json`), and against the `borsh` crate's derive.

use borsh::BorshSerialize;
use hawkeye_core::AccountId;
use hawkeye_near::KeyFile;
use hawkeye_near::keys::decode_key_text;
use hawkeye_near::rpc::b58;
use hawkeye_near::tx::{Action, FunctionCall, SignedTransaction, Transaction};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/tx_vectors.json"
    ))
    .unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["near_primitives"], "0.37.4");
    doc["vectors"].as_array().unwrap().clone()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

fn tx_of(v: &Value, key: &KeyFile) -> Transaction {
    let actions = v["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            if a == "CreateAccount" {
                Action::CreateAccount
            } else if let Some(d) = a.get("DeployContract") {
                Action::DeployContract {
                    code: hex::decode(s(d, "code_hex")).unwrap(),
                }
            } else if let Some(k) = a.get("AddKey") {
                assert_eq!(s(k, "permission"), "FullAccess");
                Action::AddFullAccessKey {
                    public_key: decode_key_text(s(k, "public_key"))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    nonce: s(k, "nonce").parse().unwrap(),
                }
            } else if let Some(f) = a.get("FunctionCall") {
                Action::FunctionCall(FunctionCall {
                    method_name: s(f, "method_name").into(),
                    args: hex::decode(s(f, "args_hex")).unwrap(),
                    gas: s(f, "gas").parse().unwrap(),
                    deposit: s(f, "deposit").parse().unwrap(),
                })
            } else {
                Action::Transfer {
                    deposit: s(&a["Transfer"], "deposit").parse().unwrap(),
                }
            }
        })
        .collect();
    Transaction {
        signer_id: AccountId::parse(s(v, "signer_id")).unwrap(),
        public_key: key.public_key(),
        nonce: s(v, "nonce").parse().unwrap(),
        receiver_id: AccountId::parse(s(v, "receiver_id")).unwrap(),
        block_hash: hex::decode(s(v, "block_hash")).unwrap().try_into().unwrap(),
        actions,
    }
}

#[test]
fn near_primitives_vectors() {
    let vs = vectors();
    assert!(vs.len() >= 7);
    let kinds: Vec<&Value> = vs
        .iter()
        .flat_map(|v| v["actions"].as_array().unwrap())
        .collect();
    assert!(kinds.iter().any(|a| a.get("AddKey").is_some()));
    assert!(kinds.iter().any(|a| a.get("DeployContract").is_some()));
    assert!(kinds.iter().any(|a| *a == "CreateAccount"));
    for v in &vs {
        let name = s(v, "name");
        let key = KeyFile::from_json(
            &serde_json::json!({"account_id": s(v, "signer_id"),
                                "public_key": s(v, "public_key"),
                                "private_key": s(v, "secret_key")})
            .to_string(),
        )
        .unwrap_or_else(|e| panic!("{name}: key: {e}"));
        assert_eq!(key.public_key_text(), s(v, "public_key"), "{name}");
        let tx = tx_of(v, &key);
        assert_eq!(hex::encode(tx.borsh()), s(v, "transaction_borsh"), "{name}");
        assert_eq!(hex::encode(tx.hash()), s(v, "transaction_hash"), "{name}");
        assert_eq!(b58(&tx.hash()), s(v, "transaction_hash_b58"), "{name}");
        let signed = tx.clone().sign(key.signing_key()).unwrap();
        // ed25519 is deterministic: the same signature near-crypto made
        assert_eq!(hex::encode(signed.signature), s(v, "signature"), "{name}");
        assert_eq!(hex::encode(signed.borsh()), s(v, "signed_borsh"), "{name}");
        assert!(signed.verify(), "{name}");
        let back = SignedTransaction::decode(&hex::decode(s(v, "signed_borsh")).unwrap()).unwrap();
        assert_eq!(back, signed, "{name}");
        let (tx2, used) =
            Transaction::decode_prefix(&hex::decode(s(v, "transaction_borsh")).unwrap()).unwrap();
        assert_eq!(
            (tx2, used),
            (tx, s(v, "transaction_borsh").len() / 2),
            "{name}"
        );
    }
}

// The same layout through the borsh crate's derive (what near-primitives derives).
#[derive(BorshSerialize)]
enum PublicKey {
    Ed25519([u8; 32]),
}

#[derive(BorshSerialize)]
struct FunctionCallAction {
    method_name: String,
    args: Vec<u8>,
    gas: u64,
    deposit: u128,
}

#[derive(BorshSerialize)]
enum Permission {
    #[allow(dead_code)]
    FunctionCall,
    FullAccess,
}

#[derive(BorshSerialize)]
struct AccessKey {
    nonce: u64,
    permission: Permission,
}

#[allow(dead_code)]
#[derive(BorshSerialize)]
enum BorshAction {
    CreateAccount,
    DeployContract(Vec<u8>),
    FunctionCall(FunctionCallAction),
    Transfer(u128),
    Stake,
    AddKey(PublicKey, AccessKey),
}

#[derive(BorshSerialize)]
struct TransactionV0 {
    signer_id: String,
    public_key: PublicKey,
    nonce: u64,
    receiver_id: String,
    block_hash: [u8; 32],
    actions: Vec<BorshAction>,
}

#[test]
fn matches_the_borsh_derive() {
    let key = KeyFile::from_seed(AccountId::parse("a.near").unwrap(), &[1; 32]);
    let tx = Transaction {
        signer_id: key.account_id.clone(),
        public_key: key.public_key(),
        nonce: 42,
        receiver_id: AccountId::parse("wyec.near").unwrap(),
        block_hash: [3; 32],
        actions: vec![
            Action::FunctionCall(FunctionCall {
                method_name: "challenge_mint".into(),
                args: b"{}".to_vec(),
                gas: 7,
                deposit: u128::MAX - 1,
            }),
            Action::Transfer { deposit: 9 },
            Action::CreateAccount,
            Action::DeployContract { code: vec![1, 2] },
            Action::AddFullAccessKey {
                public_key: [6; 32],
                nonce: 11,
            },
        ],
    };
    let derived = borsh::to_vec(&TransactionV0 {
        signer_id: "a.near".into(),
        public_key: PublicKey::Ed25519(key.public_key()),
        nonce: 42,
        receiver_id: "wyec.near".into(),
        block_hash: [3; 32],
        actions: vec![
            BorshAction::FunctionCall(FunctionCallAction {
                method_name: "challenge_mint".into(),
                args: b"{}".to_vec(),
                gas: 7,
                deposit: u128::MAX - 1,
            }),
            BorshAction::Transfer(9),
            BorshAction::CreateAccount,
            BorshAction::DeployContract(vec![1, 2]),
            BorshAction::AddKey(
                PublicKey::Ed25519([6; 32]),
                AccessKey {
                    nonce: 11,
                    permission: Permission::FullAccess,
                },
            ),
        ],
    })
    .unwrap();
    assert_eq!(tx.borsh(), derived);
}
