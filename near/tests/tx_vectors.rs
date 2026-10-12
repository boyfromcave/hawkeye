//! Golden vectors for Hawkeye's hand-rolled NEAR transaction codec (`crates/hawkeye-near/src/
//! tx.rs`, NEAR plan NH4), built and signed here by `near-primitives` / `near-crypto` 0.37.4 —
//! the types nearcore itself deserialises. Not a sandbox test: it runs with plain `cargo test`.
//!
//! `WYEC_NEAR_WRITE_TX_VECTORS=1 cargo test --test tx_vectors` (re)writes
//! `../crates/hawkeye-near/tests/data/tx_vectors.json`; without it the file must equal what
//! `near-primitives` produces now. `hawkeye-near`'s `tests/codec.rs` rebuilds every vector with
//! the hand-rolled codec and checks it byte for byte.

use std::str::FromStr;

use near_crypto::{KeyType, SecretKey, Signature};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{
    Action, AddKeyAction, CreateAccountAction, DeployContractAction, FunctionCallAction,
    SignedTransaction, Transaction, TransactionV0, TransferAction,
};
use near_primitives::types::{AccountId, Balance, Gas};
use near_sdk::borsh;
use serde_json::{Value, json};

const FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crates/hawkeye-near/tests/data/tx_vectors.json"
);

enum A {
    Call(&'static str, Vec<u8>, u64, u128),
    Transfer(u128),
    CreateAccount,
    Deploy(Vec<u8>),
    /// A full-access ed25519 key (from this seed) with this nonce.
    AddFullAccessKey(&'static str, u64),
}

struct Case {
    name: &'static str,
    seed: &'static str,
    signer: &'static str,
    receiver: &'static str,
    nonce: u64,
    block_hash: [u8; 32],
    actions: Vec<A>,
}

fn cases() -> Vec<Case> {
    let tgas = 1_000_000_000_000u64;
    let lock = "4c".repeat(32);
    let sig = format!("{}00", "5a".repeat(64));
    vec![
        Case {
            name: "propose_mint",
            seed: "hawkeye tx vector 1",
            signer: "hawkeye1.test.near",
            receiver: "wyec.test.near",
            nonce: 1,
            block_hash: [0x11; 32],
            actions: vec![A::Call(
                "propose_mint",
                format!(
                    r#"{{"lock_id":"{lock}","amount":"1000000000","receiver_id":"alice.test.near","sig":"{sig}"}}"#
                )
                .into_bytes(),
                100 * tgas,
                0,
            )],
        },
        Case {
            name: "mint_threshold_large_nonce",
            seed: "hawkeye tx vector 2",
            signer: "relayer.wyec.near",
            receiver: "wyec.near",
            nonce: (1u64 << 53) + 7,
            block_hash: [0xfe; 32],
            actions: vec![A::Call(
                "mint",
                format!(
                    r#"{{"lock_id":"{lock}","amount":"340282366920938463463374607431768211455","receiver_id":"bob.near","sigs":["{sig}","{sig}"]}}"#
                )
                .into_bytes(),
                300 * tgas,
                0,
            )],
        },
        Case {
            name: "burn_with_deposit_implicit_signer",
            seed: "hawkeye tx vector 3",
            signer: "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de",
            receiver: "wyec.testnet",
            nonce: 123_456_789_012,
            block_hash: [0x00; 32],
            actions: vec![A::Call(
                "burn",
                br#"{"amount":"400000000","ycash_recipient":"0100000000000000000000007777777777777777777777777777777777777777"}"#.to_vec(),
                30 * tgas,
                1_850_000_000_000_000_000_000,
            )],
        },
        Case {
            name: "two_actions_evm_implicit_signer",
            seed: "hawkeye tx vector 4",
            signer: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            receiver: "wyec.test.near",
            nonce: u64::MAX,
            block_hash: [0xa5; 32],
            actions: vec![
                A::Call(
                    "execute_mint",
                    format!(r#"{{"lock_id":"{lock}"}}"#).into_bytes(),
                    u64::MAX,
                    u128::MAX,
                ),
                A::Transfer(1),
            ],
        },
        Case {
            name: "empty_args_no_actions_after",
            seed: "hawkeye tx vector 5",
            signer: "ab",
            receiver: "a-b_c.d",
            nonce: 0,
            block_hash: [0x42; 32],
            actions: vec![A::Call("config", vec![], 1, 1)],
        },
        // the account set-up a devnet sends (hawkeye-near `admin`, NH5)
        Case {
            name: "create_subaccount_with_key",
            seed: "hawkeye tx vector 6",
            signer: "test.near",
            receiver: "hawkeye1.test.near",
            nonce: 9_000_001,
            block_hash: [0x5c; 32],
            actions: vec![
                A::CreateAccount,
                A::Transfer(50_000_000_000_000_000_000_000_000),
                A::AddFullAccessKey("hawkeye tx vector 6 new key", 0),
            ],
        },
        Case {
            name: "deploy_and_init",
            seed: "hawkeye tx vector 7",
            signer: "wyec.test.near",
            receiver: "wyec.test.near",
            nonce: 2,
            block_hash: [0x77; 32],
            actions: vec![
                A::Deploy(b"\0asm\x01\0\0\0 not a real module".to_vec()),
                A::Call("new", br#"{"network_id":"sandbox"}"#.to_vec(), 100 * tgas, 0),
                A::AddFullAccessKey("hawkeye tx vector 7 new key", u64::MAX),
            ],
        },
    ]
}

fn build(c: &Case) -> Value {
    let sk = SecretKey::from_seed(KeyType::ED25519, c.seed);
    let pk = sk.public_key();
    let actions: Vec<Action> = c
        .actions
        .iter()
        .map(|a| match a {
            A::Call(m, args, gas, deposit) => Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: (*m).to_owned(),
                args: args.clone(),
                gas: Gas::from_gas(*gas),
                deposit: Balance::from_yoctonear(*deposit),
            })),
            A::Transfer(d) => Action::Transfer(TransferAction {
                deposit: Balance::from_yoctonear(*d),
            }),
            A::CreateAccount => Action::CreateAccount(CreateAccountAction {}),
            A::Deploy(code) => Action::DeployContract(DeployContractAction { code: code.clone() }),
            A::AddFullAccessKey(seed, nonce) => Action::AddKey(Box::new(AddKeyAction {
                public_key: SecretKey::from_seed(KeyType::ED25519, seed).public_key(),
                access_key: AccessKey {
                    nonce: *nonce,
                    permission: AccessKeyPermission::FullAccess,
                },
            })),
        })
        .collect();
    let tx = Transaction::V0(TransactionV0 {
        signer_id: AccountId::from_str(c.signer).unwrap(),
        public_key: pk.clone(),
        nonce: c.nonce,
        receiver_id: AccountId::from_str(c.receiver).unwrap(),
        block_hash: CryptoHash(c.block_hash),
        actions,
    });
    let (hash, _) = tx.get_hash_and_size();
    let signature = sk.sign(hash.as_ref());
    let Signature::ED25519(raw) = &signature else {
        panic!("ed25519")
    };
    let sig_bytes = raw.to_bytes();
    let signed = SignedTransaction::new(signature.clone(), tx.clone());
    assert_eq!(signed.get_hash(), hash);
    let tx_borsh = borsh::to_vec(&tx).unwrap();
    let signed_borsh = borsh::to_vec(&signed).unwrap();
    // round trip through nearcore's own deserialiser
    let back: SignedTransaction = borsh::from_slice(&signed_borsh).unwrap();
    assert_eq!(back.get_hash(), hash);
    assert!(signature.verify(hash.as_ref(), &pk));
    let actions: Vec<Value> = c
        .actions
        .iter()
        .map(|a| match a {
            A::Call(m, args, gas, deposit) => json!({"FunctionCall": {
                "method_name": m, "args_hex": hex::encode(args),
                "gas": gas.to_string(), "deposit": deposit.to_string()}}),
            A::Transfer(d) => json!({"Transfer": {"deposit": d.to_string()}}),
            A::CreateAccount => json!("CreateAccount"),
            A::Deploy(code) => json!({"DeployContract": {"code_hex": hex::encode(code)}}),
            A::AddFullAccessKey(seed, nonce) => json!({"AddKey": {
                "public_key": SecretKey::from_seed(KeyType::ED25519, seed).public_key().to_string(),
                "nonce": nonce.to_string(), "permission": "FullAccess"}}),
        })
        .collect();
    json!({
        "name": c.name,
        "secret_key": sk.to_string(),
        "public_key": pk.to_string(),
        "signer_id": c.signer,
        "receiver_id": c.receiver,
        "nonce": c.nonce.to_string(),
        "block_hash": hex::encode(c.block_hash),
        "actions": actions,
        "transaction_borsh": hex::encode(&tx_borsh),
        "transaction_hash": hex::encode(hash.0),
        "transaction_hash_b58": hash.to_string(),
        "signature": hex::encode(sig_bytes),
        "signed_borsh": hex::encode(&signed_borsh),
    })
}

#[test]
fn tx_vectors_file() {
    let doc = json!({
        "comment": "NEAR TransactionV0 / SignedTransaction golden vectors built and signed by near-primitives and near-crypto 0.37.4 (near/tests/tx_vectors.rs); checked by crates/hawkeye-near/tests/codec.rs",
        "near_primitives": "0.37.4",
        "vectors": cases().iter().map(build).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("WYEC_NEAR_WRITE_TX_VECTORS").as_deref() == Ok("1") {
        std::fs::write(FILE, &text).unwrap();
        return;
    }
    let have = std::fs::read_to_string(FILE)
        .expect("tx_vectors.json (regenerate with WYEC_NEAR_WRITE_TX_VECTORS=1)");
    assert_eq!(
        have, text,
        "tx_vectors.json is stale: regenerate with WYEC_NEAR_WRITE_TX_VECTORS=1"
    );
}
