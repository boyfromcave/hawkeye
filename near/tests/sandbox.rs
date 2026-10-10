//! Sandbox integration tests: the release wasm deployed to a real NEAR sandbox node
//! (near-workspaces). Skipped unless `NEAR_SANDBOX=1`: the sandbox binary is downloaded on first
//! use (from S3, unreachable in some build containers; GitHub runners reach it), or taken from
//! `NEAR_SANDBOX_BIN_PATH`.
//!
//! Build the wasm first (README): `cargo build --target wasm32-unknown-unknown --release`;
//! `WYEC_NEAR_WASM` overrides the path. Gas burnt per call is printed (`--nocapture`).

use k256::ecdsa::SigningKey;
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wyec_near::BridgeMessage;
use wyec_near::encoding::digest_preimage;

const NETWORK: &str = "sandbox";

fn enabled() -> bool {
    if std::env::var("NEAR_SANDBOX").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set NEAR_SANDBOX=1 to run the sandbox tests");
    false
}

fn wasm_path() -> String {
    std::env::var("WYEC_NEAR_WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/wasm32-unknown-unknown/release/wyec_near.wasm"
        )
        .to_string()
    })
}

struct Guardian {
    sk: SigningKey,
    pk: [u8; 64],
}

fn guardian(i: u8) -> Guardian {
    let secret: [u8; 32] = Sha256::new()
        .chain_update(b"wyec-near test guardian ")
        .chain_update([i])
        .finalize()
        .into();
    let sk = SigningKey::from_bytes(&secret.into()).unwrap();
    let pk = sk.verifying_key().to_encoded_point(false).as_bytes()[1..]
        .try_into()
        .unwrap();
    Guardian { sk, pk }
}

fn sign(g: &Guardian, digest: &[u8; 32]) -> String {
    let (sig, recid) = g.sk.sign_prehash_recoverable(digest).unwrap();
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    hex::encode(out)
}

struct Env {
    contract: Contract,
    relayer: Account,
    gs: Vec<Guardian>,
}

impl Env {
    async fn new(threshold: u8, window: u64) -> anyhow::Result<Self> {
        let worker = near_workspaces::sandbox().await?;
        let wasm = std::fs::read(wasm_path())
            .map_err(|e| anyhow::anyhow!("{}: {e} (build the wasm first)", wasm_path()))?;
        let contract = worker.dev_deploy(&wasm).await?;
        let gs: Vec<Guardian> = (0..3).map(guardian).collect();
        let res = contract
            .call("new")
            .args_json(json!({
                "network_id": NETWORK,
                "guardians": gs.iter().map(|g| hex::encode(g.pk)).collect::<Vec<_>>(),
                "threshold": threshold,
                "challenge_window_sec": window,
                "mint_cap": "0",
                "cap_window_sec": 0,
            }))
            .transact()
            .await?;
        assert!(res.is_success(), "new: {res:?}");
        let relayer = worker.dev_create_account().await?;
        Ok(Self {
            contract,
            relayer,
            gs,
        })
    }

    fn digest(&self, msg: &BridgeMessage) -> [u8; 32] {
        Sha256::digest(digest_preimage(NETWORK, self.contract.id().as_str(), msg)).into()
    }

    fn sigs(&self, idx: &[usize], msg: &BridgeMessage) -> Vec<String> {
        let mut v = idx.to_vec();
        v.sort_by_key(|&i| self.gs[i].pk);
        let d = self.digest(msg);
        v.iter().map(|&i| sign(&self.gs[i], &d)).collect()
    }

    async fn view(&self, method: &str, args: Value) -> anyhow::Result<Value> {
        Ok(self.contract.view(method).args_json(args).await?.json()?)
    }

    async fn call(
        &self,
        who: &Account,
        method: &str,
        args: Value,
        deposit: NearToken,
    ) -> anyhow::Result<Value> {
        let res = who
            .call(self.contract.id(), method)
            .args_json(args)
            .deposit(deposit)
            .max_gas()
            .transact()
            .await?;
        println!(
            "gas {method}: {} TGas",
            res.total_gas_burnt.as_gas() as f64 / 1e12
        );
        assert!(res.is_success(), "{method}: {:?}", res.failures());
        Ok(res.json().unwrap_or(Value::Null))
    }

    async fn balance(&self, who: &Account) -> anyhow::Result<u128> {
        let v = self
            .view("ft_balance_of", json!({"account_id": who.id()}))
            .await?;
        Ok(v.as_str().unwrap().parse()?)
    }
}

fn lock(n: u8) -> String {
    hex::encode([n; 32])
}

fn mint_msg(n: u8, amount: u128, to: &Account) -> BridgeMessage {
    BridgeMessage::Mint {
        lock_id: [n; 32],
        amount,
        receiver_id: to.id().to_string(),
    }
}

const ZERO: NearToken = NearToken::from_yoctonear(0);

#[tokio::test]
async fn sandbox_threshold_mint_burn_and_transfer() -> anyhow::Result<()> {
    if !enabled() {
        return Ok(());
    }
    let env = Env::new(2, 60).await?;
    let meta = env.view("ft_metadata", json!({})).await?;
    assert_eq!(
        (meta["name"].as_str(), meta["symbol"].as_str()),
        (Some("Wrapped Ycash"), Some("wYEC"))
    );
    assert_eq!(meta["decimals"], 8);

    let alice = env
        .relayer
        .create_subaccount("alice")
        .initial_balance(NearToken::from_near(2))
        .transact()
        .await?
        .into_result()?;
    let bob = env
        .relayer
        .create_subaccount("bob")
        .initial_balance(NearToken::from_near(2))
        .transact()
        .await?
        .into_result()?;

    // Threshold mint auto-registers alice's storage.
    assert!(
        env.view("storage_balance_of", json!({"account_id": alice.id()}))
            .await?
            .is_null()
    );
    let sigs = env.sigs(&[0, 2], &mint_msg(1, 1_000, &alice));
    env.call(
        &env.relayer,
        "mint",
        json!({"lock_id": lock(1), "amount": "1000", "receiver_id": alice.id(), "sigs": sigs}),
        ZERO,
    )
    .await?;
    assert_eq!(env.balance(&alice).await?, 1_000);
    assert!(
        !env.view("storage_balance_of", json!({"account_id": alice.id()}))
            .await?
            .is_null()
    );
    assert_eq!(
        env.view("is_consumed", json!({"lock_id": lock(1)})).await?,
        true
    );

    // Storage registration + ft_transfer.
    let bounds = env.view("storage_balance_bounds", json!({})).await?;
    let min: u128 = bounds["min"].as_str().unwrap().parse()?;
    env.call(
        &bob,
        "storage_deposit",
        json!({}),
        NearToken::from_yoctonear(min),
    )
    .await?;
    env.call(
        &alice,
        "ft_transfer",
        json!({"receiver_id": bob.id(), "amount": "250"}),
        NearToken::from_yoctonear(1),
    )
    .await?;
    assert_eq!(
        (env.balance(&alice).await?, env.balance(&bob).await?),
        (750, 250)
    );

    // Burn + get_burns.
    let dep: u128 = env
        .view("burn_storage_deposit", json!({"account_id": alice.id()}))
        .await?
        .as_str()
        .unwrap()
        .parse()?;
    let mut recipient = [0u8; 32];
    recipient[0] = 1;
    recipient[12..].copy_from_slice(&[0xab; 20]);
    let nonce = env
        .call(
            &alice,
            "burn",
            json!({"amount": "300", "ycash_recipient": hex::encode(recipient)}),
            NearToken::from_yoctonear(dep),
        )
        .await?;
    assert_eq!(nonce, 0);
    let burns = env
        .view("get_burns", json!({"from_nonce": 0, "limit": 10}))
        .await?;
    assert_eq!(burns.as_array().unwrap().len(), 1);
    assert_eq!(burns[0]["from"], alice.id().as_str());
    assert_eq!(burns[0]["amount"], "300");
    assert_eq!(burns[0]["ycash_recipient"], hex::encode(recipient));
    assert_eq!(env.view("get_burn_count", json!({})).await?, 1);
    assert_eq!(env.view("ft_total_supply", json!({})).await?, "700");
    Ok(())
}

#[tokio::test]
async fn sandbox_propose_challenge_execute() -> anyhow::Result<()> {
    if !enabled() {
        return Ok(());
    }
    let window = 2;
    let env = Env::new(2, window).await?;
    let alice = env
        .relayer
        .create_subaccount("alice")
        .initial_balance(NearToken::from_near(1))
        .transact()
        .await?
        .into_result()?;
    let msg = mint_msg(5, 42, &alice);

    // Guardian 0 proposes; guardian 2 challenges; guardian 0 is vetoed for the lock.
    let s0 = env.sigs(&[0], &msg).remove(0);
    let id = env
        .call(
            &env.relayer,
            "propose_mint",
            json!({"lock_id": lock(5), "amount": "42", "receiver_id": alice.id(), "sig": s0}),
            ZERO,
        )
        .await?;
    assert_eq!(id, 1);
    let ch = BridgeMessage::Challenge {
        lock_id: [5; 32],
        proposal_id: 1,
    };
    let c2 = env.sigs(&[2], &ch).remove(0);
    env.call(
        &env.relayer,
        "challenge_mint",
        json!({"lock_id": lock(5), "proposal_id": 1, "sig": c2}),
        ZERO,
    )
    .await?;
    assert!(
        env.view("get_proposal", json!({"lock_id": lock(5)}))
            .await?
            .is_null()
    );
    assert_eq!(
        env.view(
            "is_vetoed",
            json!({"lock_id": lock(5), "guardian": hex::encode(env.gs[0].pk)})
        )
        .await?,
        true
    );

    // Guardian 1 re-proposes; after the window anyone executes.
    let s1 = env.sigs(&[1], &msg).remove(0);
    let id = env
        .call(
            &env.relayer,
            "propose_mint",
            json!({"lock_id": lock(5), "amount": "42", "receiver_id": alice.id(), "sig": s1}),
            ZERO,
        )
        .await?;
    assert_eq!(id, 2);
    let p = env
        .view("get_proposal", json!({"lock_id": lock(5)}))
        .await?;
    assert_eq!(p["status"], "Pending");
    // Wait out the window (sandbox blocks carry wall-clock time).
    for _ in 0..60 {
        if env
            .view("proposal_status", json!({"lock_id": lock(5)}))
            .await?
            == "Ready"
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    env.call(&alice, "execute_mint", json!({"lock_id": lock(5)}), ZERO)
        .await?;
    assert_eq!(env.balance(&alice).await?, 42);
    assert_eq!(
        env.view("is_consumed", json!({"lock_id": lock(5)})).await?,
        true
    );
    Ok(())
}
