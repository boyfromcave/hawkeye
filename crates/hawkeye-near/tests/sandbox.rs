//! The NEAR adapter against a **real** nearcore sandbox node (NEAR plan NH5): every RPC shape the
//! NH4 client assumed and only the mock had answered — `send_tx` with `wait_until: FINAL`, views
//! at `final` and at a block hash, `block`, `status`, `view_access_key`, `EXPERIMENTAL_changes`
//! for the contract per block, `EXPERIMENTAL_receipt`, contract panics in a view and in a
//! transaction — and [`WyecNear::scan`] finding a threshold mint, a proposal, a challenge, an
//! execute and a burn.
//!
//! Env-gated, so `cargo test --workspace` passes without a sandbox:
//!
//! | Variable | |
//! |---|---|
//! | `HAWKEYE_NEAR_SANDBOX_RPC` | the sandbox's RPC (`http://127.0.0.1:3030`); unset: skipped |
//! | `HAWKEYE_NEAR_SANDBOX_KEY` | a funded full-access key file: the sandbox home's `validator_key.json` (`test.near`) |
//! | `HAWKEYE_NEAR_WASM` | the `wyec-near` wasm (default `near/target/wasm32-unknown-unknown/release/wyec_near.wasm`) |
//! | `HAWKEYE_REQUIRE_NEAR_SANDBOX=1` | a missing sandbox fails instead of skipping (CI) |
//!
//! Every run creates fresh accounts (`<name><unix-ms>.<signer>`), so it can repeat on one node.
//! The gas each call burnt is printed (`--nocapture`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hawkeye_core::near::{BridgeMessage, Domain, GuardianKey, guardian_key_of, sign_digest};
use hawkeye_core::{AccountId, SecretKey};
use hawkeye_near::admin::{Admin, NEAR};
use hawkeye_near::contract::{NearEvent, ProposalStatus, sort_signatures};
use hawkeye_near::rpc::BlockRef;
use hawkeye_near::tx::{Action, Transaction};
use hawkeye_near::{Error, KeyFile, WyecNear};
use serde_json::json;

const NETWORK: &str = "sandbox";
const WINDOW: u64 = 3;

struct Sandbox {
    rpc: String,
    key: PathBuf,
    wasm: PathBuf,
}

fn sandbox() -> Option<Sandbox> {
    let required = std::env::var("HAWKEYE_REQUIRE_NEAR_SANDBOX").as_deref() == Ok("1");
    let Ok(rpc) = std::env::var("HAWKEYE_NEAR_SANDBOX_RPC") else {
        assert!(
            !required,
            "HAWKEYE_REQUIRE_NEAR_SANDBOX=1 but HAWKEYE_NEAR_SANDBOX_RPC is unset"
        );
        eprintln!("skipped: set HAWKEYE_NEAR_SANDBOX_RPC (and _KEY) to run against a sandbox");
        return None;
    };
    let key = std::env::var("HAWKEYE_NEAR_SANDBOX_KEY")
        .expect("HAWKEYE_NEAR_SANDBOX_KEY: the sandbox's validator_key.json")
        .into();
    let wasm = std::env::var("HAWKEYE_NEAR_WASM").map_or_else(
        |_| {
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../near/target/wasm32-unknown-unknown/release/wyec_near.wasm"
            ))
        },
        PathBuf::from,
    );
    Some(Sandbox { rpc, key, wasm })
}

fn guardian(i: u8) -> SecretKey {
    SecretKey::from_bytes(&[i + 0x31; 32]).unwrap()
}

fn seed(tag: &str, n: u128) -> [u8; 32] {
    hawkeye_core::bytes::sha256(format!("hawkeye-near sandbox {tag} {n}").as_bytes())
}

fn gas(what: &str, g: u64) {
    println!("gas {what}: {:.2} TGas", g as f64 / 1e12);
}

#[tokio::test(flavor = "multi_thread")]
async fn adapter_against_a_real_sandbox() {
    let Some(sb) = sandbox() else { return };
    let root = KeyFile::read(&sb.key).expect("signer key");
    let admin = Admin::new(&sb.rpc, root.clone()).unwrap();
    let run = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let sub = |name: &str| AccountId::parse(&format!("{name}{run}.{}", root.account_id)).unwrap();

    // ---- accounts: contract, relayer, holder (CreateAccount + Transfer + AddKey(FullAccess))
    let contract_id = sub("wyec");
    let (contract_key, o) = admin
        .create_account_with_seed(&contract_id, 30 * NEAR, &seed("contract", run))
        .await
        .expect("create the contract account");
    gas("create_account", o.gas_burnt);
    let (relayer_key, _) = admin
        .create_account_with_seed(&sub("relayer"), 10 * NEAR, &seed("relayer", run))
        .await
        .unwrap();
    let (alice_key, _) = admin
        .create_account_with_seed(&sub("alice"), 10 * NEAR, &seed("alice", run))
        .await
        .unwrap();
    let alice = alice_key.account_id.clone();

    // ---- deploy + new() in one transaction
    let gs: Vec<SecretKey> = (0..3).map(guardian).collect();
    let gk: Vec<GuardianKey> = gs.iter().map(guardian_key_of).collect();
    let code = std::fs::read(&sb.wasm).unwrap_or_else(|e| panic!("{}: {e}", sb.wasm.display()));
    let deployer = Admin::new(&sb.rpc, contract_key).unwrap();
    let init = json!({"network_id": NETWORK, "guardians": gk.iter().map(hex::encode).collect::<Vec<_>>(),
        "threshold": 2, "challenge_window_sec": WINDOW, "mint_cap": "0", "cap_window_sec": 0});
    let o = deployer
        .deploy(code.clone(), Some(("new", &init)))
        .await
        .expect("deploy + new");
    gas(&format!("deploy+new ({} bytes)", code.len()), o.gas_burnt);

    let domain = Domain::new(NETWORK, contract_id.clone()).unwrap();
    let c = WyecNear::new(
        &sb.rpc,
        domain.clone(),
        Some(relayer_key),
        100 * hawkeye_near::tx::TGAS,
    )
    .unwrap();
    let rpc = c.rpc();

    // ---- block, status, views at final
    let head = rpc.block(BlockRef::Final).await.unwrap();
    assert!(head.height > 0 && head.timestamp_ns > 1_600_000_000_000_000_000);
    assert_eq!(
        rpc.block(BlockRef::Height(head.height)).await.unwrap(),
        head
    );
    assert_eq!(rpc.block(BlockRef::Hash(head.hash)).await.unwrap(), head);
    assert_eq!(
        rpc.block(BlockRef::Hash(head.prev_hash))
            .await
            .unwrap()
            .hash,
        head.prev_hash
    );
    let earliest = rpc.earliest_block_height().await.unwrap();
    assert!(earliest <= head.height);
    let start = head.height;
    let cfg = c.config().await.unwrap();
    assert_eq!(
        (
            cfg.network_id.as_str(),
            cfg.contract_id.as_str(),
            cfg.threshold
        ),
        (NETWORK, contract_id.as_str(), 2)
    );
    assert_eq!(cfg.guardians, gk);
    assert_eq!(c.guardians().await.unwrap(), gk);
    assert_eq!(c.threshold().await.unwrap(), 2);
    assert_eq!(cfg.challenge_window_sec, WINDOW);
    assert_eq!(c.total_supply().await.unwrap(), 0);
    assert!(!c.is_paused().await.unwrap());
    assert_eq!(c.mint_available().await.unwrap(), u128::MAX);

    // ---- access key nonce at final
    let ak = rpc
        .access_key(alice.as_str(), &alice_key.public_key_text())
        .await
        .unwrap();
    assert!(ak.block_height >= start);

    // ---- a view that panics, and an unknown access key
    match c.view("get_proposal", json!({"lock_id": "zz"})).await {
        Err(Error::Panic(p)) => assert_eq!(p, "wyec: lock_id must be 32 bytes of hex"),
        other => panic!("a view panic: {other:?}"),
    }
    let e = rpc
        .access_key(
            alice.as_str(),
            &KeyFile::from_seed(alice.clone(), &[9; 32]).public_key_text(),
        )
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Rpc { .. }), "{e:?}");

    // ---- threshold mint of lock A (auto-registers alice's storage)
    let lock_a = [0xa1; 32];
    let digest = domain.digest(&BridgeMessage::Mint {
        lock_id: lock_a,
        amount: 1_000_000_000,
        receiver_id: alice.clone(),
    });
    let sigs: Vec<[u8; 65]> = [&gs[2], &gs[0]]
        .iter()
        .map(|k| sign_digest(k, &digest).unwrap())
        .collect();
    let sorted = sort_signatures(&digest, &sigs).unwrap();
    let minted = c
        .mint(&lock_a, 1_000_000_000, &alice, &sorted)
        .await
        .expect("threshold mint");
    gas("mint (threshold 2, registers storage)", minted.gas_burnt);
    assert!(minted.height >= start);
    assert_eq!(c.balance_of(&alice).await.unwrap(), 1_000_000_000);
    assert!(c.is_consumed(&lock_a).await.unwrap());

    // ---- a transaction that panics: the same lock again
    let e = c
        .mint(&lock_a, 1_000_000_000, &alice, &sorted)
        .await
        .unwrap_err();
    assert_eq!(e.revert_name(), Some("LockConsumed"), "{e:?}");

    // ---- optimistic: propose (g0), challenge (g2), propose (g1), execute after the window
    let lock_b = [0xb2; 32];
    let mint_b = BridgeMessage::Mint {
        lock_id: lock_b,
        amount: 500_000_000,
        receiver_id: alice.clone(),
    };
    let s0 = sign_digest(&gs[0], &domain.digest(&mint_b)).unwrap();
    let (p1, id1) = c
        .propose_mint(&lock_b, 500_000_000, &alice, &s0)
        .await
        .expect("propose_mint");
    gas("propose_mint", p1.gas_burnt);
    assert_eq!(id1, 1);
    let p = c
        .proposal(&lock_b)
        .await
        .unwrap()
        .expect("pending proposal");
    assert_eq!((p.id, p.proposer, p.amount), (1, gk[0], 500_000_000));
    assert_eq!(p.status, ProposalStatus::Pending);
    assert_eq!(
        c.proposal_status(&lock_b).await.unwrap(),
        ProposalStatus::Pending
    );
    // the proposal as of its own block
    let p1_block = rpc.block(BlockRef::Height(p1.height)).await.unwrap();
    let at = c
        .proposal_at(BlockRef::Hash(p1_block.hash), &lock_b)
        .await
        .unwrap()
        .expect("the proposal at its block");
    assert_eq!(at.eta, p1_block.timestamp_ns / 1_000_000_000 + WINDOW);
    assert!(
        c.proposal_at(BlockRef::Hash(p1_block.prev_hash), &lock_b)
            .await
            .unwrap()
            .is_none()
    );
    let ch = sign_digest(
        &gs[2],
        &domain.digest(&BridgeMessage::Challenge {
            lock_id: lock_b,
            proposal_id: 1,
        }),
    )
    .unwrap();
    let chal = c
        .challenge_mint(&lock_b, 1, &ch)
        .await
        .expect("challenge_mint");
    gas("challenge_mint", chal.gas_burnt);
    assert!(c.proposal(&lock_b).await.unwrap().is_none());
    assert!(c.is_vetoed(&lock_b, &gk[0]).await.unwrap());
    let e = c
        .propose_mint(&lock_b, 500_000_000, &alice, &s0)
        .await
        .unwrap_err();
    assert_eq!(e.revert_name(), Some("ProposerVetoed"), "{e:?}");
    let s1 = sign_digest(&gs[1], &domain.digest(&mint_b)).unwrap();
    let (_, id2) = c
        .propose_mint(&lock_b, 500_000_000, &alice, &s1)
        .await
        .unwrap();
    assert_eq!(id2, 2, "a refused (panicked) proposal took no id");
    let e = c.execute_mint(&lock_b).await.unwrap_err();
    assert_eq!(e.revert_name(), Some("ChallengeWindowOpen"), "{e:?}");
    let mut ready = false;
    for _ in 0..60 {
        if c.proposal_status(&lock_b).await.unwrap() == ProposalStatus::Ready {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ready, "the proposal never became Ready");
    let ex = c.execute_mint(&lock_b).await.expect("execute_mint");
    gas("execute_mint", ex.gas_burnt);
    assert_eq!(c.balance_of(&alice).await.unwrap(), 1_500_000_000);

    // ---- burn from the holder's own key, with the record's storage deposit
    let holder = WyecNear::new(
        &sb.rpc,
        domain.clone(),
        Some(alice_key.clone()),
        100 * hawkeye_near::tx::TGAS,
    )
    .unwrap();
    let mut recipient = [0u8; 32];
    recipient[0] = 1;
    recipient[12..].copy_from_slice(&[0x77; 20]);
    let (burned, nonce) = holder.burn(400_000_000, &recipient).await.expect("burn");
    gas("burn", burned.gas_burnt);
    assert_eq!(nonce, 0);
    let burns = c
        .burns_at(
            BlockRef::Final,
            0,
            c.burn_count_at(BlockRef::Final).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(burns.len(), 1);
    assert_eq!(
        (
            burns[0].amount,
            burns[0].from.as_str(),
            burns[0].ycash_recipient
        ),
        (400_000_000, alice.as_str(), recipient)
    );
    assert_eq!(c.total_supply().await.unwrap(), 1_100_000_000);

    // ---- the scanner finds every event, at the right heights, with the right keys
    let to = rpc.block(BlockRef::Final).await.unwrap().height;
    let t0 = std::time::Instant::now();
    let out = c.scan(start, to).await.expect("scan");
    println!(
        "scan {start}..={to}: {} blocks, {} events in {:?}",
        to - start + 1,
        out.events.len(),
        t0.elapsed()
    );
    for e in &out.events {
        println!("  {} {:?}", e.height, e.event);
    }
    let evs: Vec<&NearEvent> = out.events.iter().map(|e| &e.event).collect();
    let n = evs.len();
    assert_eq!(n, 6, "{evs:#?}");
    assert!(
        matches!(evs[0], NearEvent::Minted { lock_id, amount: 1_000_000_000, .. } if *lock_id == lock_a)
    );
    assert!(
        matches!(evs[1], NearEvent::Proposed { lock_id, proposal_id: 1, proposer, eta, .. }
        if *lock_id == lock_b && *proposer == gk[0] && *eta == at.eta)
    );
    assert!(
        matches!(evs[2], NearEvent::Challenged { lock_id, proposal_id: 1, challenger }
        if *lock_id == lock_b && *challenger == gk[2])
    );
    assert!(
        matches!(evs[3], NearEvent::Proposed { proposal_id: 2, proposer, .. } if *proposer == gk[1])
    );
    assert!(
        matches!(evs[4], NearEvent::Minted { lock_id, receiver_id, amount: 500_000_000 }
        if *lock_id == lock_b && *receiver_id == alice)
    );
    match evs[5] {
        NearEvent::Burn(b) => assert_eq!(*b, burns[0]),
        e => panic!("{e:?}"),
    }
    // heights: each event in its call's block; the burn at its record's block
    assert_eq!(out.events[0].height, minted.height);
    assert_eq!(out.events[1].height, p1.height);
    assert_eq!(out.events[2].height, chal.height);
    assert_eq!(out.events[4].height, ex.height);
    assert_eq!(out.events[5].height, burned.height);
    assert_eq!(out.events[5].id, burns[0].hash());
    let last = rpc.block(BlockRef::Height(to)).await.unwrap();
    assert_eq!(out.to_hash, last.hash);
    // the signatures a mint and a proposal carried, read back from their receipts
    let mut want = sorted.iter().map(|s| s.to_vec()).collect::<Vec<_>>();
    want.sort();
    let mut got = c.receipt_signatures(&out.events[0].id).await.unwrap();
    got.sort();
    assert_eq!(got, want);
    assert_eq!(
        c.receipt_signatures(&out.events[1].id).await.unwrap(),
        vec![s0.to_vec()]
    );
    // a scan of one block with nothing in it
    let quiet = c.scan(start, start).await.unwrap();
    assert!(quiet.events.iter().all(|e| e.height == start));

    // ---- an unknown block height (beyond the head)
    assert!(
        rpc.data_changes(to + 1_000_000, contract_id.as_str())
            .await
            .unwrap()
            .is_none()
    );

    // ---- a reused nonce is refused as InvalidNonce (the client re-reads and retries once)
    let ak = rpc
        .access_key(alice.as_str(), &alice_key.public_key_text())
        .await
        .unwrap();
    let stale = Transaction {
        signer_id: alice.clone(),
        public_key: alice_key.public_key(),
        nonce: ak.nonce,
        receiver_id: contract_id.clone(),
        block_hash: ak.block_hash,
        actions: vec![Action::Transfer { deposit: 1 }],
    }
    .sign(alice_key.signing_key())
    .unwrap();
    let e = rpc.send_tx(&stale.borsh()).await.unwrap_err();
    println!("reused nonce: {e}");
    assert!(e.is_invalid_nonce(), "{e:?}");
}
