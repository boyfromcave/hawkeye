//! Integration tests against a local anvil (plan §7 "Ethereum adapter"): deploy wYEC from the
//! forge-built artifacts in the predicted-address order, mint with 1-of-1 and 2-of-3 EIP-712
//! signatures made by this crate, burn and scan as finalized, and the CR-W1 optimistic flow on the
//! test double. Each test spawns its own anvil with `--slots-in-an-epoch 1` (so `finalized` is
//! `latest − 2`) and is skipped, not failed, when `anvil` is not on PATH — unless
//! `HAWKEYE_REQUIRE_ANVIL=1` (CI), which turns a missing anvil into a failure.

use std::borrow::Cow;

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::providers::{DynProvider, Provider};
use hawkeye_eth::eip712;
use hawkeye_eth::{
    Address, B256, BridgeEvent, Bytes, Deployment, Error, EthClient, EthConfig, Finality, MintMode,
    MintSubmitted, PrivateKeySigner, Scanner, U256, deploy, wallet_provider,
};

struct Env {
    anvil: AnvilInstance,
    deployer: PrivateKeySigner,
    guardians: Vec<PrivateKeySigner>,
    dep: Deployment,
    /// Sends from the deployer (also the wYEC holder in these tests).
    client: EthClient,
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn key(anvil: &AnvilInstance, i: usize) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::from_slice(&anvil.keys()[i].to_bytes())).unwrap()
}

/// anvil + a deployment with guardians = anvil accounts 1..=n (funded, so they can challenge).
async fn setup(n: usize, k: u8, mode: MintMode) -> Option<Env> {
    if !on_path("anvil") {
        assert!(
            std::env::var("HAWKEYE_REQUIRE_ANVIL").as_deref() != Ok("1"),
            "HAWKEYE_REQUIRE_ANVIL=1 but `anvil` is not on PATH"
        );
        eprintln!("skipping: `anvil` is not on PATH");
        return None;
    }
    let anvil = Anvil::new()
        .args(["--slots-in-an-epoch", "1"])
        .try_spawn()
        .expect("spawn anvil");
    let deployer = key(&anvil, 0);
    let guardians: Vec<PrivateKeySigner> = (1..=n).map(|i| key(&anvil, i)).collect();
    let addrs: Vec<Address> = guardians.iter().map(|g| g.address()).collect();
    let p = wallet_provider(&anvil.endpoint(), deployer.clone()).unwrap();
    let dep = deploy(&p, deployer.address(), &addrs, k, mode, 60)
        .await
        .expect("deploy");
    assert_eq!(
        dep.bridge,
        deployer.address().create(0),
        "bridge at the deployer's first CREATE"
    );
    let client = connect(&anvil, &dep, Some(deployer.clone())).await;
    Some(Env {
        anvil,
        deployer,
        guardians,
        dep,
        client,
    })
}

async fn connect(
    anvil: &AnvilInstance,
    dep: &Deployment,
    wallet: Option<PrivateKeySigner>,
) -> EthClient {
    let mut cfg = EthConfig::new(anvil.endpoint(), 31337, dep.bridge);
    cfg.token = Some(dep.token);
    EthClient::connect(&cfg, wallet).await.expect("connect")
}

async fn mine(p: &DynProvider, blocks: u64) {
    let _: serde_json::Value = p
        .raw_request(Cow::Borrowed("anvil_mine"), (U256::from(blocks),))
        .await
        .unwrap();
}

fn lock(i: u8) -> B256 {
    B256::repeat_byte(i)
}

fn sigs(keys: &[&PrivateKeySigner], digest: B256) -> Vec<Bytes> {
    keys.iter()
        .map(|k| eip712::sign_digest(k, digest).unwrap())
        .collect()
}

fn reason(e: Error) -> String {
    match e {
        Error::Reverted { reason, .. } => reason,
        other => panic!("expected a revert, got {other:?}"),
    }
}

#[tokio::test]
async fn mint_one_of_one() {
    let Some(env) = setup(1, 1, MintMode::Threshold { k: 1 }).await else {
        return;
    };
    let c = &env.client;
    assert_eq!(
        c.guardians().await.unwrap(),
        vec![env.guardians[0].address()]
    );
    assert_eq!(c.threshold().await.unwrap(), 1);
    assert!(!c.paused().await.unwrap());

    let to = Address::repeat_byte(0x42);
    let amount = U256::from(123_456_789u64);
    assert!(!c.consumed(lock(1)).await.unwrap());
    let s = sigs(&[&env.guardians[0]], c.mint_digest(lock(1), amount, to));
    let out = c
        .submit_mint(MintMode::Threshold { k: 1 }, lock(1), amount, to, &s)
        .await
        .unwrap();
    assert!(matches!(out, MintSubmitted::Minted(_)));
    assert!(c.consumed(lock(1)).await.unwrap());
    assert_eq!(c.balance_of(to).await.unwrap(), amount);
    assert_eq!(c.total_supply().await.unwrap(), amount);
}

#[tokio::test]
async fn mint_two_of_three_sorting_and_rejections() {
    let Some(env) = setup(3, 2, MintMode::Threshold { k: 2 }).await else {
        return;
    };
    let c = &env.client;
    let g = &env.guardians;
    let to = Address::repeat_byte(0x07);
    let amount = U256::from(5_0000_0000u64);
    let d = c.mint_digest(lock(2), amount, to);

    // Below threshold: refused locally by submit_mint, and by the contract through raw mint.
    let one = sigs(&[&g[1]], d);
    assert!(matches!(
        c.submit_mint(MintMode::Threshold { k: 2 }, lock(2), amount, to, &one)
            .await,
        Err(Error::TooFewSignatures { got: 1, need: 2 })
    ));
    assert!(reason(c.mint(lock(2), amount, to, &one).await.unwrap_err()).contains("Threshold"));

    // A non-guardian's signature.
    let outsider = PrivateKeySigner::random();
    let bad = sigs(&[&g[0], &outsider], d);
    assert!(reason(c.mint(lock(2), amount, to, &bad).await.unwrap_err()).contains("NotGuardian"));

    // The same signer twice is caught before sending.
    let dup = sigs(&[&g[0], &g[0]], d);
    assert!(matches!(
        c.mint(lock(2), amount, to, &dup).await,
        Err(Error::DuplicateSigner(_))
    ));

    // Signatures in whatever order: the client sorts them by recovered address.
    let mut two = sigs(&[&g[2], &g[0]], d);
    if eip712::recover(d, &two[0]).unwrap() < eip712::recover(d, &two[1]).unwrap() {
        two.swap(0, 1); // make sure they arrive descending
    }
    c.mint(lock(2), amount, to, &two).await.unwrap();
    assert_eq!(c.balance_of(to).await.unwrap(), amount);

    // All three also fine on a fresh lock; the lockId is the replay key.
    let d3 = c.mint_digest(lock(3), U256::from(1), to);
    c.mint(
        lock(3),
        U256::from(1),
        to,
        &sigs(&[&g[0], &g[1], &g[2]], d3),
    )
    .await
    .unwrap();
    assert!(reason(c.mint(lock(2), amount, to, &two).await.unwrap_err()).contains("LockConsumed"));
}

#[tokio::test]
async fn burn_is_scanned_once_finalized() {
    let Some(env) = setup(1, 1, MintMode::Threshold { k: 1 }).await else {
        return;
    };
    let c = &env.client;
    let p = c.provider().clone();
    let holder = env.deployer.address();
    let amount = U256::from(10_0000_0000u64);
    c.mint(
        lock(9),
        amount,
        holder,
        &sigs(&[&env.guardians[0]], c.mint_digest(lock(9), amount, holder)),
    )
    .await
    .unwrap();

    // anvil 1.7.1 with --slots-in-an-epoch 1: finalized = latest - 2.
    let latest = c.latest_block_number().await.unwrap();
    assert_eq!(
        c.finalized_block_number().await.unwrap(),
        latest.saturating_sub(2)
    );

    let mut scanner = Scanner::new(env.dep.deploy_block);
    let first = scanner.poll(c).await.unwrap();
    assert_eq!(first.from, env.dep.deploy_block);

    let rcpt = B256::left_padding_from(&[0x01, 0x00]); // opaque to the contract
    let burned = c.burn(U256::from(3_0000_0000u64), rcpt).await.unwrap();
    assert_eq!(burned.nonce, U256::ZERO);
    assert_eq!(c.burn_nonce().await.unwrap(), U256::from(1));
    assert_eq!(
        c.balance_of(holder).await.unwrap(),
        U256::from(7_0000_0000u64)
    );

    // Not final yet: the burn's block is above finalized.
    let early = scanner.poll(c).await.unwrap();
    assert!(
        early
            .events
            .iter()
            .all(|e| !matches!(e.event, BridgeEvent::Burn { .. }))
    );
    assert!(early.to < burned.mined.block_number);

    mine(&p, 2).await;
    let batch = scanner.poll(c).await.unwrap();
    assert!(batch.to >= burned.mined.block_number);
    let burns: Vec<_> = batch
        .events
        .iter()
        .filter(|e| matches!(e.event, BridgeEvent::Burn { .. }))
        .collect();
    assert_eq!(burns.len(), 1);
    assert_eq!(
        burns[0].event,
        BridgeEvent::Burn {
            nonce: U256::ZERO,
            from: holder,
            amount: U256::from(3_0000_0000u64),
            ycash_recipient: rcpt,
        }
    );
    assert_eq!(burns[0].meta.tx_hash, burned.mined.tx);
    assert_eq!(burns[0].meta.block_number, burned.mined.block_number);

    // Everything from the deployment on, in order, over a whole rescan with 1-block chunks.
    let fin = c.finalized_block_number().await.unwrap();
    let mut cfg = EthConfig::new(env.anvil.endpoint(), 31337, env.dep.bridge);
    cfg.log_chunk = 1;
    let small = EthClient::connect(&cfg, None).await.unwrap();
    let all = small.scan(env.dep.deploy_block, fin).await.unwrap();
    let kinds: Vec<&str> = all
        .iter()
        .map(|e| match e.event {
            BridgeEvent::GuardiansChanged { .. } => "guardians",
            BridgeEvent::Minted { .. } => "minted",
            BridgeEvent::Burn { .. } => "burn",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["guardians", "minted", "burn"]);
    assert_eq!(
        all[1].event,
        BridgeEvent::Minted {
            lock_id: lock(9),
            to: holder,
            amount
        }
    );

    // A second burn gets nonce 1; a zero-amount burn is accepted and spends nonce 2.
    assert_eq!(
        c.burn(U256::from(1), rcpt).await.unwrap().nonce,
        U256::from(1)
    );
    assert_eq!(
        c.burn(U256::ZERO, B256::ZERO).await.unwrap().nonce,
        U256::from(2)
    );
}

#[tokio::test]
async fn optimistic_propose_challenge_execute() {
    let Some(env) = setup(3, 2, MintMode::Optimistic).await else {
        return;
    };
    let c = &env.client;
    let g = &env.guardians;
    assert_eq!(c.challenge_window().await.unwrap(), 60);
    let to = Address::repeat_byte(0x55);
    let amount = U256::from(42u64);
    let d = c.mint_digest(lock(5), amount, to);
    let mut scanner = Scanner::new(env.dep.deploy_block);

    // One guardian's signature opens a proposal.
    let MintSubmitted::Proposed { executable_at, .. } = c
        .submit_mint(
            MintMode::Optimistic,
            lock(5),
            amount,
            to,
            &sigs(&[&g[0]], d),
        )
        .await
        .unwrap()
    else {
        panic!("expected a proposal")
    };
    let prop = c.proposal(lock(5)).await.unwrap().unwrap();
    assert_eq!(
        (prop.amount, prop.to, prop.proposer),
        (amount, to, g[0].address())
    );
    assert_eq!(prop.executable_at, executable_at);

    // Another guardian challenges it from its own account.
    let challenger = connect(&env.anvil, &env.dep, Some(g[1].clone())).await;
    challenger.challenge_mint(lock(5)).await.unwrap();
    assert_eq!(c.proposal(lock(5)).await.unwrap(), None);
    // A non-guardian cannot.
    assert!(reason(c.challenge_mint(lock(5)).await.unwrap_err()).contains("NotGuardian"));

    // Re-proposed (by another guardian's signature); too early to execute.
    let (_, at) = c
        .propose_mint(lock(5), amount, to, &sigs(&[&g[2]], d)[0])
        .await
        .unwrap();
    assert!(reason(c.execute_mint(lock(5)).await.unwrap_err()).contains("ChallengeWindowOpen"));

    let p = c.provider();
    let _: serde_json::Value = p
        .raw_request(Cow::Borrowed("evm_increaseTime"), (U256::from(60),))
        .await
        .unwrap();
    mine(p, 1).await;
    let now = p
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .unwrap()
        .header
        .timestamp;
    assert!(now >= at);
    c.execute_mint(lock(5)).await.unwrap();
    assert_eq!(c.balance_of(to).await.unwrap(), amount);
    assert!(c.consumed(lock(5)).await.unwrap());

    mine(p, 2).await;
    let events: Vec<BridgeEvent> = scanner
        .poll(c)
        .await
        .unwrap()
        .events
        .into_iter()
        .map(|e| e.event)
        .filter(|e| !matches!(e, BridgeEvent::GuardiansChanged { .. }))
        .collect();
    assert_eq!(
        events,
        vec![
            BridgeEvent::MintProposed {
                lock_id: lock(5),
                to,
                amount,
                proposer: g[0].address(),
                executable_at
            },
            BridgeEvent::MintChallenged {
                lock_id: lock(5),
                challenger: g[1].address(),
                proposer: g[0].address()
            },
            BridgeEvent::MintProposed {
                lock_id: lock(5),
                to,
                amount,
                proposer: g[2].address(),
                executable_at: at
            },
            BridgeEvent::Minted {
                lock_id: lock(5),
                to,
                amount
            },
        ]
    );
}

#[tokio::test]
async fn pause_and_rotation_through_admin_signatures() {
    let Some(env) = setup(3, 2, MintMode::Threshold { k: 2 }).await else {
        return;
    };
    let c = &env.client;
    let g = &env.guardians;
    let bridge = env.dep.bridge;

    let n0 = c.admin_nonce().await.unwrap();
    let d = eip712::set_paused_digest(31337, bridge, true, n0);
    c.set_paused(true, &sigs(&[&g[0], &g[1]], d)).await.unwrap();
    assert!(c.paused().await.unwrap());
    let to = Address::repeat_byte(1);
    let md = c.mint_digest(lock(1), U256::from(1), to);
    let e = c
        .mint(lock(1), U256::from(1), to, &sigs(&[&g[0], &g[1]], md))
        .await
        .unwrap_err();
    assert!(reason(e).contains("EnforcedPause"));

    // Rotate to {g2, g1} with threshold 1 (works while paused), then unpause with the new set.
    let set = vec![g[2].address(), g[1].address()];
    let n1 = c.admin_nonce().await.unwrap();
    assert_eq!(n1, n0 + U256::from(1));
    let d = eip712::set_guardians_digest(31337, bridge, &set, 1, n1);
    c.set_guardians(&set, 1, &sigs(&[&g[1], &g[2]], d))
        .await
        .unwrap();
    let gs = c.guardian_set().await.unwrap();
    assert_eq!(
        (gs.guardians, gs.threshold, gs.admin_nonce),
        (set, 1, n1 + U256::from(1))
    );
    assert!(!c.is_guardian(g[0].address()).await.unwrap());

    let d = eip712::set_paused_digest(31337, bridge, false, n1 + U256::from(1));
    c.set_paused(false, &sigs(&[&g[2]], d)).await.unwrap();
    c.mint(lock(1), U256::from(1), to, &sigs(&[&g[2]], md))
        .await
        .unwrap();

    mine(c.provider(), 2).await;
    let fin = c.finalized_block_number().await.unwrap();
    let events: Vec<BridgeEvent> = c
        .scan(env.dep.deploy_block, fin)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(events.contains(&BridgeEvent::Paused {
        paused: true,
        account: env.deployer.address()
    }));
    assert!(events.contains(&BridgeEvent::Paused {
        paused: false,
        account: env.deployer.address()
    }));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, BridgeEvent::GuardiansChanged { .. }))
            .count(),
        2
    );
}

#[tokio::test]
async fn connect_checks_and_finality_modes() {
    let Some(env) = setup(1, 1, MintMode::Threshold { k: 1 }).await else {
        return;
    };

    let mut cfg = EthConfig::new(env.anvil.endpoint(), 1, env.dep.bridge);
    assert!(matches!(
        EthClient::connect(&cfg, None).await,
        Err(Error::WrongChain {
            expected: 1,
            got: 31337
        })
    ));

    cfg.chain_id = 31337;
    cfg.token = Some(Address::repeat_byte(0xEE));
    assert!(matches!(
        EthClient::connect(&cfg, None).await,
        Err(Error::NoCode(_))
    ));

    // The token's address as the "bridge": it has code but no token() -> an RPC/revert error.
    let mut cfg2 = EthConfig::new(env.anvil.endpoint(), 31337, env.dep.token);
    cfg2.token = None;
    assert!(EthClient::connect(&cfg2, None).await.is_err());

    // Read-only clients do not send.
    cfg.token = None;
    let ro = EthClient::connect(&cfg, None).await.unwrap();
    assert_eq!(ro.token_address(), env.dep.token);
    assert!(matches!(
        ro.burn(U256::from(1), B256::ZERO).await,
        Err(Error::ReadOnly)
    ));

    // Depth finality.
    let p = ro.provider().clone();
    mine(&p, 5).await;
    let latest = ro.latest_block_number().await.unwrap();
    cfg.finality = Finality::Depth { depth: 3 };
    let depth = EthClient::connect(&cfg, None).await.unwrap();
    assert_eq!(depth.finalized_block_number().await.unwrap(), latest - 3);
    cfg.finality = Finality::Finalized {
        fallback_depth: Some(100),
    };
    let tagged = EthClient::connect(&cfg, None).await.unwrap();
    assert_eq!(tagged.finalized_block_number().await.unwrap(), latest - 2);

    // The deployment file round-trips.
    let path = std::env::temp_dir().join(format!("hawkeye-eth-deploy-{}.json", std::process::id()));
    env.dep.write(&path).unwrap();
    assert_eq!(Deployment::read(&path).unwrap(), env.dep);
    std::fs::remove_file(&path).unwrap();
}
