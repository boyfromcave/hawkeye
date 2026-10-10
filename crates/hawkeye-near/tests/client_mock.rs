//! The `wyec-near` client against the mock NEAR node (feature `mock`): views, the relayer's
//! calls and nonces, panic mapping, and the block scanner.

use hawkeye_core::near::{BridgeMessage, Domain, guardian_key_of, sign_digest};
use hawkeye_core::{AccountId, SecretKey};
use hawkeye_near::contract::{DEFAULT_GAS, ProposalStatus};
use hawkeye_near::mock::{Contract, MockNear, MockState};
use hawkeye_near::{KeyFile, NearEvent, WyecNear};
use serde_json::json;

const WINDOW: u64 = 60;

fn guardian(i: u8) -> SecretKey {
    SecretKey::from_bytes(&[i; 32]).unwrap()
}

fn domain() -> Domain {
    Domain::new("sandbox", AccountId::parse("wyec.test.near").unwrap()).unwrap()
}

fn relayer(name: &str, seed: u8) -> KeyFile {
    KeyFile::from_seed(AccountId::parse(name).unwrap(), &[seed; 32])
}

async fn setup(threshold: u8) -> (MockNear, WyecNear, KeyFile) {
    let keys: Vec<_> = (1..=3).map(|i| guardian_key_of(&guardian(i))).collect();
    let contract = Contract::new("sandbox", keys, threshold, WINDOW, 0, 0);
    let mut st = MockState::new(domain(), contract);
    let r = relayer("relayer.test.near", 7);
    st.add_access_key(r.account_id.as_str(), r.public_key());
    let mock = MockNear::start(st).await.unwrap();
    let c = WyecNear::new(&mock.url(), domain(), Some(r.clone()), DEFAULT_GAS).unwrap();
    (mock, c, r)
}

fn mint_sig(i: u8, lock: &[u8; 32], amount: u128, to: &AccountId) -> [u8; 65] {
    let d = domain().digest(&BridgeMessage::Mint {
        lock_id: *lock,
        amount,
        receiver_id: to.clone(),
    });
    sign_digest(&guardian(i), &d).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn views_calls_and_the_scanner() {
    let (mock, c, r) = setup(2).await;
    let alice = AccountId::parse("alice.test.near").unwrap();
    let (h0, t0) = c.final_head().await.unwrap();
    assert_eq!(h0, 1);
    assert!(t0 > 1_700_000_000);
    assert_eq!(c.threshold().await.unwrap(), 2);
    assert_eq!(c.guardians().await.unwrap().len(), 3);
    assert_eq!(c.mint_available().await.unwrap(), u128::MAX);
    assert_eq!(c.config().await.unwrap().challenge_window_sec, WINDOW);

    // threshold mint: signatures sorted by the recovered key
    let lock = [0x11u8; 32];
    let sigs = vec![
        mint_sig(3, &lock, 500, &alice),
        mint_sig(1, &lock, 500, &alice),
    ];
    let digest = domain().digest(&BridgeMessage::Mint {
        lock_id: lock,
        amount: 500,
        receiver_id: alice.clone(),
    });
    let sorted = hawkeye_near::contract::sort_signatures(&digest, &sigs).unwrap();
    let m = c.mint(&lock, 500, &alice, &sorted).await.unwrap();
    assert!(m.height > h0);
    assert!(c.is_consumed(&lock).await.unwrap());
    assert_eq!(c.balance_of(&alice).await.unwrap(), 500);
    // unsorted signatures are refused by the contract (a panic, named)
    let lock2 = [0x22u8; 32];
    let mut bad = vec![
        mint_sig(1, &lock2, 5, &alice),
        mint_sig(3, &lock2, 5, &alice),
    ];
    let d2 = domain().digest(&BridgeMessage::Mint {
        lock_id: lock2,
        amount: 5,
        receiver_id: alice.clone(),
    });
    let good = hawkeye_near::contract::sort_signatures(&d2, &bad).unwrap();
    if good == bad {
        bad.reverse();
    }
    let e = c.mint(&lock2, 5, &alice, &bad).await.unwrap_err();
    assert_eq!(e.revert_name(), Some("SignersNotAscending"), "{e}");
    let e = c.mint(&lock, 500, &alice, &sorted).await.unwrap_err();
    assert_eq!(e.revert_name(), Some("LockConsumed"), "{e}");

    // optimistic: propose, a second proposal is refused, challenge, veto
    let lock3 = [0x33u8; 32];
    let (p, id) = c
        .propose_mint(&lock3, 700, &alice, &mint_sig(2, &lock3, 700, &alice))
        .await
        .unwrap();
    assert_eq!(id, 1);
    let prop = c.proposal(&lock3).await.unwrap().unwrap();
    assert_eq!(prop.proposer, guardian_key_of(&guardian(2)));
    assert_eq!(
        c.proposal_status(&lock3).await.unwrap(),
        ProposalStatus::Pending
    );
    let e = c
        .propose_mint(&lock3, 700, &alice, &mint_sig(1, &lock3, 700, &alice))
        .await
        .unwrap_err();
    assert_eq!(e.revert_name(), Some("ProposalPending"));
    let e = c.execute_mint(&lock3).await.unwrap_err();
    assert_eq!(e.revert_name(), Some("ChallengeWindowOpen"));
    let ch = domain().digest(&BridgeMessage::Challenge {
        lock_id: lock3,
        proposal_id: id,
    });
    c.challenge_mint(&lock3, id, &sign_digest(&guardian(3), &ch).unwrap())
        .await
        .unwrap();
    assert!(c.proposal(&lock3).await.unwrap().is_none());
    assert!(
        c.is_vetoed(&lock3, &guardian_key_of(&guardian(2)))
            .await
            .unwrap()
    );
    let e = c
        .challenge_mint(&lock3, id, &sign_digest(&guardian(3), &ch).unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.revert_name(), Some("NoProposal"));

    // a re-proposal by another guardian, executed after the window
    let (_, id2) = c
        .propose_mint(&lock3, 700, &alice, &mint_sig(1, &lock3, 700, &alice))
        .await
        .unwrap();
    mock.state().warp(WINDOW);
    assert_eq!(
        c.proposal_status(&lock3).await.unwrap(),
        ProposalStatus::Ready
    );
    c.execute_mint(&lock3).await.unwrap();
    assert_eq!(c.balance_of(&alice).await.unwrap(), 1200);

    // a burn from the relayer: needs a balance; the deposit is read from the contract
    let e = c.burn(1, &[1; 32]).await.unwrap_err();
    assert!(e.to_string().contains("is not registered"), "{e}");
    {
        let mut st = mock.state();
        st.contract.balances.insert(r.account_id.to_string(), 300);
        st.contract.total_supply += 300;
    }
    let (b, nonce) = c.burn(200, &[0x77; 32]).await.unwrap();
    assert_eq!(nonce, 0);
    mock.state().skip_heights(3);
    mock.state().produce_blocks(2);

    // the scan sees every event, in order, with the right ids
    let (fin, _) = c.final_head().await.unwrap();
    let out = c.scan(1, fin).await.unwrap();
    let kinds: Vec<&str> = out
        .events
        .iter()
        .map(|e| match &e.event {
            NearEvent::Minted { .. } => "minted",
            NearEvent::Proposed { .. } => "proposed",
            NearEvent::Challenged { .. } => "challenged",
            NearEvent::Burn(_) => "burn",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "minted",
            "proposed",
            "challenged",
            "proposed",
            "minted",
            "burn"
        ]
    );
    match &out.events[1].event {
        NearEvent::Proposed {
            proposal_id,
            proposer,
            eta,
            amount,
            ..
        } => {
            assert_eq!((*proposal_id, *amount), (1, 700));
            assert_eq!(*proposer, guardian_key_of(&guardian(2)));
            assert_eq!(*eta, prop.eta);
        }
        e => panic!("{e:?}"),
    }
    assert_eq!(out.events[1].height, p.height);
    match &out.events[2].event {
        NearEvent::Challenged {
            challenger,
            proposal_id,
            ..
        } => {
            assert_eq!(*challenger, guardian_key_of(&guardian(3)));
            assert_eq!(*proposal_id, 1);
        }
        e => panic!("{e:?}"),
    }
    match &out.events[3].event {
        NearEvent::Proposed { proposal_id, .. } => assert_eq!(*proposal_id, id2),
        e => panic!("{e:?}"),
    }
    match &out.events[4].event {
        NearEvent::Minted {
            amount,
            receiver_id,
            ..
        } => assert_eq!((*amount, receiver_id), (700, &alice)),
        e => panic!("{e:?}"),
    }
    match &out.events[5].event {
        NearEvent::Burn(rec) => {
            assert_eq!(
                (rec.nonce, rec.amount, rec.from.clone()),
                (0, 200, r.account_id.clone())
            );
            assert_eq!(out.events[5].id, rec.hash());
            assert_eq!(rec.block_height, b.height);
        }
        e => panic!("{e:?}"),
    }
    assert_eq!(out.to_hash, mock.state().head().hash);
    // the mint signatures of the proposal and of the threshold mint are recoverable
    assert_eq!(
        c.receipt_signatures(&out.events[0].id).await.unwrap().len(),
        2
    );
    assert_eq!(
        c.receipt_signatures(&out.events[1].id).await.unwrap(),
        vec![mint_sig(2, &lock3, 700, &alice).to_vec()]
    );
    assert!(c.receipt_signatures(&[9; 32]).await.unwrap().is_empty());
    // a range ending on a skipped height has no hash; empty ranges are empty
    let skipped = b.height + 1;
    let out = c.scan(skipped, skipped).await.unwrap();
    assert!(out.events.is_empty());
    assert_eq!(out.to_hash, [0; 32]);
    // a pruned (non-archival) range is an error, never a silent gap
    mock.state().pruned_below = 3;
    let e = c.scan(1, fin).await.unwrap_err();
    assert!(e.to_string().contains("archival"), "{e}");
    assert!(c.scan(3, fin).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn nonces_are_sequential_and_a_refused_one_is_retried() {
    let (mock, c, r) = setup(1).await;
    let alice = AccountId::parse("alice.test.near").unwrap();
    for i in 0..3u8 {
        let lock = [i; 32];
        c.mint(&lock, 1, &alice, &[mint_sig(1, &lock, 1, &alice)])
            .await
            .unwrap();
    }
    let nonce = |m: &MockNear| m.state().access_keys[&(r.account_id.to_string(), r.public_key())];
    assert_eq!(nonce(&mock), 3);
    // another process used nonces meanwhile: the node refuses, the client re-reads and retries
    mock.state().send_errors.push(json!({"name": "HANDLER_ERROR",
        "cause": {"name": "INVALID_TRANSACTION", "info": {}}, "code": -32000,
        "message": "Server error",
        "data": {"TxExecutionError": {"InvalidTxError": {"InvalidNonce": {"tx_nonce": 4, "ak_nonce": 9}}}}}));
    let lock = [9u8; 32];
    c.mint(&lock, 1, &alice, &[mint_sig(1, &lock, 1, &alice)])
        .await
        .unwrap();
    assert_eq!(nonce(&mock), 4);
    assert_eq!(mock.state().calls_to("send_tx"), 5);
    // a read-only client cannot send
    let ro = WyecNear::new(&mock.url(), domain(), None, DEFAULT_GAS).unwrap();
    assert!(ro.execute_mint(&lock).await.is_err());
    // an unknown key is refused by the node, not retried
    let stranger = WyecNear::new(
        &mock.url(),
        domain(),
        Some(relayer("stranger.test.near", 9)),
        DEFAULT_GAS,
    )
    .unwrap();
    assert!(stranger.execute_mint(&lock).await.is_err());
    // a view panic is named like a call's
    let e = c
        .view("is_consumed", json!({"lock_id": "zz"}))
        .await
        .unwrap_err();
    assert_eq!(e.revert_name(), Some("BadLockId"), "{e}");
}
