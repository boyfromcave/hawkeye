//! The client against the mock ycashd: request shapes, result shapes, error mapping, and the
//! bridge flows of plan §1 (lock → unlock with the memo → release; cancel; acts).

use hawkeye_ycash::mock::{MockState, MockYcashd};
use hawkeye_ycash::stock::Unspent;
use hawkeye_ycash::tx::{self, Transaction};
use hawkeye_ycash::types::*;
use hawkeye_ycash::{Amount, Auth, Error, ErrorReason, HexBytes, PubKey, YcashRpc};
use serde_json::json;

fn set_params(admit: PubKey, ratelimitbps: u32) -> SetParams {
    SetParams {
        seats: 3,
        unlockthreshold: 1,
        cancelthreshold: 1,
        slashthreshold: 2,
        open: false,
        ratelimitbps,
        ratewindow: 20,
        livenesswindow: 60,
        bondmin: Amount(100_000_000),
        bondlockmin: 0,
        maturity: 2,
        admitkey: admit,
    }
}

/// A set with three members, all in the mock wallet, and a confirmed WYEC vault of 10 YEC.
async fn bridge(ratelimitbps: u32) -> (MockYcashd, SetId, hawkeye_ycash::OutPoint) {
    let m = MockYcashd::start().await.unwrap();
    let (set, vault) = {
        let mut s = m.state();
        let admit = s.new_wallet_key();
        let set = s.add_set(set_params(admit, ratelimitbps));
        for _ in 0..3 {
            let k = s.new_wallet_key();
            s.add_member(&set, k, true);
        }
        let owner = s.new_wallet_key();
        let fields = VaultFields {
            tag: HexBytes(b"WYEC".to_vec()),
            tagtext: "WYEC".into(),
            setid: set,
            cancelsetid: set,
            delay: 6,
            ownerheight: 400,
            appheight: 0,
            ownerkey: owner,
        };
        let v = s.add_vault(fields, Amount(1_000_000_000));
        s.mine(1);
        (set, v)
    };
    (m, set, vault)
}

use hawkeye_ycash::primitives::SetId;

fn rpc_reason(e: &Error) -> ErrorReason {
    e.reason()
        .unwrap_or_else(|| panic!("no documented reason in {e}"))
}

#[tokio::test]
async fn burn_release_flow_with_memo() {
    let (m, set, vault) = bridge(0).await;
    let c = m.client();
    let info = c.vault_getinfo().await.unwrap();
    assert_eq!(info.branchid, "6d5b7a31");
    assert!(info.active);
    assert_eq!(info.lockedvalue, Some(Amount(1_000_000_000)));

    let rows = c
        .vault_list(Some(&VaultListFilter {
            tag: Some("WYEC".into()),
            kind: Some(TemplateKind::Vault),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outpoint(), vault);

    let recipient = c.getnewaddress().await.unwrap();
    let amount: Amount = "4.00000001".parse().unwrap();
    let built = c
        .vault_buildunlock(&vault, &[Recipient::address(recipient.clone(), amount)])
        .await
        .unwrap();
    assert_eq!(built.required, 1);
    assert_eq!(built.intents[0].amount, amount);
    // the request carried the amount exactly, as a decimal string
    let call = m.state().calls_to("vault_buildunlock")[0].clone();
    assert_eq!(
        call.params[1],
        json!([{"address": recipient, "amount": "4.00000001"}])
    );

    // the memo goes in before any signature
    let memo = {
        let mut d = b"HKB1\x01".to_vec();
        d.extend(31337u64.to_le_bytes());
        d.extend([0x11; 20]);
        d.extend(7u64.to_le_bytes());
        d.extend([0x22; 32]);
        d
    };
    // plan §4.3: 4 + 1 + 8 + 20 + 8 + 32 = 73 bytes, script `6a 49 …`
    assert_eq!(memo.len(), 73);
    let with_memo: HexBytes = tx::insert_op_return(&built.hex.to_string(), &memo)
        .unwrap()
        .parse()
        .unwrap();
    let signed = c.set_signunlock(&with_memo).await.unwrap();
    assert!(signed.complete);
    assert_eq!(
        (signed.signatures, signed.required, signed.setsigs.len()),
        (1, 1, 1)
    );
    // a signed transaction no longer takes a memo
    assert!(matches!(
        tx::insert_op_return(&signed.hex.to_string(), b"x"),
        Err(tx::CodecError::AlreadyHasOpReturn(_))
    ));
    let txid = c.vault_send(&signed.hex).await.unwrap();
    assert_eq!(c.getrawmempool().await.unwrap(), vec![txid]);
    let blocks = c.generate(1).await.unwrap();

    // the intent is indexed; the block carries the memo
    let intents = c
        .vault_list(Some(&VaultListFilter {
            setid: Some(set),
            kind: Some(TemplateKind::Intent),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(intents.len(), 1);
    let i = intents[0].as_intent().unwrap().clone();
    assert_eq!(i.value, amount);
    assert_eq!(i.fields.recipienthash, built.intents[0].recipienthash);
    assert!(!i.mature && i.cancellable);
    let relock = c
        .vault_list(Some(&VaultListFilter {
            kind: Some(TemplateKind::Vault),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(relock[0].valuezat(), 1_000_000_000 - amount.zat());
    let block = c.getblock_txs(&blocks[0]).await.unwrap();
    let t = block
        .tx
        .iter()
        .find(|t| t.txid == txid)
        .unwrap()
        .decode()
        .unwrap()
        .unwrap();
    assert_eq!(t.txid(), txid);
    assert_eq!(
        t.op_returns().collect::<Vec<_>>(),
        vec![(t.outputs.len() - 1, &memo[..])]
    );

    // release: refused before maturity, then paid
    let e = c.vault_release(&i.outpoint, None).await.unwrap_err();
    assert_eq!(
        rpc_reason(&e),
        ErrorReason::NotMature {
            height: Some(i.matureheight)
        }
    );
    assert_eq!(e.rpc().unwrap().matures_at_height(), Some(i.matureheight));
    c.generate(5).await.unwrap();
    let rel = c
        .vault_release(&i.outpoint, Some(&recipient))
        .await
        .unwrap();
    c.generate(1).await.unwrap();
    let tx = c.getrawtransaction_verbose(&rel, None).await.unwrap();
    assert_eq!(tx.vout[0].value, amount);
    assert_eq!(tx.vin[0].sequence, 6, "RELEASE nSequence = delay");
    assert!(
        c.vault_list(Some(&VaultListFilter {
            kind: Some(TemplateKind::Intent),
            ..Default::default()
        }))
        .await
        .unwrap()
        .is_empty()
    );
}

#[tokio::test]
async fn sign_once_is_enforced_and_reported() {
    let (m, _set, vault) = bridge(0).await;
    let c = m.client();
    let a = c.getnewaddress().await.unwrap();
    let u1 = c
        .vault_buildunlock(&vault, &[Recipient::address(a.clone(), Amount(100))])
        .await
        .unwrap();
    let s1 = c.set_signunlock(&u1.hex).await.unwrap();
    // the identical transaction again: idempotent
    let again = c.set_signunlock(&u1.hex).await.unwrap();
    assert_eq!(again.sighash, s1.sighash);
    // a different spend of the same vault: set-sign-once
    let u2 = c
        .vault_buildunlock(&vault, &[Recipient::address(a, Amount(200))])
        .await
        .unwrap();
    let e = c.set_signunlock(&u2.hex).await.unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::SetSignOnce);
    assert!(e.rpc().unwrap().is_set_sign_once());
    assert_eq!(e.rpc().unwrap().code, -4);
}

#[tokio::test]
async fn watcher_cancels_a_mempool_intent() {
    let (m, set, vault) = bridge(0).await;
    let c = m.client();
    let rogue = c.getnewaddress().await.unwrap();
    let u = c
        .vault_buildunlock(&vault, &[Recipient::address(rogue, Amount(300_000_000))])
        .await
        .unwrap();
    let s = c.set_signunlock(&u.hex).await.unwrap();
    let txid = c.vault_send(&s.hex).await.unwrap();
    let intent = hawkeye_ycash::OutPoint::new(txid, u.intents[0].vout);
    // from the mempool (finding (65)): intentconfirmed false, same transaction on a second call
    let x1 = c.vault_buildcancel(&intent).await.unwrap();
    assert!(!x1.intentconfirmed);
    assert_eq!(x1.cancelsetid, set);
    assert_eq!(x1.deadline, m.state().next_height() + 6 - 1);
    let x2 = c.vault_buildcancel(&intent).await.unwrap();
    assert_eq!(x1.hex, x2.hex, "one cancel per intent");
    let sc = c.set_signcancel(&x1.hex).await.unwrap();
    assert!(sc.complete);
    // signing the unlock path of an intent spend is refused with the documented reason
    let e = c.set_signunlock(&x1.hex).await.unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::TemplateNotVault);
    c.vault_send(&sc.hex).await.unwrap();
    c.generate(1).await.unwrap();
    let all = c
        .vault_list(Some(&VaultListFilter {
            setid: Some(set),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        all.iter().all(|t| t.as_vault().is_some()),
        "the intent was cancelled back into a vault"
    );
    assert_eq!(
        all.iter().map(TemplateOut::valuezat).sum::<i64>(),
        1_000_000_000
    );

    // past the window: the documented refusal
    let u = c
        .vault_buildunlock(&all[0].outpoint(), &[Recipient::address("tmX", Amount(1))])
        .await
        .unwrap();
    let s = c.set_signunlock(&u.hex).await.unwrap();
    let t = c.vault_send(&s.hex).await.unwrap();
    c.generate(7).await.unwrap();
    let e = c
        .vault_buildcancel(&hawkeye_ycash::OutPoint::new(t, 0))
        .await
        .unwrap_err();
    assert!(e.rpc().unwrap().is_cancel_window_closed());
    assert!(matches!(
        rpc_reason(&e),
        ErrorReason::CannotCancel {
            matured_at: Some(_)
        }
    ));
}

#[tokio::test]
async fn incomplete_or_rate_limited_spends_are_rejected() {
    let (m, _set, vault) = bridge(5000).await;
    let c = m.client();
    c.generate(20).await.unwrap(); // a new epoch: basis = locked value (10 YEC), cap 5 YEC
    let set = c.set_list().await.unwrap().remove(0);
    assert_eq!(set.unlockavailable, Some(Amount(500_000_000)));
    let u = c
        .vault_buildunlock(&vault, &[Recipient::address("tmA", Amount(600_000_000))])
        .await
        .unwrap();
    // unsigned
    let e = c.vault_send(&u.hex).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().code, -26);
    let s = c.set_signunlock(&u.hex).await.unwrap();
    let e = c.vault_send(&s.hex).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().bad_vault(), Some("bad-txns-vault-rate"));
    assert_eq!(
        rpc_reason(&e),
        ErrorReason::Rejected {
            code: 16,
            reason: "bad-txns-vault-rate".into()
        }
    );
}

#[tokio::test]
async fn acts_create_join_heartbeat_remove_equivocate() {
    let m = MockYcashd::start().await.unwrap();
    let c = m.client();
    let created = c
        .set_create(&SetCreateParams {
            seats: 3,
            unlockthreshold: 1,
            slashthreshold: Some(2),
            maturity: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.txid, created.setid);
    // a set exists from the block after its SET_CREATE
    assert_eq!(
        rpc_reason(&c.set_getinfo(&created.setid, None).await.unwrap_err()),
        ErrorReason::UnknownSet
    );
    c.generate(1).await.unwrap();
    let mut keys = vec![];
    for _ in 0..3 {
        let j = c
            .set_join(&created.setid, Amount(100_000_000), 500, None)
            .await
            .unwrap();
        assert!(j.act.complete, "the wallet holds the admit key");
        assert_eq!(j.bondoutpoint.txid, j.txid.unwrap());
        keys.push(j.memberkey);
    }
    c.generate(1).await.unwrap();
    let e = c
        .set_join(&created.setid, Amount(100_000_000), 500, None)
        .await
        .unwrap_err();
    assert_eq!(e.rpc().unwrap().bad_vault(), Some("bad-vault-act-seats"));
    let info = c.set_getinfo(&created.setid, None).await.unwrap();
    assert_eq!(info.set.current, 3);
    assert!(
        info.memberlist
            .iter()
            .all(|mb| mb.wallet && mb.status == MemberStatus::Active)
    );
    let hb = c.set_heartbeat(&created.setid, None).await.unwrap();
    assert!(keys.contains(&hb.memberkey));

    // remove (burn) through build → sign → send
    let built = c
        .set_buildact(&BuildAct::Remove {
            setid: created.setid,
            memberkey: keys[2],
            burn: true,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            built.acttype,
            built.complete,
            built.signatures,
            built.required
        ),
        (ActType::Remove, false, 0, 2)
    );
    let call = m.state().calls_to("set_buildact")[0].clone();
    assert_eq!(call.params[0], "remove");
    assert_eq!(call.params[1]["burn"], true);
    let e = c.set_sendact(&built.hex).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().bad_vault(), Some("bad-vault-act-sigs"));
    let signed = c
        .set_signact(&built.hex, Some(&created.setid))
        .await
        .unwrap();
    assert!(signed.complete);
    c.set_sendact(&signed.hex).await.unwrap();
    // equivocation by keys[1]
    let sig = |b: u8| {
        let mut s = vec![0x1f];
        s.extend(keys[1].0);
        s.extend([b; 31]);
        HexBytes(s)
    };
    let proof = Proof {
        setid: created.setid,
        prevout: hawkeye_ycash::OutPoint::new(created.txid, 0),
        rolea: 1,
        sighasha: hawkeye_ycash::Bytes32([1; 32]),
        siga: sig(1),
        roleb: 1,
        sighashb: hawkeye_ycash::Bytes32([2; 32]),
        sigb: sig(2),
    };
    c.set_equivocation(&proof).await.unwrap();
    c.generate(1).await.unwrap();
    let info = c.set_getinfo(&created.setid, None).await.unwrap();
    let st = |k: &PubKey| {
        info.memberlist
            .iter()
            .find(|mb| &mb.key == k)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (st(&keys[2]).status, st(&keys[2]).bondfrozen),
        (MemberStatus::Removed, true)
    );
    assert_eq!(st(&keys[1]).status, MemberStatus::Ejected);
    assert_eq!(info.set.current, 1);
    assert_eq!(
        rpc_reason(
            &c.set_buildact(&BuildAct::Winddown {
                setid: hawkeye_ycash::Hash256([9; 32])
            })
            .await
            .unwrap_err()
        ),
        ErrorReason::UnknownSet
    );
    let e = c
        .call_value("set_buildact", vec!["bogus".into(), json!({})])
        .await
        .unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::UnknownActType);
}

#[tokio::test]
async fn owner_and_app_branches() {
    let (m, set, vault) = bridge(0).await;
    let c = m.client();
    let a = c.getnewaddress().await.unwrap();
    let e = c.vault_ownerspend(&vault, &a).await.unwrap_err();
    assert_eq!(
        rpc_reason(&e),
        ErrorReason::OwnerBranchClosed { height: Some(401) }
    );
    let e = c.vault_app(&vault, None).await.unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::NoAppBranch);
    // a lock through the RPC, with an APP branch and an owner height already passed
    let tip = c.getblockcount().await.unwrap();
    let lock = c
        .vault_lock(&VaultLockParams {
            tag: "WYEC".into(),
            setid: set,
            cancelsetid: None,
            delay: 6,
            ownerheight: tip,
            appheight: Some(tip + 3),
            amount: "0.30000001".parse().unwrap(),
            ownerkey: None,
        })
        .await
        .unwrap();
    c.generate(1).await.unwrap();
    let rows = c
        .vault_list(Some(&VaultListFilter {
            mine: Some(true),
            ..Default::default()
        }))
        .await
        .unwrap();
    let mine = rows
        .iter()
        .find(|r| r.outpoint() == lock.outpoint)
        .unwrap()
        .as_vault()
        .unwrap()
        .clone();
    assert_eq!(mine.value.zat(), 30_000_001);
    assert_eq!(mine.fields.appheight, tip + 3);
    let e = c.vault_app(&lock.outpoint, None).await.unwrap_err();
    assert_eq!(
        rpc_reason(&e),
        ErrorReason::AppBranchClosed {
            height: Some(tip + 4)
        }
    );
    c.generate(3).await.unwrap();
    let app = c
        .vault_app(
            &lock.outpoint,
            Some(&[Recipient::script(vec![0x51], Amount(1))]),
        )
        .await
        .unwrap();
    assert_eq!(app.intents.len(), 1);
    let spent = c.vault_ownerspend(&lock.outpoint, &a).await.unwrap();
    assert_eq!(spent.selector, 2);
    let decoded = c.vault_decodescript(&lock.script).await.unwrap();
    assert!(matches!(decoded, DecodedScript::Vault(f) if f.tagtext == "WYEC"));
    assert_eq!(
        c.vault_decodescript(&HexBytes(vec![0x51])).await.unwrap(),
        DecodedScript::None
    );
}

#[tokio::test]
async fn stock_rpcs() {
    let (m, _set, _vault) = bridge(0).await;
    let c = m.client();
    let info = c.getblockchaininfo().await.unwrap();
    assert_eq!(info.chain, "regtest");
    assert_eq!(info.consensus.nextblock, "6d5b7a31");
    assert_eq!(info.upgrades["6d5b7a31"].status, "active");
    assert_eq!(info.difficulty, 1.0);
    let n = c.getblockcount().await.unwrap();
    assert_eq!(info.blocks, n);
    let best = c.getbestblockhash().await.unwrap();
    assert_eq!(c.getblockhash(n).await.unwrap(), best);
    let b = c.getblock(&best).await.unwrap();
    assert_eq!((b.height, b.confirmations), (n, 1));
    assert!(b.previousblockhash.is_some() && b.nextblockhash.is_none());
    assert!(!c.getblock_hex(&best).await.unwrap().0.is_empty());
    // a raw transaction round trip
    let raw = c.getrawtransaction(&b.tx[0]).await.unwrap();
    let t = Transaction::decode(&raw.0).unwrap();
    assert_eq!(t.txid(), b.tx[0]);
    let dec = c.decoderawtransaction(&raw).await.unwrap();
    assert_eq!(dec.txid, b.tx[0]);
    assert_eq!(dec.vout[0].value, Amount(625_000_000));
    assert!(dec.vin[0].coinbase.is_some());
    let v = c
        .getrawtransaction_verbose(&b.tx[0], Some(&best))
        .await
        .unwrap();
    assert_eq!(v.blockhash, Some(best));
    assert_eq!(v.confirmations, Some(1));
    // send, duplicate, mine
    let spend = Transaction::new_v4(
        vec![tx::TxIn {
            prevout: hawkeye_ycash::OutPoint::new(b.tx[0], 0),
            script_sig: vec![],
            sequence: u32::MAX,
        }],
        vec![tx::TxOut {
            value: 1,
            script_pubkey: vec![0x51],
        }],
        0,
        0,
    );
    let signed = c
        .signrawtransaction(
            &HexBytes(spend.encode()),
            None,
            None,
            None,
            Some("6d5b7a31"),
        )
        .await
        .unwrap();
    assert!(signed.complete);
    assert_eq!(
        m.state().calls_to("signrawtransaction")[0].params,
        vec![
            json!(spend.encode_hex()),
            json!(null),
            json!(null),
            json!(null),
            json!("6d5b7a31")
        ]
    );
    let id = c.sendrawtransaction(&signed.hex, false).await.unwrap();
    let e = c.sendrawtransaction(&signed.hex, false).await.unwrap_err();
    assert!(e.rpc().unwrap().is_already_known());
    c.generate(1).await.unwrap();
    let e = c.sendrawtransaction(&signed.hex, true).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().code, -27);
    assert_eq!(
        m.state()
            .calls_to("sendrawtransaction")
            .last()
            .unwrap()
            .params[1],
        json!(true)
    );
    assert_eq!(
        c.getrawtransaction_verbose(&id, None)
            .await
            .unwrap()
            .confirmations,
        Some(1)
    );
    // wallet
    let a = c.getnewaddress().await.unwrap();
    let va = c.validateaddress(&a).await.unwrap();
    assert!(va.isvalid && va.ismine == Some(true));
    assert_eq!(va.script_pub_key.unwrap().0.len(), 25);
    assert!(!c.validateaddress("not valid!").await.unwrap().isvalid);
    let imported = c.importprivkey("cMockWif", "hawkeye", false).await.unwrap();
    assert_eq!(
        m.state().calls_to("importprivkey")[0].params,
        vec![json!("cMockWif"), json!("hawkeye"), json!(false)]
    );
    assert!(imported.starts_with("tm"));
    m.state().unspent.push(Unspent {
        txid: id,
        vout: 0,
        generated: false,
        address: Some(a),
        account: None,
        redeem_script: None,
        script_pub_key: HexBytes(vec![0x51]),
        amount: "20999999.99999999".parse().unwrap(),
        amount_zat: 2_099_999_999_999_999,
        confirmations: 1,
        spendable: true,
    });
    let u = c.listunspent(Some(1), None, None).await.unwrap();
    assert_eq!(
        u[0].amount.zat(),
        u[0].amount_zat,
        "amounts cross the wire exactly"
    );
    assert_eq!(m.state().calls_to("listunspent")[0].params, vec![json!(1)]);
}

#[tokio::test]
async fn errors_injection_http_and_auth() {
    let m = MockYcashd::start().await.unwrap();
    let c = m.client();
    m.state()
        .inject_error("vault_send", -26, "16: bad-vault-act-seats");
    let e = c.vault_send(&HexBytes(vec![0])).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().bad_vault(), Some("bad-vault-act-seats"));
    // canned result in node format (amounts as decimal numbers)
    m.state().queue_result_text(
        "vault_getinfo",
        r#"{"branchid":"6d5b7a31","activationheight":-1,"active":false,"height":7,"dbtip":null}"#,
    );
    let info = c.vault_getinfo().await.unwrap();
    assert_eq!(
        (info.activationheight, info.dbtip, info.sets),
        (-1, None, None)
    );
    // unknown method: HTTP 404 with a JSON-RPC error
    let e = c.call_value("nope", vec![]).await.unwrap_err();
    assert_eq!(e.rpc().unwrap().code, -32601);
    // HTTP failure without a body
    m.state().fail_http(503);
    let e = c.getblockcount().await.unwrap_err();
    assert!(matches!(e, Error::Status { status: 503, .. }) && e.is_transient());
    // a shape mismatch is a decode error naming the method
    m.state().queue_result("getblockcount", json!("x"));
    assert!(
        matches!(c.getblockcount().await.unwrap_err(), Error::Decode { method, .. } if method == "getblockcount")
    );
    // not active
    m.state().activation_height = 100;
    let e = c
        .set_create(&SetCreateParams {
            seats: 1,
            unlockthreshold: 1,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::NotActive);
    m.state().activation_height = 1;
    let e = c
        .set_create(&SetCreateParams {
            seats: 16,
            unlockthreshold: 1,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::SetParamsOutOfRange);
    let e = c
        .call_value("vault_list", vec![json!({"kind": "coin"})])
        .await
        .unwrap_err();
    assert_eq!(rpc_reason(&e), ErrorReason::BadKind);

    // credentials: user/password and a cookie file
    m.state().auth = Some(("__cookie__".into(), "s3cret".into()));
    let e = c.getblockcount().await.unwrap_err();
    assert!(matches!(e, Error::Status { status: 401, .. }));
    assert_eq!(m.client().getblockcount().await.unwrap(), 0);
    let dir = std::env::temp_dir().join(format!("hawkeye-ycash-cookie-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("regtest")).unwrap();
    std::fs::write(dir.join("regtest/.cookie"), "__cookie__:s3cret\n").unwrap();
    let cc = YcashRpc::new(m.url(), Auth::cookie(&dir, "regtest")).unwrap();
    assert_eq!(cc.getblockcount().await.unwrap(), 0);
    std::fs::write(dir.join("regtest/.cookie"), "__cookie__:rotated").unwrap();
    assert!(matches!(
        cc.getblockcount().await.unwrap_err(),
        Error::Status { status: 401, .. }
    ));
    let missing = YcashRpc::new(m.url(), Auth::cookie(dir.join("nope"), "regtest")).unwrap();
    assert!(matches!(
        missing.getblockcount().await.unwrap_err(),
        Error::Cookie { .. }
    ));
    std::fs::remove_dir_all(&dir).unwrap();
    // a dead endpoint is a transport error
    drop(m);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let dead = YcashRpc::with_timeout(
        "http://127.0.0.1:9/",
        Auth::None,
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    let e = dead.getblockcount().await.unwrap_err();
    assert!(matches!(e, Error::Http(_)) && e.is_transient());
}

#[tokio::test]
async fn mock_state_is_shareable() {
    // other crates build their own state and start the mock with it
    let mut s = MockState::new();
    s.activation_height = 5;
    s.mine(3);
    let m = MockYcashd::start_with(s).await.unwrap();
    let c = m.client();
    assert_eq!(c.getblockcount().await.unwrap(), 3);
    let info = c.vault_getinfo().await.unwrap();
    assert!(!info.active && info.dbtip.is_none());
    c.generate(1).await.unwrap();
    let info = c.vault_getinfo().await.unwrap();
    assert!(
        info.active && info.dbtip.is_none(),
        "active at the next block, the database starts at the first active block"
    );
    c.generate(1).await.unwrap();
    assert_eq!(c.vault_getinfo().await.unwrap().dbtip.unwrap().height, 5);
    assert_eq!(m.state().calls.len(), 6);
}
