// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! `[keys] ycash_signing = "self"` against a **real** regtest `ycashd` (remedial report 05/M-1
//! §4.3, §5): the member key never enters the node wallet; Hawkeye makes every set and act
//! signature itself and the node only funds and signs fee inputs.
//!
//! - `SET_JOIN` of a key the wallet does not hold: the member's act signature self-made, the
//!   admit key's added by the wallet (`set_signact`), sent with `set_sendact`;
//! - an UNLOCK self-signed (ZIP-243 sighash, `SetSigMsg`, `sign_compact`), `vault_send`
//!   accepted and mined; `set_signunlock` on the same transaction verifies the signature and
//!   reports the **same sighash** (parity), signing nothing (and recording nothing: no
//!   equivocation);
//! - the hash type is `SIGHASH_ALL|SIGHASH_ANYONECANPAY` (audit 01/V-2): the builds report the
//!   sighash Hawkeye signs, the remembered build is returned again (`reused`), the mined UNLOCK
//!   attributes to the member key (`attribute_template_input`), and the self-signed CANCEL is
//!   re-funded by `vault_refee` (only its fee inputs change, same sighash) and the re-funded
//!   spend is mined with Hawkeye's signature;
//! - a CANCEL of the intent, self-signed, mined;
//! - a `SET_HEARTBEAT` self-signed, mined (the member's `lastact` moves);
//! - `dumpprivkey` of the member key's address fails: the wallet never held it.
//!
//! Run with `HAWKEYE_REGTEST_YCASHD=/path/to/ycashd` (either node line; `-version` ≥ 6 is
//! ycash6), `HAWKEYE_REGTEST_PORT` (p2p port; RPC = +1; default 2470) and optionally
//! `HAWKEYE_REGTEST_DIR` (the data directory's parent). Skipped otherwise.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hawkeye::engine::sign::{
    next_branch_id, same_set_signed_spend, self_sign_act, self_sign_template,
};
use hawkeye_core::address::{Network, encode_address};
use hawkeye_core::attribution::{VAULT_BRANCH_ID, attribute_template_input};
use hawkeye_core::bytes::hash160;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::setsig::Role;
use hawkeye_core::{OutPoint as CoreOutPoint, SecretKey};
use hawkeye_ycash::types::{BuildAct, BuildKind, Recipient};
use hawkeye_ycash::{Amount, Auth, Hash256, HexBytes, OutPoint, PubKey, YcashRpc};
use serde_json::{Value, json};

const UPGRADES: [&str; 6] = [
    "-nuparams=5ba81b19:1",
    "-nuparams=76b809bb:1",
    "-nuparams=374d694f:1",
    "-nuparams=8e471bd6:1",
    "-nuparams=66314da3:1",
    "-nuparams=19bd2d2f:1",
];
const ACTIVATION: u32 = 110;

struct Node {
    child: Child,
    rpc: YcashRpc,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start(bin: &str, dir: &std::path::Path, port: u16) -> Node {
    let version = Command::new(bin).arg("-version").output().unwrap();
    let text = String::from_utf8_lossy(&version.stdout).to_string();
    let major: u32 = text
        .split(" v")
        .nth(1)
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse().ok())
        .unwrap_or(4);
    eprintln!("regtest node: {}", text.lines().next().unwrap_or_default());
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("ycash.conf"),
        format!(
            "regtest=1\nserver=1\nshowmetrics=0\nprinttoconsole=0\nrpcuser=u\nrpcpassword=p\n\
             rpcallowip=127.0.0.1\nlistenonion=0\ndiscover=0\ndnsseed=0\ntxindex=1\n\
             port={port}\nrpcport={}\nbind=127.0.0.1\n",
            port + 1
        ),
    )
    .unwrap();
    let mut args = vec![format!("-datadir={}", dir.display())];
    if major >= 6 {
        args.push("-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025".into());
    }
    args.extend(UPGRADES.iter().map(|s| s.to_string()));
    args.push(format!("-nuparams=6d5b7a31:{ACTIVATION}"));
    let child = Command::new(bin)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let rpc = YcashRpc::new(
        format!("http://127.0.0.1:{}/", port + 1),
        Auth::UserPass {
            user: "u".into(),
            password: "p".to_owned().into(),
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if rpc.getblockcount().await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "ycashd did not start");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Node { child, rpc }
}

/// Wait until the wallet has seen `txid` confirmed: Zcash notifies the wallet of blocks on a
/// separate thread, so right after `generate` a build can still fund from a coin the block
/// spent.
async fn wallet_sees_confirmed(rpc: &YcashRpc, txid: &Hash256) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(t) = rpc
            .call_value("gettransaction", vec![json!(txid.to_string())])
            .await
            && t["confirmations"].as_i64().unwrap_or(0) >= 1
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the wallet never saw {txid} confirmed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn call(rpc: &YcashRpc, m: &str, p: Vec<Value>) -> Value {
    rpc.call_value(m, p)
        .await
        .unwrap_or_else(|e| panic!("{m}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_signed_set_and_act_signatures_on_a_real_node() {
    let Ok(bin) = std::env::var("HAWKEYE_REGTEST_YCASHD") else {
        eprintln!("skipping: HAWKEYE_REGTEST_YCASHD is not set");
        return;
    };
    let port: u16 = std::env::var("HAWKEYE_REGTEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2470);
    let parent = std::env::var("HAWKEYE_REGTEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    std::fs::create_dir_all(&parent).unwrap();
    let tmp = tempfile::tempdir_in(&parent).unwrap();
    let node = start(&bin, tmp.path(), port).await;
    let rpc = &node.rpc;
    rpc.generate(ACTIVATION + 101).await.unwrap();
    // the set: one seat, every threshold 1, the admit key in the wallet
    let created = call(
        rpc,
        "set_create",
        vec![
            json!({"seats": 1, "unlockthreshold": 1, "cancelthreshold": 1,
                    "slashthreshold": 1, "maturity": 2, "bondmin": 1,
                    "ratewindow": 20, "livenesswindow": 1000}),
        ],
    )
    .await;
    let setid: Hash256 = created["setid"].as_str().unwrap().parse().unwrap();
    rpc.generate(1).await.unwrap();
    // the member key: Hawkeye's, never imported
    let member = SecretKey::from_bytes(&[0x5a; 32]).unwrap();
    let me = member.public_key();
    let tip = rpc.getblockcount().await.unwrap();
    let join = rpc
        .set_buildact(&BuildAct::Join {
            setid,
            bondamount: Amount::from_zat(100_000_000),
            bondlocktime: tip + 20,
            memberkey: Some(PubKey(me)),
        })
        .await
        .unwrap();
    let (mine, _, n) = self_sign_act(&member, &join.hex.to_string()).unwrap();
    assert_eq!(n, 1, "the member's own S_1");
    let admitted = rpc
        .set_signact(&mine.parse::<HexBytes>().unwrap(), Some(&setid))
        .await
        .unwrap();
    assert!(admitted.complete, "{admitted:?}");
    rpc.set_sendact(&admitted.hex).await.unwrap();
    rpc.generate(4).await.unwrap(); // current after the set's maturity
    let info = call(rpc, "set_getinfo", vec![json!(setid.to_string())]).await;
    let m = info["memberlist"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["key"] == json!(hex::encode(me)))
        .expect("joined")
        .clone();
    assert_eq!(m["current"], json!(true), "{m}");
    // a vault of the set
    let tip = rpc.getblockcount().await.unwrap();
    let locked = call(
        rpc,
        "vault_lock",
        vec![
            json!({"tag": "WYEC", "setid": setid.to_string(), "delay": 6,
                    "ownerheight": tip + 1000, "amount": 5}),
        ],
    )
    .await;
    let vtxid: Hash256 = locked["txid"].as_str().unwrap().parse().unwrap();
    let vault = OutPoint::new(vtxid, locked["vout"].as_u64().unwrap() as u32);
    rpc.generate(1).await.unwrap();
    wallet_sees_confirmed(rpc, &vtxid).await;
    let core = |op: &OutPoint| CoreOutPoint::new(op.txid.0, op.vout);
    let coin_of = |op: OutPoint| async move {
        let o = rpc
            .gettxout(&op.txid, op.vout, true)
            .await
            .unwrap()
            .unwrap();
        (
            o.script_pub_key.hex.0,
            u64::try_from(o.value.zat()).unwrap(),
        )
    };
    // UNLOCK, self-signed
    let to = rpc.getnewaddress().await.unwrap();
    let built = rpc
        .vault_buildunlock(
            &vault,
            &[Recipient::address(&to, Amount::from_zat(100_000_000))],
        )
        .await
        .unwrap();
    let branch = next_branch_id(rpc).await.unwrap();
    let vault_coin = coin_of(vault).await;
    let out = self_sign_template(
        &member,
        &setid.0,
        Role::Unlock,
        &core(&vault),
        &vault_coin,
        branch,
        1,
        &built.hex.to_string(),
    )
    .unwrap();
    assert!(out.complete);
    assert_eq!(
        built.sighash.0, out.sighash,
        "vault_buildunlock reports the sighash Hawkeye signs (ALL|ANYONECANPAY)"
    );
    assert_eq!(built.build, BuildKind::New);
    let again = rpc
        .vault_buildunlock(
            &vault,
            &[Recipient::address(&to, Amount::from_zat(100_000_000))],
        )
        .await
        .unwrap();
    assert_eq!(again.build, BuildKind::Reused);
    assert_eq!(again.hex, built.hex);
    // parity: the node verifies our signature, reports the same sighash, adds none
    let parity = rpc
        .set_signunlock(&out.hex.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    assert_eq!(
        parity.sighash.0, out.sighash,
        "ZIP-243 sighash parity with the node"
    );
    assert_eq!(parity.signatures, 1);
    assert_eq!(parity.hex.to_string(), out.hex);
    let utxid = rpc
        .vault_send(&out.hex.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    rpc.generate(1).await.unwrap();
    wallet_sees_confirmed(rpc, &utxid).await;
    // the mined UNLOCK attributes to the member key (the node's 0x81 digest)
    let raw = rpc.getrawtransaction(&utxid).await.unwrap();
    let mined = hawkeye_ycash::tx::Transaction::decode(raw.as_slice()).unwrap();
    let idx = hawkeye::engine::sign::input_index(&mined, &core(&vault)).unwrap();
    let a = attribute_template_input(
        raw.as_slice(),
        idx,
        &vault_coin.0,
        vault_coin.1,
        VAULT_BRANCH_ID,
    )
    .unwrap();
    assert_eq!(a.signers.len(), 1);
    assert_eq!(
        a.signers[0].pubkey, me,
        "the unlock attributes to the member"
    );
    assert_eq!(a.sighash, out.sighash);
    let intent = OutPoint::new(utxid, built.intents[0].vout);
    assert!(
        rpc.gettxout(&vault.txid, vault.vout, true)
            .await
            .unwrap()
            .is_none(),
        "the vault is spent"
    );
    // CANCEL, self-signed
    let cancel = rpc.vault_buildcancel(&intent).await.unwrap();
    let branch = next_branch_id(rpc).await.unwrap();
    let intent_coin = coin_of(intent).await;
    let c = self_sign_template(
        &member,
        &setid.0,
        Role::Cancel,
        &core(&intent),
        &intent_coin,
        branch,
        1,
        &cancel.hex.to_string(),
    )
    .unwrap();
    assert_eq!(cancel.sighash.0, c.sighash, "vault_buildcancel's sighash");
    let parity = rpc
        .set_signcancel(&c.hex.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    assert_eq!(parity.sighash.0, c.sighash);
    // the cancel's fee input is spent elsewhere (a stock transaction of this wallet), so the
    // signed cancel can no longer be sent as it is
    let signed: HexBytes = c.hex.parse().unwrap();
    let old = hawkeye_ycash::tx::Transaction::decode(&signed.0).unwrap();
    let fee_in = old
        .inputs
        .iter()
        .find(|i| core(&i.prevout) != core(&intent))
        .unwrap()
        .prevout;
    let fee_coin = rpc
        .gettxout(&fee_in.txid, fee_in.vout, true)
        .await
        .unwrap()
        .expect("the fee input is unspent");
    let sink = rpc.getnewaddress().await.unwrap();
    let raw = call(
        rpc,
        "createrawtransaction",
        vec![
            json!([{"txid": fee_in.txid.to_string(), "vout": fee_in.vout}]),
            json!({ sink: (fee_coin.value.zat() - 10_000) as f64 / 1e8 }),
        ],
    )
    .await;
    let s = call(rpc, "signrawtransaction", vec![raw]).await;
    let spend: Hash256 = call(rpc, "sendrawtransaction", vec![s["hex"].clone()])
        .await
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    rpc.generate(1).await.unwrap();
    wallet_sees_confirmed(rpc, &spend).await;
    let e = rpc.vault_send(&signed).await.unwrap_err();
    eprintln!("the stale cancel: {e}");
    // re-funded (01/V-2): the fee inputs replaced, Hawkeye's signature still valid
    let refunded = rpc.vault_refee(&signed).await.unwrap();
    assert_eq!(
        refunded.sighash.0, c.sighash,
        "vault_refee keeps the sighash"
    );
    assert_eq!(refunded.replaced, vec![fee_in]);
    let new = hawkeye_ycash::tx::Transaction::decode(&refunded.hex.0).unwrap();
    same_set_signed_spend(&old, &new, &core(&intent)).unwrap();
    assert!(
        new.inputs.iter().all(|i| i.prevout != fee_in),
        "the spent coin is gone"
    );
    let ctxid = rpc.vault_send(&refunded.hex).await.unwrap();
    rpc.generate(1).await.unwrap();
    let raw = rpc.getrawtransaction(&ctxid).await.unwrap();
    let mined = hawkeye_ycash::tx::Transaction::decode(raw.as_slice()).unwrap();
    let idx = hawkeye::engine::sign::input_index(&mined, &core(&intent)).unwrap();
    let a = attribute_template_input(
        raw.as_slice(),
        idx,
        &intent_coin.0,
        intent_coin.1,
        VAULT_BRANCH_ID,
    )
    .unwrap();
    assert_eq!(
        a.signers[0].pubkey, me,
        "the re-funded cancel attributes to the member"
    );
    assert!(
        rpc.gettxout(&intent.txid, intent.vout, true)
            .await
            .unwrap()
            .is_none(),
        "the intent is cancelled"
    );
    // SET_HEARTBEAT, self-signed
    let hb = rpc
        .set_buildact(&BuildAct::Heartbeat {
            setid,
            memberkey: PubKey(me),
        })
        .await
        .unwrap();
    let (signed, _, _) = self_sign_act(&member, &hb.hex.to_string()).unwrap();
    rpc.set_sendact(&signed.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    rpc.generate(1).await.unwrap();
    let h = rpc.getblockcount().await.unwrap();
    let info = call(rpc, "set_getinfo", vec![json!(setid.to_string())]).await;
    let m = info["memberlist"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["key"] == json!(hex::encode(me)))
        .unwrap()
        .clone();
    assert_eq!(m["lastact"].as_u64(), Some(u64::from(h)), "{m}");
    // the wallet never held the member key
    let addr = encode_address(&YcashRecipient::p2pkh(hash160(&me)), Network::Regtest);
    let e = rpc
        .call_value("dumpprivkey", vec![json!(addr)])
        .await
        .unwrap_err();
    eprintln!("dumpprivkey {addr}: {e}");
    let _ = rpc.call_value("stop", vec![]).await;
}
