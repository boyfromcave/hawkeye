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
//! - a CANCEL of the intent, self-signed, mined;
//! - a `SET_HEARTBEAT` self-signed, mined (the member's `lastact` moves);
//! - `dumpprivkey` of the member key's address fails: the wallet never held it.
//!
//! Run with `HAWKEYE_REGTEST_YCASHD=/path/to/ycashd` (either node line; `-version` ≥ 6 is
//! ycash6), `HAWKEYE_REGTEST_PORT` (p2p port; RPC = +1; default 2470) and optionally
//! `HAWKEYE_REGTEST_DIR` (the data directory's parent). Skipped otherwise.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hawkeye::engine::sign::{next_branch_id, self_sign_act, self_sign_template};
use hawkeye_core::address::{Network, encode_address};
use hawkeye_core::bytes::hash160;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::setsig::Role;
use hawkeye_core::{OutPoint as CoreOutPoint, SecretKey};
use hawkeye_ycash::types::{BuildAct, Recipient};
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
    let out = self_sign_template(
        &member,
        &setid.0,
        Role::Unlock,
        &core(&vault),
        &coin_of(vault).await,
        branch,
        1,
        &built.hex.to_string(),
    )
    .unwrap();
    assert!(out.complete);
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
    let c = self_sign_template(
        &member,
        &setid.0,
        Role::Cancel,
        &core(&intent),
        &coin_of(intent).await,
        branch,
        1,
        &cancel.hex.to_string(),
    )
    .unwrap();
    let parity = rpc
        .set_signcancel(&c.hex.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    assert_eq!(parity.sighash.0, c.sighash);
    rpc.vault_send(&c.hex.parse::<HexBytes>().unwrap())
        .await
        .unwrap();
    rpc.generate(1).await.unwrap();
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
