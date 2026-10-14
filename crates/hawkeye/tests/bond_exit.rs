//! `hawkeye leave` and `hawkeye withdraw-bond` against the mock ycashd (owner 2026-10-11, quantum
//! plan D-Q-29..D-Q-31, plan §2.4): an ACTIVE member's bond is locked; leaving starts the exit
//! delay; the withdrawal is refused until `exitheight + maturity`, then signed by the member key
//! over the bond's redeem script and accepted; a frozen bond is refused.

use hawkeye::cli::{build_bond_withdrawal, leave_set, withdraw_bond_with};
use hawkeye_core::SecretKey;
use hawkeye_core::template::bond_redeem;
use hawkeye_ycash::mock::{MockState, MockYcashd};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{BuildAct, MemberStatus, SetParams};
use hawkeye_ycash::{Amount, Hash256, PubKey};

fn key(i: u8) -> SecretKey {
    let mut s = [0u8; 32];
    s[0] = 0x42;
    s[31] = i;
    SecretKey::from_bytes(&s).unwrap()
}

/// A three-member set (maturity 4) of real keys, all in the mock wallet.
async fn setup() -> (MockYcashd, Hash256, Vec<SecretKey>) {
    let mut st = MockState::new();
    let admit = st.new_wallet_key();
    let set = st.add_set(SetParams {
        seats: 3,
        unlockthreshold: 1,
        cancelthreshold: 1,
        slashthreshold: 2,
        open: false,
        ratelimitbps: 0,
        ratewindow: 20,
        livenesswindow: 1000,
        bondmin: Amount(100_000_000),
        bondlockmin: 0,
        maturity: 4,
        admitkey: admit,
    });
    let keys: Vec<SecretKey> = (1..=3).map(key).collect();
    for k in &keys {
        st.add_member(&set, PubKey(k.public_key()), true);
    }
    st.mine(1);
    (MockYcashd::start_with(st).await.unwrap(), set, keys)
}

fn mine_to_bond_lock(m: &MockYcashd, set: &Hash256, k: &SecretKey) {
    let mut st = m.state();
    let lock = st.sets[set]
        .memberlist
        .iter()
        .find(|mb| mb.key.0 == k.public_key())
        .unwrap()
        .bondlocktime;
    while st.tip_height() < lock {
        st.mine(1);
    }
}

#[tokio::test]
async fn leave_then_withdraw_after_the_exit_delay() {
    let (m, set, keys) = setup().await;
    let c = m.client();
    let me = &keys[0];
    mine_to_bond_lock(&m, &set, me); // the bond script's CLTV is past: only the exit delay holds it
    // ACTIVE: refused before anything is built
    let e = withdraw_bond_with(&c, me, &set, None).await.unwrap_err();
    assert!(e.to_string().contains("hawkeye leave"), "{e}");
    // leave
    let r = leave_set(&c, me, &set).await.unwrap();
    let exit = r["exitheight"].as_u64().unwrap() as u32;
    assert_eq!(r["bondspendableat"].as_u64().unwrap() as u32, exit + 4);
    assert_eq!(r["maturity"], 4);
    m.state().mine(1);
    let e = leave_set(&c, me, &set).await.unwrap_err();
    assert!(e.to_string().contains("nothing to leave"), "{e}");
    // in the exit delay: the node refuses
    let e = withdraw_bond_with(&c, me, &set, None).await.unwrap_err();
    assert!(format!("{e:#}").contains("exit delay"), "{e:#}");
    while m.state().next_height() < exit + 4 {
        m.state().mine(1);
    }
    let r = withdraw_bond_with(&c, me, &set, None).await.unwrap();
    assert_eq!(r["value_zat"], 100_000_000 - 10_000);
    // the transaction in the mempool spends the bond with a valid member-key signature
    let (tx, bond) = {
        let st = m.state();
        let txid = st.mempool[0];
        let tx = Transaction::decode(&st.txs[&txid].0).unwrap();
        let bond = st.sets[&set]
            .memberlist
            .iter()
            .find(|mb| mb.key.0 == me.public_key())
            .unwrap()
            .clone();
        (tx, bond)
    };
    assert_eq!(tx.inputs[0].prevout, bond.bondoutpoint);
    assert_eq!(tx.inputs[0].sequence, 0xffff_fffe);
    assert!(tx.lock_time >= bond.bondlocktime);
    let pushes = hawkeye_core::script::push_values(&tx.inputs[0].script_sig).unwrap();
    let redeem = bond_redeem(&me.public_key(), bond.bondlocktime);
    assert_eq!(pushes[1], redeem);
    let (der, ht) = pushes[0].split_at(pushes[0].len() - 1);
    assert_eq!(ht, [1]);
    let mut unsigned = tx.clone();
    unsigned.inputs[0].script_sig.clear();
    let core = hawkeye_core::tx::Transaction::parse(&unsigned.encode()).unwrap();
    let digest = hawkeye_core::sighash::zip243(
        &core,
        0,
        &redeem,
        100_000_000,
        1,
        u32::from_str_radix(hawkeye_ycash::mock::VAULT_BRANCH_ID, 16).unwrap(),
    )
    .unwrap();
    assert!(hawkeye_core::setsig::verify_der(
        &me.public_key(),
        &digest,
        der
    ));
    // mined: the bond is gone, the member stays removed
    m.state().mine(1);
    let e = withdraw_bond_with(&c, me, &set, None).await.unwrap_err();
    assert!(e.to_string().contains("already spent"), "{e}");
}

#[tokio::test]
async fn a_member_slashed_in_its_exit_delay_cannot_withdraw() {
    let (m, set, keys) = setup().await;
    let c = m.client();
    let rogue = &keys[1];
    mine_to_bond_lock(&m, &set, rogue);
    leave_set(&c, rogue, &set).await.unwrap();
    m.state().mine(1);
    // the others co-sign SET_REMOVE burn=1 of the member that already left
    let built = c
        .set_buildact(&BuildAct::Remove {
            setid: set,
            memberkey: PubKey(rogue.public_key()),
            burn: true,
        })
        .await
        .unwrap();
    let signed = c.set_signact(&built.hex, Some(&set)).await.unwrap();
    assert!(signed.complete);
    c.set_sendact(&signed.hex).await.unwrap();
    m.state().mine(6);
    let mb = c
        .set_getinfo(&set, None)
        .await
        .unwrap()
        .memberlist
        .into_iter()
        .find(|mb| mb.key.0 == rogue.public_key())
        .unwrap();
    assert_eq!((mb.status, mb.bondfrozen), (MemberStatus::Removed, true));
    let e = withdraw_bond_with(&c, rogue, &set, None).await.unwrap_err();
    assert!(e.to_string().contains("frozen"), "{e}");
}

#[test]
fn the_withdrawal_refuses_a_foreign_bond_script() {
    let k = key(7);
    let other = key(8);
    let op = hawkeye_ycash::OutPoint::new(Hash256([5; 32]), 0);
    let spk = hawkeye_core::template::bond_spk(&other.public_key(), 10);
    let e = build_bond_withdrawal(&k, &op, 10, &spk, 100_000_000, vec![0x51], 20, 0x6d5b_7a31)
        .unwrap_err();
    assert!(
        e.to_string().contains("not this member key's bond script"),
        "{e}"
    );
    let spk = hawkeye_core::template::bond_spk(&k.public_key(), 30);
    let e = build_bond_withdrawal(&k, &op, 30, &spk, 100_000_000, vec![0x51], 20, 0x6d5b_7a31)
        .unwrap_err();
    assert!(e.to_string().contains("CLTV"), "{e}");
    let tx = build_bond_withdrawal(
        &k,
        &op,
        10,
        &hawkeye_core::template::bond_spk(&k.public_key(), 10),
        100_000_000,
        vec![0x51],
        20,
        0x6d5b_7a31,
    )
    .unwrap();
    assert_eq!((tx.lock_time, tx.expiry_height), (20, 60));
}

/// A live leader unlock of an unspent vault makes `hawkeye leave` refuse (W4-B-2).
#[tokio::test]
async fn leave_refuses_with_a_live_signed_unlock() {
    use hawkeye::cli::live_unlock_reason;
    use hawkeye_core::{Deployment, EthAddress};
    use hawkeye_store::{SignDomain, UnlockBurn, UnlockOrigin, YcashSignKey};
    use hawkeye_ycash::HexBytes;
    use hawkeye_ycash::types::VaultFields;
    let (m, set, keys) = setup().await;
    let c = m.client();
    let vault = {
        let mut st = m.state();
        let owner = st.new_wallet_owner();
        st.add_vault(
            VaultFields {
                tag: HexBytes(b"WYEC".to_vec()),
                tagtext: "WYEC".into(),
                setid: set,
                cancelsetid: set,
                delay: 1,
                ownerheight: 100_000,
                appheight: 0,
                owner,
                ownerscheme: 1,
            },
            Amount(100_000_000),
        )
    };
    let dir = tempfile::tempdir().unwrap();
    let mut store = hawkeye_store::Store::open(dir.path().join("hawkeye.db")).unwrap();
    let dep = Deployment {
        chain_id: 1,
        bridge: EthAddress([1; 20]),
    };
    let prev = hawkeye_core::OutPoint::new(vault.txid.0, vault.vout);
    let burn = hawkeye_store::BurnKey::new(dep, 3);
    store
        .tx(|t| {
            t.sign_once_unlock(
                &YcashSignKey {
                    domain: SignDomain::YcashUnlock,
                    set_id: set.0,
                    prevout: prev,
                },
                Some(&UnlockBurn {
                    key: burn,
                    origin: UnlockOrigin::Leader,
                    allow_double: false,
                }),
                "aabb",
                |_| Ok::<_, String>(("aabb".into(), [9; 32])),
            )?;
            Ok::<_, hawkeye_store::StoreError>(())
        })
        .unwrap();
    let why = live_unlock_reason(&mut store, set.0, dep, &c, keys[0].public_key())
        .await
        .unwrap()
        .expect("refused");
    assert!(why.contains("burn 3 on vault"), "{why}");
    assert!(why.contains("--with-live-unlocks"), "{why}");
}

/// `--with-live-unlocks` is the same `set_leave` once the operator accepts the cost.
#[tokio::test]
async fn leave_with_live_unlocks_flag_proceeds() {
    use hawkeye::cli::live_unlock_reason;
    use hawkeye_core::{Deployment, EthAddress};
    let (m, set, keys) = setup().await;
    let c = m.client();
    let dir = tempfile::tempdir().unwrap();
    let mut store = hawkeye_store::Store::open(dir.path().join("hawkeye.db")).unwrap();
    let dep = Deployment {
        chain_id: 1,
        bridge: EthAddress([1; 20]),
    };
    assert!(
        live_unlock_reason(&mut store, set.0, dep, &c, keys[0].public_key())
            .await
            .unwrap()
            .is_none()
    );
    leave_set(&c, &keys[0], &set).await.expect("leave proceeds");
}
