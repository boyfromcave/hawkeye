//! The audit log's contents.

mod common;

use common::*;
use hawkeye_store::{BurnState, LockState, ObjectKind, StoreError, VaultState};

#[test]
fn a_lock_lifecycle_is_logged_in_order() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 1, 100)))
        .unwrap();
    let amount = new_lock(1, 100).value_zat;
    s.sign_once_mint(&id, amount, &DEST, &[7; 32], fake_sig)
        .unwrap();
    s.tx(|t| {
        t.transition_lock(&id, LockState::MintSubmitted, None, Some("eth tx 0xab"))?;
        t.transition_lock(&id, LockState::Minted, None, None)?;
        let ev = t.events_for(ObjectKind::Lock, &hex::encode(id))?;
        let got: Vec<_> = ev
            .iter()
            .map(|e| (e.from.as_deref(), e.to.as_str(), e.height))
            .collect();
        assert_eq!(
            got,
            [
                (None, "SEEN", Some(100)),
                (Some("SEEN"), "CONFIRMED", Some(140)),
                (Some("CONFIRMED"), "POLICY_OK", Some(140)),
                (Some("POLICY_OK"), "SIGNED", None),
                (Some("SIGNED"), "MINT_SUBMITTED", None),
                (Some("MINT_SUBMITTED"), "MINTED", None),
            ]
        );
        assert_eq!(ev[4].detail.as_deref(), Some("eth tx 0xab"));
        assert!(
            ev[3]
                .detail
                .as_deref()
                .unwrap()
                .starts_with("Mint(amount 1000001")
        );
        assert!(
            ev.iter()
                .all(|e| e.at == fixed_clock() && e.kind == ObjectKind::Lock)
        );
        assert!(ev.windows(2).all(|w| w[0].id < w[1].id));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn rejection_reason_is_stored_and_logged() {
    let mut s = store();
    s.tx(|t| {
        let id = t.insert_lock(&new_lock(2, 100))?.lock_id;
        t.transition_lock(&id, LockState::Confirmed, Some(140), None)?;
        t.reject_lock(&id, "owner age below MIN_OWNER_AGE", Some(140))?;
        let l = t.lock(&id)?.unwrap();
        assert_eq!(l.state, LockState::PolicyRejected);
        assert_eq!(
            l.rejection_reason.as_deref(),
            Some("owner age below MIN_OWNER_AGE")
        );
        let ev = t.events_for(ObjectKind::Lock, &hex::encode(id))?;
        assert_eq!(
            ev.last().unwrap().detail.as_deref(),
            Some("owner age below MIN_OWNER_AGE")
        );
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn a_rolled_back_transaction_logs_nothing() {
    let mut s = store();
    let k = burn_key(1);
    s.tx(|t| t.insert_burn(&new_burn(1, 10, true)).map(drop))
        .unwrap();
    let r: Result<(), StoreError> = s.tx(|t| {
        t.assign_burn(&k, &LEADER, 50)?;
        Err(StoreError::Invalid("abort".into()))
    });
    assert!(r.is_err());
    s.tx(|t| {
        assert_eq!(t.burn(&k)?.unwrap().state, BurnState::Finalized);
        assert_eq!(t.events_for(ObjectKind::Burn, &k.to_string())?.len(), 1);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn events_since_tails_the_log_across_kinds() {
    let mut s = store();
    s.tx(|t| {
        t.insert_burn(&new_burn(1, 10, false))?;
        t.transition_burn(&burn_key(1), BurnState::Finalized, Some(12), None)?;
        let v = t.insert_vault(&new_vault(1, 20))?.outpoint;
        t.transition_vault(
            &v,
            VaultState::RollDue,
            Some(30),
            Some("ownerHeight - ROLL_MARGIN"),
        )?;
        let i = t.insert_intent(&new_intent(1, 31, None))?.outpoint;
        t.confirm_intent(&i, 32)?;
        Ok::<_, StoreError>(())
    })
    .unwrap();
    s.tx(|t| {
        let all = t.events_since(0, 100)?;
        let got: Vec<_> = all.iter().map(|e| (e.kind, e.to.as_str())).collect();
        assert_eq!(
            got,
            [
                (ObjectKind::Burn, "SEEN"),
                (ObjectKind::Burn, "FINALIZED"),
                (ObjectKind::Vault, "LIVE"),
                (ObjectKind::Vault, "ROLL_DUE"),
                (ObjectKind::Intent, "OBSERVED"),
                (ObjectKind::Intent, "OBSERVED"),
            ]
        );
        // The confirmation note is from == to with a detail.
        let note = &all[5];
        assert_eq!(note.from.as_deref(), Some("OBSERVED"));
        assert_eq!(note.detail.as_deref(), Some("mined at 32"));
        assert_eq!(note.height, Some(32));
        assert_eq!(note.object_id, op(0x20, 1).to_string());
        assert_eq!(all[0].object_id, format!("31337:{}:1", DEP.bridge));
        // Paging.
        let page = t.events_since(all[1].id, 2)?;
        assert_eq!(page, all[2..4]);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}
