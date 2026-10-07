//! Chain cursors and reorg rewinds (§5.4).

mod common;

use common::*;
use hawkeye_store::events::DELETED;
use hawkeye_store::{
    BurnState, Chain, FaultKind, IntentState, LockState, NewSlashCase, ObjectKind, SlashState,
    StoreError, VaultState,
};

#[test]
fn cursor_advances_forward_only() {
    let mut s = store();
    s.tx(|t| {
        assert!(t.cursor(Chain::Ycash)?.is_none());
        t.advance_cursor(Chain::Ycash, 10, &h(0xbb, 10))?;
        t.advance_cursor(Chain::Ycash, 11, &h(0xbb, 11))?;
        // Same block again: no-op.
        t.advance_cursor(Chain::Ycash, 11, &h(0xbb, 11))?;
        // Another block at a known height is a reorg: rewind first.
        assert!(matches!(
            t.advance_cursor(Chain::Ycash, 11, &h(0xcc, 11)),
            Err(StoreError::CursorRegression { .. })
        ));
        assert!(matches!(
            t.advance_cursor(Chain::Ycash, 9, &h(0xbb, 9)),
            Err(StoreError::CursorRegression { .. })
        ));
        // Ethereum's finalized head jumps.
        t.advance_cursor(Chain::Ethereum, 100, &h(0xeb, 100))?;
        t.advance_cursor(Chain::Ethereum, 164, &h(0xeb, 164))?;
        let c = t.cursor(Chain::Ycash)?.unwrap();
        assert_eq!((c.height, c.hash), (11, Some(h(0xbb, 11))));
        assert_eq!(t.cursor(Chain::Ethereum)?.unwrap().height, 164);
        assert_eq!(t.block_hash(Chain::Ycash, 10)?, Some(h(0xbb, 10)));
        assert_eq!(t.prune_blocks(Chain::Ycash, 11)?, 1);
        assert_eq!(t.block_hash(Chain::Ycash, 10)?, None);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn ycash_rewind_undoes_what_reorged_blocks_caused() {
    let mut s = store();
    let deep_signed = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 1, 100)))
        .unwrap();
    let unsigned = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 2, 105)))
        .unwrap();
    let signed = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 3, 106)))
        .unwrap();
    for (id, n) in [(deep_signed, 1), (signed, 3)] {
        s.sign_once_mint(
            &id,
            new_lock(n, 0).value_zat,
            &DEST,
            &[n as u8; 32],
            fake_sig,
        )
        .unwrap();
    }
    let k = burn_key(7);
    let (released, ours, theirs, slash_id) = s
        .tx(|t| {
            for b in 100..=110 {
                t.advance_cursor(Chain::Ycash, b, &h(0xbb, b as u32))?;
            }
            // A burn paid by intent X: mined at 105, released at 107.
            t.insert_burn(&new_burn(7, 50, true))?;
            t.assign_burn(&k, &LEADER, 103)?;
            let x = t.insert_intent(&new_intent(1, 104, None))?.outpoint;
            t.burn_intent_pending(&k, &x, 104)?;
            t.classify_intent(
                &x,
                &DEP,
                &hawkeye_core::matcher::Classification::MatchedBurn { nonce: 7 },
                Some(104),
            )?;
            t.confirm_intent(&x, 105)?;
            t.transition_burn(&k, BurnState::IntentConfirmed, Some(105), None)?;
            t.intent_released(&x, &h(0xee, 1), 107)?;
            t.transition_burn(&k, BurnState::Released, Some(107), None)?;
            // Intent Y: unmatched, our cancel mined at 106.
            let y = t.insert_intent(&new_intent(2, 104, Some(104)))?.outpoint;
            t.classify_intent(&y, &DEP, &unmatched(), Some(104))?;
            t.intent_cancel_sent(&y, &h(0xca, 2), Some(104))?;
            t.intent_cancelled(&y, &h(0xca, 2), 106)?;
            // Intent Z: unmatched, someone else's cancel mined at 106.
            let z = t.insert_intent(&new_intent(3, 104, Some(104)))?.outpoint;
            t.classify_intent(&z, &DEP, &unmatched(), Some(104))?;
            t.intent_cancelled(&z, &h(0xcb, 3), 106)?;
            // Vaults: one created above the fork, one spent above it, one rolled above it.
            t.insert_vault(&new_vault(1, 108))?;
            let spent = t.insert_vault(&new_vault(2, 90))?.outpoint;
            t.vault_spent(&spent, VaultState::Spent, &h(0x5a, 2), 107)?;
            let rolled = t.insert_vault(&new_vault(3, 90))?.outpoint;
            t.transition_vault(&rolled, VaultState::RollDue, Some(100), None)?;
            t.transition_vault(&rolled, VaultState::Rolling, Some(101), None)?;
            t.vault_spent(&rolled, VaultState::Rolled, &h(0x5b, 3), 109)?;
            // A slash case removed at 107 after our submission.
            let (c, _) = t.open_slash_case(&NewSlashCase {
                target_key: [0x03; 33],
                fault: FaultKind::FraudulentIntent,
                subject: z.txid.to_vec(),
                evidence_json: "{}".into(),
                opened_height: Some(104),
            })?;
            t.slash_vote(c.id, "act", "vote", Some(104))?;
            t.slash_submitted(c.id, &h(0x51, 1), Some(105))?;
            t.slash_slashed(c.id, 107, None)?;
            Ok::<_, StoreError>((x, y, z, c.id))
        })
        .unwrap();

    let rep = s.tx(|t| t.rewind_ycash_to(104)).unwrap();
    assert_eq!(rep.to, 104);
    assert_eq!(rep.locks_deleted, vec![unsigned]);
    assert_eq!(rep.exposures, vec![signed]);
    assert_eq!(rep.intents_unreleased, vec![released]);
    assert_eq!(rep.burns_reverted, vec![k]);
    assert_eq!(rep.intents_unconfirmed, vec![released]);
    assert_eq!(rep.intents_uncancelled.len(), 2);
    assert_eq!(rep.vaults_deleted, vec![op(0x40, 1)]);
    assert_eq!(rep.vaults_unspent.len(), 2);
    assert_eq!(rep.slash_cases_reverted, vec![slash_id]);

    s.tx(|t| {
        // Cursor and block window.
        let c = t.cursor(Chain::Ycash)?.unwrap();
        assert_eq!((c.height, c.hash), (104, Some(h(0xbb, 104))));
        assert_eq!(t.block_hash(Chain::Ycash, 105)?, None);
        // Locks.
        assert!(t.lock(&unsigned)?.is_none());
        let l = t.lock(&signed)?.unwrap();
        assert_eq!((l.state, l.exposure), (LockState::Reorged, true));
        assert!(
            t.mint_signature(&signed)?.is_some(),
            "sign-once records survive"
        );
        assert_eq!(t.lock(&deep_signed)?.unwrap().state, LockState::Signed);
        let ev = t.events_for(ObjectKind::Lock, &hex::encode(unsigned))?;
        let last = ev.last().unwrap();
        assert_eq!(
            (last.from.as_deref(), last.to.as_str()),
            (Some("POLICY_OK"), DELETED)
        );
        // Intents and the burn.
        let x = t.intent(&released)?.unwrap();
        assert_eq!(x.state, IntentState::Matched);
        assert_eq!(
            (x.confirmed_height, x.released_height, x.released_txid),
            (None, None, None)
        );
        assert_eq!(x.matched_burn, Some(k));
        assert_eq!(t.burn(&k)?.unwrap().state, BurnState::IntentPending);
        let y = t.intent(&ours)?.unwrap();
        assert_eq!(y.state, IntentState::CancelSent);
        assert_eq!((y.cancel_txid, y.cancel_height), (Some(h(0xca, 2)), None));
        let z = t.intent(&theirs)?.unwrap();
        assert_eq!(z.state, IntentState::Unmatched);
        assert_eq!((z.cancel_txid, z.cancel_height), (None, None));
        // Intents mined at or below the fork keep their confirmation.
        assert_eq!(y.confirmed_height, Some(104));
        // Vaults.
        assert!(t.vault(&op(0x40, 1))?.is_none());
        let v2 = t.vault(&op(0x40, 2))?.unwrap();
        assert_eq!((v2.state, v2.spent_height), (VaultState::Live, None));
        assert_eq!(t.vault(&op(0x40, 3))?.unwrap().state, VaultState::Rolling);
        // Slash case.
        let c = t.slash_case(slash_id)?.unwrap();
        assert_eq!((c.state, c.slashed_height), (SlashState::Submitted, None));
        // The cursor rewind is logged.
        let ev = t.events_for(ObjectKind::Cursor, "ycash")?;
        assert_eq!(ev.len(), 1);
        assert_eq!(
            (ev[0].from.as_deref(), ev[0].to.as_str()),
            (Some("110"), "104")
        );
        Ok::<_, StoreError>(())
    })
    .unwrap();

    // The new branch: the unsigned lock reappears as new, the signed one returns to SEEN, and
    // the cursor moves on from the fork.
    s.tx(|t| {
        let a = t.insert_lock(&new_lock(2, 105))?;
        assert_eq!(a.state, LockState::Seen);
        let mut moved = new_lock(3, 107);
        moved.block_hash = h(0xcc, 107);
        let b = t.insert_lock(&moved)?;
        assert_eq!(
            (b.state, b.block_height, b.exposure),
            (LockState::Seen, 107, true)
        );
        t.advance_cursor(Chain::Ycash, 105, &h(0xcc, 105))?;
        // The second rewind finds nothing more to undo above 104 except the new lock rows.
        let rep = t.rewind_ycash_to(104)?;
        assert_eq!(rep.locks_deleted.len(), 1); // lock 2 again (unsigned)
        assert_eq!(rep.exposures, vec![b.lock_id]);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn rewind_is_idempotent_and_a_noop_above_the_cursor() {
    let mut s = store();
    s.tx(|t| {
        for b in 1..=5 {
            t.advance_cursor(Chain::Ycash, b, &h(0xbb, b as u32))?;
        }
        t.insert_lock(&new_lock(1, 3))?;
        let r1 = t.rewind_ycash_to(9)?;
        assert_eq!(r1.locks_deleted.len(), 0);
        assert_eq!(t.cursor(Chain::Ycash)?.unwrap().height, 5);
        let r2 = t.rewind_ycash_to(2)?;
        assert_eq!(r2.locks_deleted.len(), 1);
        let r3 = t.rewind_ycash_to(2)?;
        assert_eq!(
            r3,
            hawkeye_store::RewindReport {
                to: 2,
                ..Default::default()
            }
        );
        // Rewinding below the hash window leaves the hash unknown.
        t.prune_blocks(Chain::Ycash, 2)?;
        t.rewind_ycash_to(1)?;
        let c = t.cursor(Chain::Ycash)?.unwrap();
        assert_eq!((c.height, c.hash), (1, None));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn eth_rewind_drops_unfinalized_burns_only() {
    let mut s = store();
    s.tx(|t| {
        t.advance_cursor(Chain::Ethereum, 60, &h(0xeb, 60))?;
        t.insert_burn(&new_burn(1, 40, true))?;
        t.insert_burn(&new_burn(2, 55, false))?;
        t.insert_burn(&new_burn(3, 58, false))?;
        Ok::<_, StoreError>(())
    })
    .unwrap();
    let rep = s.tx(|t| t.rewind_eth_to(50)).unwrap();
    assert_eq!(rep.burns_deleted, vec![burn_key(2), burn_key(3)]);
    s.tx(|t| {
        assert!(t.burn(&burn_key(2))?.is_none());
        assert_eq!(t.burn(&burn_key(1))?.unwrap().state, BurnState::Finalized);
        assert_eq!(t.cursor(Chain::Ethereum)?.unwrap().height, 50);
        let ev = t.events_for(ObjectKind::Burn, &burn_key(3).to_string())?;
        assert_eq!(ev.last().unwrap().to, DELETED);
        Ok::<_, StoreError>(())
    })
    .unwrap();
    // A finalized burn above the target refuses the rewind, and nothing changes.
    let r = s.tx(|t| t.rewind_eth_to(30));
    assert!(matches!(
        r,
        Err(StoreError::FinalizedReorg { block: 40, .. })
    ));
    s.tx(|t| {
        assert!(t.burn(&burn_key(1))?.is_some());
        assert_eq!(t.cursor(Chain::Ethereum)?.unwrap().height, 50);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn unfinalized_burns_are_replaced_then_finalized() {
    let mut s = store();
    s.tx(|t| {
        t.insert_burn(&new_burn(1, 40, false))?;
        // An unfinalized reorg gives nonce 1 another transaction.
        let mut other = new_burn(1, 41, false);
        other.tx_hash = h(0xe9, 1);
        other.amount = 42;
        let b = t.insert_burn(&other)?;
        assert_eq!(
            (b.amount, b.block_number, b.state),
            (42, 41, BurnState::Seen)
        );
        // The matcher does not see unfinalized burns, and an intent cannot match one.
        assert!(t.matcher_burn(&DEP, 1)?.is_none());
        let i = t.insert_intent(&new_intent(1, 10, None))?.outpoint;
        assert!(matches!(
            t.classify_intent(
                &i,
                &DEP,
                &hawkeye_core::matcher::Classification::MatchedBurn { nonce: 1 },
                None
            ),
            Err(StoreError::Invalid(_))
        ));
        other.finalized = true;
        assert_eq!(t.insert_burn(&other)?.state, BurnState::Finalized);
        // Finalized: identical is idempotent, different is a duplicate.
        assert_eq!(t.insert_burn(&other)?.state, BurnState::Finalized);
        other.amount = 43;
        assert!(matches!(
            t.insert_burn(&other),
            Err(StoreError::Duplicate { .. })
        ));
        let ev = t.events_for(ObjectKind::Burn, &burn_key(1).to_string())?;
        let tos: Vec<_> = ev.iter().map(|e| e.to.as_str()).collect();
        assert_eq!(tos, ["SEEN", "SEEN", "FINALIZED"]);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn matcher_view_of_consumption() {
    let mut s = store();
    s.tx(|t| {
        let k = burn_key(9);
        t.insert_burn(&new_burn(9, 40, true))?;
        let matched = hawkeye_core::matcher::Classification::MatchedBurn { nonce: 9 };
        let b = t.matcher_burn(&DEP, 9)?.unwrap();
        assert_eq!((b.nonce, b.amount, b.consumed_by), (9, 500_009, None));
        // Matched but only in the mempool: not consumed.
        let a = t.insert_intent(&new_intent(1, 200, None))?.outpoint;
        t.classify_intent(&a, &DEP, &matched, Some(200))?;
        assert_eq!(t.matcher_burn(&DEP, 9)?.unwrap().consumed_by, None);
        // A later-seen intent mined first, then the earlier one: the earliest-seen mined one
        // consumes.
        let b2 = t.insert_intent(&new_intent(2, 203, Some(204)))?.outpoint;
        t.classify_intent(&b2, &DEP, &matched, Some(204))?;
        assert_eq!(
            t.matcher_burn(&DEP, 9)?.unwrap().consumed_by.unwrap().txid,
            b2.txid
        );
        t.confirm_intent(&a, 205)?;
        let c = t.matcher_burn(&DEP, 9)?.unwrap().consumed_by.unwrap();
        assert_eq!((c.txid, c.first_seen), (a.txid, 200));
        // Cancelled intents do not consume.
        t.intent_cancelled(&a, &h(0xca, 1), 206)?;
        assert_eq!(
            t.matcher_burn(&DEP, 9)?.unwrap().consumed_by.unwrap().txid,
            b2.txid
        );
        assert_eq!(t.intents_for_burn(&k)?.len(), 2);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}
