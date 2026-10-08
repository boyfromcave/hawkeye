//! Transition legality: the §5.1 edge tables, written out here independently of the
//! implementation, are checked pair by pair; then every (from, to) pair of every machine is
//! driven through the ledger's typed API: legal edges succeed and log exactly one event,
//! illegal ones fail with `IllegalTransition`, leave the state alone and log nothing.

mod common;

use std::collections::{HashMap, VecDeque};

use common::*;
use hawkeye_core::OutPoint;
use hawkeye_store::{
    BurnState, Edge, FaultKind, IntentState, LockState, Machine, NewSlashCase, ObjectKind,
    SlashState, Store, StoreError, Tx, VaultState,
};

// ---------------------------------------------------------------------------------------------
// The expected tables.

fn lock_forward() -> Vec<(LockState, LockState)> {
    use LockState::*;
    let mut v = vec![
        (Seen, Confirmed),
        (Confirmed, PolicyOk),
        (Confirmed, PolicyRejected),
        (PolicyOk, Signed),
        (PolicyOk, Minted),
        (Signed, MintSubmitted),
        (Signed, Proposed),
        (Signed, Minted),
        (MintSubmitted, Minted),
        (Proposed, Challenged),
        (Proposed, Executed),
        (Challenged, Proposed),
        (Executed, Minted),
        (Reorged, Seen),
    ];
    for &s in LockState::ALL {
        if s != Reorged {
            v.push((s, Reorged));
        }
    }
    v
}

fn burn_forward() -> Vec<(BurnState, BurnState)> {
    use BurnState::*;
    vec![
        (Seen, Finalized),
        (Finalized, Orphaned),
        (Finalized, Assigned),
        (Finalized, WaitingCap),
        (Assigned, Assigned),
        (Assigned, WaitingCap),
        (WaitingCap, Finalized),
        (WaitingCap, Assigned),
        (Finalized, IntentPending),
        (Assigned, IntentPending),
        (WaitingCap, IntentPending),
        (IntentPending, IntentConfirmed),
        (IntentConfirmed, Released),
        (IntentPending, Cancelled),
        (IntentConfirmed, Cancelled),
        (Cancelled, Finalized),
    ]
}

fn burn_rewind() -> Vec<(BurnState, BurnState)> {
    use BurnState::*;
    vec![
        (IntentConfirmed, IntentPending),
        (Released, IntentConfirmed),
    ]
}

fn intent_forward() -> Vec<(IntentState, IntentState)> {
    use IntentState::*;
    vec![
        (Observed, Matched),
        (Observed, Unmatched),
        (Matched, Released),
        (Matched, Cancelled),
        (Matched, Unmatched),
        (Unmatched, Matched),
        (Unmatched, CancelSent),
        (Unmatched, Cancelled),
        (Unmatched, MaturedUnmatched),
        (CancelSent, Cancelled),
        (CancelSent, MaturedUnmatched),
        (MaturedUnmatched, Released),
    ]
}

fn intent_rewind() -> Vec<(IntentState, IntentState)> {
    use IntentState::*;
    vec![
        (Cancelled, CancelSent),
        (Cancelled, Matched),
        (Cancelled, Unmatched),
        (Released, Matched),
    ]
}

fn vault_forward() -> Vec<(VaultState, VaultState)> {
    use VaultState::*;
    vec![
        (Live, RollDue),
        (RollDue, Rolling),
        (Rolling, Rolled),
        (Live, Spent),
        (RollDue, Spent),
        (Rolling, Spent),
    ]
}

fn vault_rewind() -> Vec<(VaultState, VaultState)> {
    use VaultState::*;
    vec![(Spent, Live), (Rolled, Rolling)]
}

fn slash_forward() -> Vec<(SlashState, SlashState)> {
    use SlashState::*;
    vec![
        (Opened, Voted),
        (Voted, Submitted),
        (Submitted, Slashed),
        (Opened, Slashed),
        (Voted, Slashed),
        (Opened, Expired),
        (Voted, Expired),
        (Submitted, Expired),
    ]
}

fn slash_rewind() -> Vec<(SlashState, SlashState)> {
    use SlashState::*;
    vec![(Slashed, Submitted), (Slashed, Voted), (Slashed, Opened)]
}

fn check_table<S: Machine + std::hash::Hash>(fwd: Vec<(S, S)>, rew: Vec<(S, S)>) {
    let mut expected: HashMap<(S, S), Edge> = HashMap::new();
    for e in fwd {
        assert!(expected.insert(e, Edge::Forward).is_none(), "dup {e:?}");
    }
    for e in rew {
        assert!(expected.insert(e, Edge::Rewind).is_none(), "dup {e:?}");
    }
    for &a in S::ALL {
        for &b in S::ALL {
            assert_eq!(
                a.edge(b),
                expected.get(&(a, b)).copied(),
                "{} edge {a} -> {b}",
                S::KIND
            );
        }
    }
}

#[test]
fn edge_tables_match_the_plan() {
    check_table(lock_forward(), vec![]);
    check_table(burn_forward(), burn_rewind());
    check_table(intent_forward(), intent_rewind());
    check_table(vault_forward(), vault_rewind());
    check_table(slash_forward(), slash_rewind());
}

#[test]
fn sample_of_illegal_edges() {
    use LockState as L;
    for (a, b) in [
        (L::Seen, L::Signed),
        (L::Seen, L::PolicyOk),
        (L::PolicyRejected, L::PolicyOk),
        (L::PolicyRejected, L::Signed),
        (L::Minted, L::Signed),
        (L::Challenged, L::Executed),
        (L::Reorged, L::Signed),
        (L::Reorged, L::Reorged),
    ] {
        assert_eq!(a.edge(b), None, "{a} -> {b}");
    }
    use BurnState as B;
    for (a, b) in [
        (B::Seen, B::Assigned),
        (B::Orphaned, B::Assigned),
        (B::Released, B::Cancelled),
        (B::Cancelled, B::Assigned),
        (B::IntentPending, B::Released),
    ] {
        assert_eq!(a.edge(b), None, "{a} -> {b}");
    }
    // Rewind edges are not forward edges.
    assert_eq!(B::Released.edge(B::IntentConfirmed), Some(Edge::Rewind));
    use IntentState as I;
    for (a, b) in [
        (I::Observed, I::CancelSent),
        (I::Matched, I::CancelSent),
        (I::MaturedUnmatched, I::Cancelled),
        (I::Released, I::Cancelled),
    ] {
        assert_eq!(a.edge(b), None, "{a} -> {b}");
    }
    assert_eq!(VaultState::Rolled.edge(VaultState::Live), None);
    assert_eq!(SlashState::Expired.edge(SlashState::Slashed), None);
}

// ---------------------------------------------------------------------------------------------
// Driving every pair through the API.

/// Shortest forward path from `start` to every reachable state.
fn paths<S: Machine + std::hash::Hash>(start: S) -> HashMap<S, Vec<S>> {
    let mut out = HashMap::from([(start, vec![])]);
    let mut q = VecDeque::from([start]);
    while let Some(s) = q.pop_front() {
        for &t in S::ALL {
            if s.edge(t) == Some(Edge::Forward) && !out.contains_key(&t) {
                let mut p = out[&s].clone();
                p.push(t);
                out.insert(t, p);
                q.push_back(t);
            }
        }
    }
    out
}

/// Take object `n` from the first state to the second.
type Apply<S> = dyn Fn(&Tx<'_>, u32, S, S) -> Result<(), StoreError>;

struct Driver<'f, S> {
    start: S,
    create: &'f dyn Fn(&Tx<'_>, u32) -> String,
    apply: &'f Apply<S>,
    get: &'f dyn Fn(&Tx<'_>, u32) -> S,
    /// Pairs whose call is deliberately not an edge check (documented elsewhere).
    skip: &'f dyn Fn(S, S) -> bool,
}

fn drive<S: Machine + std::hash::Hash>(store: &mut Store, d: Driver<'_, S>) {
    let paths = paths(d.start);
    for &s in S::ALL {
        assert!(paths.contains_key(&s), "{} state {s} unreachable", S::KIND);
    }
    let mut n = 0u32;
    let mut legal = 0;
    let mut illegal = 0;
    for &from in S::ALL {
        for &to in S::ALL {
            if (d.skip)(from, to) {
                continue;
            }
            n += 1;
            store
                .tx(|t| {
                    let id = (d.create)(t, n);
                    let mut cur = d.start;
                    for &step in &paths[&from] {
                        (d.apply)(t, n, cur, step)
                            .unwrap_or_else(|e| panic!("{} path {cur} -> {step}: {e}", S::KIND));
                        cur = step;
                    }
                    assert_eq!((d.get)(t, n), from);
                    let before = t.events_for(S::KIND, &id)?.len();
                    let r = (d.apply)(t, n, from, to);
                    let events = t.events_for(S::KIND, &id)?;
                    if from.edge(to) == Some(Edge::Forward) {
                        r.unwrap_or_else(|e| panic!("{} {from} -> {to}: {e}", S::KIND));
                        legal += 1;
                        assert_eq!((d.get)(t, n), to);
                        let last = events.last().unwrap();
                        assert_eq!(last.from.as_deref(), Some(from.to_string().as_str()));
                        assert_eq!(last.to, to.to_string());
                        assert_eq!(events.len(), before + 1, "{from} -> {to}");
                    } else {
                        illegal += 1;
                        match r {
                            Err(StoreError::IllegalTransition {
                                kind,
                                from: f,
                                to: tt,
                                ..
                            }) => {
                                assert_eq!(kind, S::KIND);
                                assert_eq!(f, from.to_string());
                                assert_eq!(tt, to.to_string());
                            }
                            other => panic!("{} {from} -> {to}: {other:?}", S::KIND),
                        }
                        assert_eq!((d.get)(t, n), from);
                        assert_eq!(events.len(), before, "illegal edge logged");
                    }
                    Ok::<_, StoreError>(())
                })
                .unwrap();
        }
    }
    assert!(legal > 0 && illegal > 0);
}

fn lock_id_n(n: u32) -> hawkeye_core::bytes::Hash32 {
    lock_id_of(n)
}

#[test]
fn every_lock_pair_through_the_api() {
    let mut s = store();
    drive(
        &mut s,
        Driver {
            start: LockState::Seen,
            create: &|t, n| hex::encode(t.insert_lock(&new_lock(n, 100)).unwrap().lock_id),
            apply: &|t, n, from, to| {
                let id = lock_id_n(n);
                match to {
                    LockState::Signed if from == LockState::PolicyOk => {
                        let l = t.lock(&id)?.unwrap();
                        t.sign_once_mint(&id, l.value_zat, &DEST, &[7; 32], fake_sig)
                            .map(drop)
                    }
                    LockState::PolicyRejected => t.reject_lock(&id, "value < MIN_LOCK", Some(140)),
                    _ => t.transition_lock(&id, to, Some(141), None).map(drop),
                }
            },
            get: &|t, n| t.lock(&lock_id_n(n)).unwrap().unwrap().state,
            skip: &|_, _| false,
        },
    );
}

#[test]
fn every_burn_pair_through_the_api() {
    let mut s = store();
    drive(
        &mut s,
        Driver {
            start: BurnState::Seen,
            create: &|t, n| {
                t.insert_burn(&new_burn(n.into(), 10, false))
                    .unwrap()
                    .key
                    .to_string()
            },
            apply: &|t, n, _from, to| {
                let k = burn_key(n.into());
                match to {
                    BurnState::Assigned => t.assign_burn(&k, &LEADER, 200),
                    BurnState::WaitingCap => t.burn_wait_cap(&k, 3, Some(200)),
                    BurnState::IntentPending => {
                        let i = t.insert_intent(&new_intent(n * 100 + 1, 200, None))?;
                        t.burn_intent_pending(&k, &i.outpoint, 200)
                    }
                    _ => t.transition_burn(&k, to, Some(11), None).map(drop),
                }
            },
            get: &|t, n| t.burn(&burn_key(n.into())).unwrap().unwrap().state,
            skip: &|_, _| false,
        },
    );
}

fn intent_op(n: u32) -> OutPoint {
    op(0x20, n)
}

#[test]
fn every_intent_pair_through_the_api() {
    let mut s = store();
    drive(
        &mut s,
        Driver {
            start: IntentState::Observed,
            create: &|t, n| {
                t.insert_intent(&new_intent(n, 300, Some(301)))
                    .unwrap()
                    .outpoint
                    .to_string()
            },
            apply: &|t, n, _from, to| {
                let o = intent_op(n);
                match to {
                    IntentState::Matched => {
                        t.classify_intent(&o, &DEP, &roll(), Some(302)).map(drop)
                    }
                    IntentState::Unmatched => t
                        .classify_intent(&o, &DEP, &unmatched(), Some(302))
                        .map(drop),
                    IntentState::CancelSent => t.intent_cancel_sent(&o, &h(0xca, n), Some(302)),
                    IntentState::Cancelled => t.intent_cancelled(&o, &h(0xca, n), 303),
                    IntentState::Released => t.intent_released(&o, &h(0xee, n), 310),
                    _ => t.transition_intent(&o, to, Some(310), None).map(drop),
                }
            },
            get: &|t, n| t.intent(&intent_op(n)).unwrap().unwrap().state,
            // Re-classifying into the same state is an update, not an edge (see
            // `reclassification_in_place`).
            skip: &|a, b| a == b && matches!(a, IntentState::Matched | IntentState::Unmatched),
        },
    );
}

#[test]
fn reclassification_in_place() {
    let mut s = store();
    s.tx(|t| {
        let o = t.insert_intent(&new_intent(1, 300, None))?.outpoint;
        t.classify_intent(&o, &DEP, &unmatched(), Some(300))?;
        let n = t.events_for(ObjectKind::Intent, &o.to_string())?.len();
        // Same verdict: no-op.
        t.classify_intent(&o, &DEP, &unmatched(), Some(301))?;
        assert_eq!(t.events_for(ObjectKind::Intent, &o.to_string())?.len(), n);
        // A different reason: updated and logged, state unchanged.
        let c = hawkeye_core::matcher::Classification::Unmatched(
            hawkeye_core::matcher::Unmatched::WrongValue {
                expected: 5,
                got: 6,
            },
        );
        t.classify_intent(&o, &DEP, &c, Some(302))?;
        let rec = t.intent(&o)?.unwrap();
        assert_eq!(rec.state, IntentState::Unmatched);
        assert_eq!(
            rec.classification.as_deref(),
            Some("unmatched:wrong-value:5:6")
        );
        let ev = t.events_for(ObjectKind::Intent, &o.to_string())?;
        assert_eq!(ev.len(), n + 1);
        assert_eq!(
            ev.last().unwrap().detail.as_deref(),
            Some("unmatched:wrong-value:5:6")
        );
        // Foreign is refused.
        assert!(matches!(
            t.classify_intent(
                &o,
                &DEP,
                &hawkeye_core::matcher::Classification::Foreign,
                None
            ),
            Err(StoreError::Invalid(_))
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

fn vault_op(n: u32) -> OutPoint {
    op(0x40, n)
}

#[test]
fn every_vault_pair_through_the_api() {
    let mut s = store();
    drive(
        &mut s,
        Driver {
            start: VaultState::Live,
            create: &|t, n| {
                t.insert_vault(&new_vault(n, 50))
                    .unwrap()
                    .outpoint
                    .to_string()
            },
            apply: &|t, n, _from, to| {
                let o = vault_op(n);
                match to {
                    VaultState::Spent | VaultState::Rolled => {
                        t.vault_spent(&o, to, &h(0x5a, n), 60)
                    }
                    _ => t.transition_vault(&o, to, Some(55), None).map(drop),
                }
            },
            get: &|t, n| t.vault(&vault_op(n)).unwrap().unwrap().state,
            skip: &|_, _| false,
        },
    );
}

#[test]
fn every_slash_pair_through_the_api() {
    let mut s = store();
    drive(
        &mut s,
        Driver {
            start: SlashState::Opened,
            create: &|t, n| {
                let (c, created) = t
                    .open_slash_case(&NewSlashCase {
                        target_key: [0x03; 33],
                        fault: FaultKind::FraudulentIntent,
                        subject: n.to_le_bytes().to_vec(),
                        evidence_json: r#"{"intent":"00"}"#.into(),
                        opened_height: Some(400),
                    })
                    .unwrap();
                assert!(created);
                assert_eq!(c.id, i64::from(n));
                c.id.to_string()
            },
            apply: &|t, n, _from, to| {
                let id = i64::from(n);
                match to {
                    SlashState::Voted => t.slash_vote(id, "act", "vote", Some(401)),
                    SlashState::Submitted => t.slash_submitted(id, &h(0x51, n), Some(402)),
                    SlashState::Slashed => t.slash_slashed(id, 403, None),
                    _ => t.transition_slash(id, to, Some(404), None).map(drop),
                }
            },
            get: &|t, n| t.slash_case(i64::from(n)).unwrap().unwrap().state,
            skip: &|_, _| false,
        },
    );
}

#[test]
fn payload_targets_refuse_the_generic_call() {
    let mut s = store();
    s.tx(|t| {
        let k = t.insert_burn(&new_burn(1, 10, true))?.key;
        for to in [
            BurnState::Assigned,
            BurnState::WaitingCap,
            BurnState::IntentPending,
        ] {
            assert!(matches!(
                t.transition_burn(&k, to, None, None),
                Err(StoreError::Invalid(_))
            ));
        }
        let o = t.insert_intent(&new_intent(1, 1, None))?.outpoint;
        assert!(matches!(
            t.transition_intent(&o, IntentState::Matched, None, None),
            Err(StoreError::Invalid(_))
        ));
        let v = t.insert_vault(&new_vault(1, 1))?.outpoint;
        assert!(matches!(
            t.transition_vault(&v, VaultState::Spent, None, None),
            Err(StoreError::Invalid(_))
        ));
        // POLICY_REJECTED needs a reason; SIGNED needs a sign-once record.
        let l = t.insert_lock(&new_lock(1, 1))?.lock_id;
        t.transition_lock(&l, LockState::Confirmed, None, None)?;
        assert!(matches!(
            t.transition_lock(&l, LockState::PolicyRejected, None, None),
            Err(StoreError::Invalid(_))
        ));
        t.transition_lock(&l, LockState::PolicyOk, None, None)?;
        assert!(matches!(
            t.transition_lock(&l, LockState::Signed, None, None),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(t.lock(&l)?.unwrap().state, LockState::PolicyOk);
        // Unknown objects.
        assert!(matches!(
            t.transition_lock(&[9; 32], LockState::Confirmed, None, None),
            Err(StoreError::NotFound { .. })
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn burn_payloads_are_stored_and_cleared() {
    let mut s = store();
    s.tx(|t| {
        let k = t.insert_burn(&new_burn(4, 10, true))?.key;
        t.burn_wait_cap(&k, 9, Some(100))?;
        assert_eq!(t.burn(&k)?.unwrap().waiting_epoch, Some(9));
        t.assign_burn(&k, &LEADER, 120)?;
        let b = t.burn(&k)?.unwrap();
        assert_eq!(
            (b.leader, b.assigned_height, b.waiting_epoch),
            (Some(LEADER), Some(120), None)
        );
        // Takeover.
        t.assign_burn(&k, &[0x03; 33], 125)?;
        assert_eq!(t.burn(&k)?.unwrap().leader, Some([0x03; 33]));
        let i = t.insert_intent(&new_intent(4, 126, None))?.outpoint;
        t.burn_intent_pending(&k, &i, 126)?;
        assert_eq!(t.burn(&k)?.unwrap().intent, Some(i));
        assert_eq!(t.burn_for_intent(&i)?.unwrap().key, k);
        t.transition_burn(&k, BurnState::Cancelled, Some(130), Some("cancelled"))?;
        t.transition_burn(&k, BurnState::Finalized, Some(130), None)?;
        let b = t.burn(&k)?.unwrap();
        assert_eq!((b.leader, b.intent, b.assigned_height), (None, None, None));
        // An intent that does not exist cannot be linked.
        t.assign_burn(&k, &LEADER, 131)?;
        assert!(matches!(
            t.burn_intent_pending(&k, &op(0x77, 1), 131),
            Err(StoreError::NotFound { .. })
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn a_release_matured_unmatched_is_recorded_then_adopted() {
    let mut s = store();
    s.tx(|t| {
        t.insert_burn(&new_burn(4, 20, true))?;
        let o = t.insert_intent(&new_intent(1, 300, Some(301)))?.outpoint;
        t.classify_intent(&o, &DEP, &unmatched(), Some(301))?;
        // adoption needs a matured-unmatched intent with a recorded release
        assert!(matches!(
            t.adopt_release(&o, &DEP, 4, Some(305)),
            Err(StoreError::Invalid(_))
        ));
        t.intent_released_unmatched(&o, &h(0xee, 1), 307)?;
        let rec = t.intent(&o)?.unwrap();
        assert_eq!(rec.state, IntentState::MaturedUnmatched);
        assert_eq!(rec.released_txid, Some(h(0xee, 1)));
        assert_eq!(rec.released_height, Some(307));
        // recording again on a matured intent only refreshes the release, no edge
        let n = t.events_for(ObjectKind::Intent, &o.to_string())?.len();
        t.intent_released_unmatched(&o, &h(0xee, 1), 307)?;
        assert_eq!(t.events_for(ObjectKind::Intent, &o.to_string())?.len(), n);
        // an unknown or unfinalized burn is refused
        assert!(t.adopt_release(&o, &DEP, 9, Some(308)).is_err());
        t.insert_burn(&new_burn(5, 21, false))?;
        assert!(matches!(
            t.adopt_release(&o, &DEP, 5, Some(308)),
            Err(StoreError::Invalid(_))
        ));
        t.adopt_release(&o, &DEP, 4, Some(308))?;
        let rec = t.intent(&o)?.unwrap();
        assert_eq!(rec.state, IntentState::Released);
        assert_eq!(rec.classification.as_deref(), Some("matched-burn"));
        assert_eq!(rec.matched_burn, Some(burn_key(4)));
        let last = t
            .events_for(ObjectKind::Intent, &o.to_string())?
            .pop()
            .unwrap();
        assert_eq!(last.from.as_deref(), Some("MATURED_UNMATCHED"));
        assert_eq!(last.to, "RELEASED");
        // once released, it is no longer adoptable
        assert!(t.adopt_release(&o, &DEP, 4, Some(309)).is_err());
        Ok::<_, StoreError>(())
    })
    .unwrap();
}
