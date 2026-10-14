//! Sign-once semantics (HK-7, AGENTS.md rule 7).

mod common;

use std::cell::Cell;

use common::*;
use hawkeye_core::EthAddress;
use hawkeye_store::{
    Account, ChallengedProposal, Guardian, LockState, ObjectKind, SignDomain, Store, StoreError,
    YcashSignKey,
};

#[test]
fn mint_identical_call_returns_stored_signature_without_signing() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 1, 100)))
        .unwrap();
    let amount = new_lock(1, 100).value_zat;
    let calls = Cell::new(0);
    let signer = |d: &[u8; 32]| {
        calls.set(calls.get() + 1);
        fake_sig(d)
    };
    let first = s
        .sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], signer)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(first.signature, fake_sig(&[7; 32]).unwrap());
    assert_eq!(
        (first.amount, first.to.clone(), first.digest),
        (amount, DEST, [7; 32])
    );

    let again = s
        .sign_once_mint(
            &DEP,
            &id,
            amount,
            &DEST,
            &[7; 32],
            |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called twice") },
        )
        .unwrap();
    assert_eq!(again, first);

    s.tx(|t| {
        // The first signature took the lock POLICY_OK -> SIGNED, once.
        assert_eq!(t.lock(&id)?.unwrap().state, LockState::Signed);
        let ev = t.events_for(ObjectKind::Lock, &hex::encode(id))?;
        let signed: Vec<_> = ev.iter().filter(|e| e.to == "SIGNED").collect();
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].from.as_deref(), Some("POLICY_OK"));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn mint_conflict_never_calls_the_signer() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 2, 100)))
        .unwrap();
    let amount = new_lock(2, 100).value_zat;
    s.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)
        .unwrap();
    let never =
        |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called on conflict") };
    for (a, to, d) in [
        (amount + 1, DEST, [7; 32]),
        (amount, Account::Ethereum(EthAddress([0xee; 20])), [7; 32]),
        (amount, DEST, [8; 32]),
    ] {
        match s.sign_once_mint(&DEP, &id, a, &to, &d, never) {
            Err(StoreError::SignOnceConflict { domain, key, .. }) => {
                assert_eq!(domain, "eip712-mint");
                assert_eq!(key, hex::encode(id));
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }
    // The stored record is unchanged.
    let rec = s.tx(|t| t.mint_signature(&DEP, &id)).unwrap().unwrap();
    assert_eq!((rec.amount, rec.to, rec.digest), (amount, DEST, [7; 32]));
}

#[test]
fn mint_refuses_locks_that_are_not_policy_ok_or_do_not_match() {
    let mut s = store();
    let never = |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called") };
    s.tx(|t| {
        // Unknown lock.
        assert!(matches!(
            t.sign_once_mint(&DEP, &[1; 32], 1, &DEST, &[7; 32], never),
            Err(StoreError::NotFound { .. })
        ));
        // A SEEN lock.
        let rec = t.insert_lock(&new_lock(3, 100))?;
        assert!(matches!(
            t.sign_once_mint(&DEP, &rec.lock_id, rec.value_zat, &DEST, &[7; 32], never),
            Err(StoreError::Invalid(_))
        ));
        // POLICY_OK but the wrong amount or recipient for the lock.
        let id = policy_ok_lock(t, 4, 100);
        let v = new_lock(4, 100).value_zat;
        assert!(matches!(
            t.sign_once_mint(&DEP, &id, v + 1, &DEST, &[7; 32], never),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            t.sign_once_mint(
                &DEP,
                &id,
                v,
                &Account::Ethereum(EthAddress([1; 20])),
                &[7; 32],
                never
            ),
            Err(StoreError::Invalid(_))
        ));
        assert!(t.mint_signature(&DEP, &id)?.is_none());
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn signer_failure_records_nothing() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 5, 100)))
        .unwrap();
    let amount = new_lock(5, 100).value_zat;
    let r = s.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], |_: &[u8; 32]| {
        Err::<[u8; 65], _>(std::io::Error::other("keystore locked"))
    });
    assert!(matches!(r, Err(StoreError::Signer(_))));
    s.tx(|t| {
        assert!(t.mint_signature(&DEP, &id)?.is_none());
        assert_eq!(t.lock(&id)?.unwrap().state, LockState::PolicyOk);
        Ok::<_, StoreError>(())
    })
    .unwrap();
    // A later attempt signs normally.
    s.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)
        .unwrap();
}

#[test]
fn a_rolled_back_transaction_releases_no_signature() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 6, 100)))
        .unwrap();
    let amount = new_lock(6, 100).value_zat;
    let r: Result<(), StoreError> = s.tx(|t| {
        t.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)?;
        Err(StoreError::Invalid("caller aborts".into()))
    });
    assert!(r.is_err());
    assert!(s.tx(|t| t.mint_signature(&DEP, &id)).unwrap().is_none());
}

#[test]
fn sign_once_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let ykey = YcashSignKey {
        domain: SignDomain::YcashUnlock,
        set_id: SET,
        prevout: op(0x40, 1),
    };
    let (id, amount) = {
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.journal_mode().unwrap(), "wal");
        let id = s
            .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 7, 100)))
            .unwrap();
        let amount = new_lock(7, 100).value_zat;
        s.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)
            .unwrap();
        s.sign_once_ycash(&ykey, "0400aa", |hex: &str| {
            Ok::<_, StoreError>((format!("{hex}ff"), [0x99; 32]))
        })
        .unwrap();
        (id, amount)
    };
    let mut s = Store::open(&path).unwrap();
    let never = |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("re-signed after reopen") };
    let rec = s
        .sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], never)
        .unwrap();
    assert_eq!(rec.signature, fake_sig(&[7; 32]).unwrap());
    assert!(matches!(
        s.sign_once_mint(&DEP, &id, amount, &DEST, &[8; 32], never),
        Err(StoreError::SignOnceConflict { .. })
    ));
    let y = s
        .sign_once_ycash(
            &ykey,
            "0400aa",
            |_: &str| -> Result<(String, [u8; 32]), StoreError> {
                panic!("node asked twice after reopen")
            },
        )
        .unwrap();
    assert_eq!(y.signed_hex, "0400aaff");
    assert_eq!(y.sighash, [0x99; 32]);
}

#[test]
fn ycash_sign_once_reuses_bytes_and_refuses_a_rebuild() {
    let mut s = store();
    let key = YcashSignKey {
        domain: SignDomain::YcashCancel,
        set_id: SET,
        prevout: op(0x20, 1),
    };
    let calls = Cell::new(0);
    let rec = s
        .sign_once_ycash(&key, "built-1", |b: &str| {
            calls.set(calls.get() + 1);
            Ok::<_, StoreError>((format!("signed({b})"), [0x11; 32]))
        })
        .unwrap();
    assert_eq!(rec.signed_hex, "signed(built-1)");
    assert_eq!(calls.get(), 1);
    // Retry with the same bytes: the stored signed hex, no node call.
    let again = s
        .sign_once_ycash(
            &key,
            "built-1",
            |_: &str| -> Result<(String, [u8; 32]), StoreError> { panic!("re-signed") },
        )
        .unwrap();
    assert_eq!(again, rec);
    // A rebuilt transaction for the same prevout: conflict, no node call.
    assert!(matches!(
        s.sign_once_ycash(
            &key,
            "built-2",
            |_: &str| -> Result<(String, [u8; 32]), StoreError> { panic!("signed a rebuild") }
        ),
        Err(StoreError::SignOnceConflict {
            domain: "ycash-cancel",
            ..
        })
    ));
    // The node-guard mirror.
    s.tx(|t| {
        t.check_ycash_sighash(&key, &[0x11; 32])?;
        assert!(matches!(
            t.check_ycash_sighash(&key, &[0x12; 32]),
            Err(StoreError::SignOnceConflict { .. })
        ));
        // Other domains and prevouts are independent.
        let other = YcashSignKey {
            domain: SignDomain::YcashUnlock,
            ..key
        };
        t.check_ycash_sighash(&other, &[0x12; 32])?;
        assert!(t.ycash_signature(&other)?.is_none());
        // The EIP-712 domain is not a Ycash domain.
        let bad = YcashSignKey {
            domain: SignDomain::Eip712Mint,
            ..key
        };
        assert!(matches!(
            t.sign_once_ycash(
                &bad,
                "x",
                |_: &str| -> Result<(String, [u8; 32]), StoreError> { panic!() }
            ),
            Err(StoreError::Invalid(_))
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn sign_once_rows_are_immutable_in_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let mut s = Store::open(&path).unwrap();
        let id = s
            .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 8, 100)))
            .unwrap();
        s.sign_once_mint(
            &DEP,
            &id,
            new_lock(8, 100).value_zat,
            &DEST,
            &[7; 32],
            fake_sig,
        )
        .unwrap();
    }
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(raw.execute("DELETE FROM sign_once_mint", []).is_err());
    assert!(
        raw.execute("UPDATE sign_once_mint SET amount = 1", [])
            .is_err()
    );
    assert!(raw.execute("DELETE FROM events", []).is_err());
    assert!(raw.execute("UPDATE events SET to_state = 'X'", []).is_err());
}

fn proposal(lock_id: [u8; 32], id: u128, amount: u64, to: Account) -> ChallengedProposal {
    ChallengedProposal {
        lock_id,
        proposal_id: id,
        proposer: Guardian::Ethereum(EthAddress([0xee; 20])),
        amount,
        to,
    }
}

#[test]
fn challenge_signs_once_per_lock_and_proposal_id() {
    let mut s = store();
    let fake = [0xcd; 32];
    let calls = Cell::new(0);
    let signer = |d: &[u8; 32]| {
        calls.set(calls.get() + 1);
        fake_sig(d)
    };
    let big = u128::from(u64::MAX) * 1000; // a uint96 id beyond SQLite's INTEGER
    let p = proposal(fake, big, 5, DEST);
    let first = s
        .tx(|t| t.sign_once_challenge(&p, "no lock", &[9; 32], signer))
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        (first.proposal_id, first.amount, first.reason.as_str()),
        (big, 5, "no lock")
    );
    // the same (lockId, proposalId): the stored bytes, the signer not called
    let again = s
        .tx(|t| {
            t.sign_once_challenge(
                &p,
                "retry",
                &[9; 32],
                |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called twice") },
            )
        })
        .unwrap();
    assert_eq!(again, first);
    // another digest for the same key: conflict, never signed
    let e = s
        .tx(|t| {
            t.sign_once_challenge(
                &p,
                "x",
                &[8; 32],
                |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("never") },
            )
        })
        .unwrap_err();
    assert!(
        matches!(e, StoreError::SignOnceConflict { domain, .. } if domain == SignDomain::Eip712Challenge.as_str())
    );
    // a re-proposal (new id) of the same lock is a new record
    s.tx(|t| {
        t.sign_once_challenge(
            &proposal(fake, big + 1, 5, DEST),
            "no lock",
            &[7; 32],
            fake_sig,
        )
    })
    .unwrap();
    let all = s.tx(|t| t.challenge_signatures()).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], first);
    // id 0 is no proposal
    assert!(matches!(
        s.tx(|t| t.sign_once_challenge(&proposal(fake, 0, 5, DEST), "x", &[1; 32], fake_sig)),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn a_matching_proposal_is_never_challenged() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 3, 100)))
        .unwrap();
    let amount = new_lock(3, 100).value_zat;
    let never = |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signed a match") };
    let e = s
        .tx(|t| t.sign_once_challenge(&proposal(id, 1, amount, DEST), "x", &[1; 32], never))
        .unwrap_err();
    assert!(e.to_string().contains("never challenged"), "{e}");
    // ... in every policy-OK state (here SIGNED)
    s.sign_once_mint(&DEP, &id, amount, &DEST, &[2; 32], fake_sig)
        .unwrap();
    assert!(
        s.tx(|t| t.sign_once_challenge(&proposal(id, 1, amount, DEST), "x", &[1; 32], never))
            .is_err()
    );
    // a wrong amount or recipient for the same real lock is challengeable
    s.tx(|t| {
        t.sign_once_challenge(
            &proposal(id, 2, amount + 1, DEST),
            "amount",
            &[3; 32],
            fake_sig,
        )
    })
    .unwrap();
    s.tx(|t| {
        t.sign_once_challenge(
            &proposal(id, 3, amount, Account::Ethereum(EthAddress([1; 20]))),
            "to",
            &[4; 32],
            fake_sig,
        )
    })
    .unwrap();
}

#[test]
fn drill_mint_only_for_unknown_locks_and_once() {
    let mut s = store();
    let fake = [0xab; 32];
    let first = s
        .tx(|t| t.sign_once_drill_mint(&fake, 7, &DEST, &[5; 32], fake_sig))
        .unwrap();
    let again = s
        .tx(|t| {
            t.sign_once_drill_mint(
                &fake,
                7,
                &DEST,
                &[5; 32],
                |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("twice") },
            )
        })
        .unwrap();
    assert_eq!(again, first);
    assert!(matches!(
        s.tx(|t| t.sign_once_drill_mint(&fake, 8, &DEST, &[5; 32], fake_sig)),
        Err(StoreError::SignOnceConflict { .. })
    ));
    // never for a lock this ledger holds
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 4, 100)))
        .unwrap();
    assert!(matches!(
        s.tx(|t| t.sign_once_drill_mint(&id, 7, &DEST, &[6; 32], fake_sig)),
        Err(StoreError::Invalid(_))
    ));
    // and it never counts as the lock's real Mint signature
    s.tx(|t| {
        assert!(t.mint_signature(&DEP, &fake)?.is_none());
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

/// Schema v6 (remedial report 05/H-1 §4.3): one live vault per burn, whatever signed it; the
/// per-vault record still applies; rolls carry no burn; the drill may double; a dead row frees
/// the burn for one more vault.
#[test]
fn unlock_sign_once_has_a_burn_dimension() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin};
    let mut s = store();
    let k = |n: u8| YcashSignKey {
        domain: SignDomain::YcashUnlock,
        set_id: SET,
        prevout: op(n, 0),
    };
    let burn = |origin| UnlockBurn {
        key: burn_key(7),
        origin,
        allow_double: false,
    };
    let signed = |b: &str| Ok::<_, StoreError>((format!("signed({b})"), [0x22; 32]));
    let never = |_: &str| -> Result<(String, [u8; 32]), StoreError> { panic!("signed") };
    s.tx(|t| {
        // the leader signs burn 7 on V1
        let r = t.sign_once_unlock(&k(1), Some(&burn(UnlockOrigin::Leader)), "u1", signed)?;
        assert_eq!(r.signed_hex, "signed(u1)");
        // idempotent
        assert_eq!(
            t.sign_once_unlock(&k(1), Some(&burn(UnlockOrigin::Leader)), "u1", never)?,
            r
        );
        // burn 7 on V2: refused, the signer is never called, whoever asks
        for origin in [UnlockOrigin::Leader, UnlockOrigin::Cosign] {
            match t.sign_once_unlock(&k(2), Some(&burn(origin)), "u2", never) {
                Err(StoreError::SignOnceConflict { domain, key, .. }) => {
                    assert_eq!(domain, "ycash-unlock");
                    assert_eq!(key, format!("burn {}", burn_key(7)));
                }
                other => panic!("{other:?}"),
            }
        }
        // a roll of V2 still signs
        t.sign_once_unlock(&k(2), None, "roll2", signed)?;
        // a different burn on V3 signs
        let b8 = UnlockBurn {
            key: burn_key(8),
            origin: UnlockOrigin::Cosign,
            allow_double: false,
        };
        t.sign_once_unlock(&k(3), Some(&b8), "u3", signed)?;
        assert_eq!(
            t.live_unlock_for_burn(&SET, &burn_key(8))?.unwrap().origin,
            UnlockOrigin::Cosign
        );
        // the drill doubles burn 7 on V4 (allow_double), recorded as a drill row
        let drill = UnlockBurn {
            key: burn_key(7),
            origin: UnlockOrigin::Drill,
            allow_double: true,
        };
        t.sign_once_unlock(&k(4), Some(&drill), "u4", signed)?;
        // allow_double is the drill's alone
        let bad = UnlockBurn {
            origin: UnlockOrigin::Leader,
            ..drill
        };
        assert!(matches!(
            t.sign_once_unlock(&k(5), Some(&bad), "u5", never),
            Err(StoreError::Invalid(_))
        ));
        // a cancel key is not the unlock domain
        let cancel = YcashSignKey {
            domain: SignDomain::YcashCancel,
            ..k(6)
        };
        assert!(matches!(
            t.sign_once_unlock(&cancel, None, "c", never),
            Err(StoreError::Invalid(_))
        ));
        // the V1 row dies (its fee input spent C_Y deep): V5 may now pay burn 7, once
        t.mark_unlock_dead(&SET, &burn_key(7), &op(1, 0), "fee input spent", 40)?;
        assert!(
            t.mark_unlock_dead(&SET, &burn_key(7), &op(1, 0), "again", 41)
                .is_err(),
            "dead once"
        );
        let live: Vec<_> = t
            .unlock_burn_rows(&SET, &burn_key(7))?
            .into_iter()
            .filter(|r| r.is_live())
            .collect();
        assert_eq!(live.len(), 1, "the drill row");
        assert_eq!(live[0].origin, UnlockOrigin::Drill);
        Ok::<_, StoreError>(())
    })
    .unwrap();
    // the drill row is live too: a leader may not add a third vault while it lives
    s.tx(|t| {
        assert!(matches!(
            t.sign_once_unlock(&k(5), Some(&burn(UnlockOrigin::Leader)), "u5", never),
            Err(StoreError::SignOnceConflict { .. })
        ));
        t.mark_unlock_dead(&SET, &burn_key(7), &op(4, 0), "drill fee spent", 42)?;
        t.sign_once_unlock(&k(5), Some(&burn(UnlockOrigin::Leader)), "u5", signed)?;
        let dead = t
            .unlock_burn_rows(&SET, &burn_key(7))?
            .into_iter()
            .find(|r| r.prevout == op(1, 0))
            .unwrap();
        assert_eq!(dead.dead_reason.as_deref(), Some("fee input spent"));
        assert_eq!(dead.dead_height, Some(40));
        assert_eq!(t.unlock_burns_of_vault(&SET, &op(5, 0))?.len(), 1);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

/// Schema v9 (audit 05/L-3): the `Mint` record is per deployment; a successor bridge gets its own
/// signature for a lock signed but never minted, with the same `(amount, to)` only.
#[test]
fn mint_sign_once_per_deployment() {
    let mut s = store();
    let id = s
        .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 1, 100)))
        .unwrap();
    let amount = new_lock(1, 0).value_zat;
    let succ = hawkeye_core::Deployment {
        chain_id: DEP.chain_id,
        bridge: hawkeye_core::EthAddress([0xc1; 20]),
    };
    let a = s
        .sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)
        .unwrap();
    // the successor's digest differs (another domain): a second record, the lock stays SIGNED
    let b = s
        .sign_once_mint(&succ, &id, amount, &DEST, &[8; 32], fake_sig)
        .unwrap();
    assert_eq!((a.deployment, b.deployment), (DEP, succ));
    assert_ne!(a.signature, b.signature);
    let never = |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called") };
    s.tx(|t| {
        assert_eq!(t.lock(&id)?.unwrap().state, LockState::Signed);
        assert_eq!(t.mint_signatures_any(&id)?.len(), 2);
        // identical repeat on either deployment: the stored record, no signing
        assert_eq!(
            t.sign_once_mint(&succ, &id, amount, &DEST, &[8; 32], never)?,
            b
        );
        // another (amount, to) on a third deployment: refused, by the code and by the trigger
        let third = hawkeye_core::Deployment {
            chain_id: 1,
            bridge: hawkeye_core::EthAddress([0xd2; 20]),
        };
        assert!(matches!(
            t.sign_once_mint(&third, &id, amount + 1, &DEST, &[9; 32], never),
            Err(StoreError::SignOnceConflict { .. })
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn mint_one_amount_per_lock_is_a_sqlite_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l.sqlite");
    let id = {
        let mut s = Store::open(&path).unwrap();
        let id = s
            .tx(|t| Ok::<_, StoreError>(policy_ok_lock(t, 1, 100)))
            .unwrap();
        let amount = new_lock(1, 0).value_zat;
        s.sign_once_mint(&DEP, &id, amount, &DEST, &[7; 32], fake_sig)
            .unwrap();
        id
    };
    let raw = rusqlite::Connection::open(&path).unwrap();
    let insert = |amount: i64, bridge: u8| {
        raw.execute(
            "INSERT INTO sign_once_mint (lock_id, chain_id, bridge, amount, recipient, digest,
                                         signature, signed_at)
             SELECT lock_id, chain_id, ?2, ?1, recipient, digest, signature, signed_at
             FROM sign_once_mint LIMIT 1",
            (amount, vec![bridge; 20]),
        )
    };
    let amount = i64::try_from(new_lock(1, 0).value_zat).unwrap();
    let e = insert(amount + 1, 0xc1).unwrap_err().to_string();
    assert!(e.contains("one (amount, recipient) per lock"), "{e}");
    insert(amount, 0xc1).unwrap();
    // a stored record is immutable, and only a placeholder row may take a deployment
    assert!(
        raw.execute(
            "UPDATE sign_once_mint SET chain_id = 5 WHERE lock_id = ?1",
            [id.to_vec()]
        )
        .is_err()
    );
    assert!(raw.execute("DELETE FROM sign_once_mint", []).is_err());
}

/// Review L-3: a drill row is never a burn's live unlock (never re-sent or served), though the
/// per-burn guard still counts it.
#[test]
fn drill_rows_are_never_the_live_unlock() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin};
    let mut s = store();
    let k = |n: u8| YcashSignKey {
        domain: SignDomain::YcashUnlock,
        set_id: SET,
        prevout: op(n, 0),
    };
    let signed = |b: &str| Ok::<_, StoreError>((format!("signed({b})"), [0x22; 32]));
    s.tx(|t| {
        t.sign_once_unlock(
            &k(1),
            Some(&UnlockBurn {
                key: burn_key(9),
                origin: UnlockOrigin::Drill,
                allow_double: true,
            }),
            "d1",
            signed,
        )?;
        assert!(t.live_unlock_for_burn(&SET, &burn_key(9))?.is_none());
        assert!(t.live_unlock_rows(&SET)?.is_empty());
        // the guard still sees it
        assert!(matches!(
            t.sign_once_unlock(
                &k(2),
                Some(&UnlockBurn {
                    key: burn_key(9),
                    origin: UnlockOrigin::Leader,
                    allow_double: false,
                }),
                "l2",
                signed,
            ),
            Err(StoreError::SignOnceConflict { .. })
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

/// W4-B-2: `adopt_unlock` refuses a second live vault for a burn and does not block a roll's
/// `sign_once_ycash` of that vault; a real `ycash-unlock` record does.
#[test]
fn adopt_unlock_does_not_block_a_roll() {
    use hawkeye_store::{UnlockBurn, UnlockOrigin};
    let mut s = store();
    let k = |n: u8| YcashSignKey {
        domain: SignDomain::YcashUnlock,
        set_id: SET,
        prevout: op(n, 0),
    };
    let signed = |b: &str| Ok::<_, StoreError>((format!("signed({b})"), [0x22; 32]));
    s.tx(|t| {
        t.adopt_unlock(
            &SET,
            &burn_key(1),
            &op(1, 0),
            "adopted-bytes",
            4,
            Some(0x6d5b7a31),
        )?;
        assert!(matches!(
            t.adopt_unlock(&SET, &burn_key(1), &op(2, 0), "other", 4, None),
            Err(StoreError::SignOnceConflict { .. })
        ));
        // the adopted vault is free for this member's roll
        t.sign_once_unlock(&k(1), None, "roll", signed)?;
        // a vault this member actually signed is not
        t.sign_once_unlock(
            &k(3),
            Some(&UnlockBurn {
                key: burn_key(3),
                origin: UnlockOrigin::Leader,
                allow_double: false,
            }),
            "u3",
            signed,
        )?;
        assert!(matches!(
            t.sign_once_unlock(&k(3), None, "roll3", signed),
            Err(StoreError::SignOnceConflict { .. })
        ));
        Ok::<_, StoreError>(())
    })
    .unwrap();
}
