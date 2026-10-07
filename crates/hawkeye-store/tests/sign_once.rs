//! Sign-once semantics (HK-7, AGENTS.md rule 7).

mod common;

use std::cell::Cell;

use common::*;
use hawkeye_core::EthAddress;
use hawkeye_store::{LockState, ObjectKind, SignDomain, Store, StoreError, YcashSignKey};

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
        .sign_once_mint(&id, amount, &DEST, &[7; 32], signer)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(first.signature, fake_sig(&[7; 32]).unwrap());
    assert_eq!(
        (first.amount, first.to, first.digest),
        (amount, DEST, [7; 32])
    );

    let again = s
        .sign_once_mint(
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
    s.sign_once_mint(&id, amount, &DEST, &[7; 32], fake_sig)
        .unwrap();
    let never =
        |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called on conflict") };
    for (a, to, d) in [
        (amount + 1, DEST, [7; 32]),
        (amount, EthAddress([0xee; 20]), [7; 32]),
        (amount, DEST, [8; 32]),
    ] {
        match s.sign_once_mint(&id, a, &to, &d, never) {
            Err(StoreError::SignOnceConflict { domain, key, .. }) => {
                assert_eq!(domain, "eip712-mint");
                assert_eq!(key, hex::encode(id));
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }
    // The stored record is unchanged.
    let rec = s.tx(|t| t.mint_signature(&id)).unwrap().unwrap();
    assert_eq!((rec.amount, rec.to, rec.digest), (amount, DEST, [7; 32]));
}

#[test]
fn mint_refuses_locks_that_are_not_policy_ok_or_do_not_match() {
    let mut s = store();
    let never = |_: &[u8; 32]| -> Result<[u8; 65], StoreError> { panic!("signer called") };
    s.tx(|t| {
        // Unknown lock.
        assert!(matches!(
            t.sign_once_mint(&[1; 32], 1, &DEST, &[7; 32], never),
            Err(StoreError::NotFound { .. })
        ));
        // A SEEN lock.
        let rec = t.insert_lock(&new_lock(3, 100))?;
        assert!(matches!(
            t.sign_once_mint(&rec.lock_id, rec.value_zat, &DEST, &[7; 32], never),
            Err(StoreError::Invalid(_))
        ));
        // POLICY_OK but the wrong amount or recipient for the lock.
        let id = policy_ok_lock(t, 4, 100);
        let v = new_lock(4, 100).value_zat;
        assert!(matches!(
            t.sign_once_mint(&id, v + 1, &DEST, &[7; 32], never),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            t.sign_once_mint(&id, v, &EthAddress([1; 20]), &[7; 32], never),
            Err(StoreError::Invalid(_))
        ));
        assert!(t.mint_signature(&id)?.is_none());
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
    let r = s.sign_once_mint(&id, amount, &DEST, &[7; 32], |_: &[u8; 32]| {
        Err::<[u8; 65], _>(std::io::Error::other("keystore locked"))
    });
    assert!(matches!(r, Err(StoreError::Signer(_))));
    s.tx(|t| {
        assert!(t.mint_signature(&id)?.is_none());
        assert_eq!(t.lock(&id)?.unwrap().state, LockState::PolicyOk);
        Ok::<_, StoreError>(())
    })
    .unwrap();
    // A later attempt signs normally.
    s.sign_once_mint(&id, amount, &DEST, &[7; 32], fake_sig)
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
        t.sign_once_mint(&id, amount, &DEST, &[7; 32], fake_sig)?;
        Err(StoreError::Invalid("caller aborts".into()))
    });
    assert!(r.is_err());
    assert!(s.tx(|t| t.mint_signature(&id)).unwrap().is_none());
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
        s.sign_once_mint(&id, amount, &DEST, &[7; 32], fake_sig)
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
        .sign_once_mint(&id, amount, &DEST, &[7; 32], never)
        .unwrap();
    assert_eq!(rec.signature, fake_sig(&[7; 32]).unwrap());
    assert!(matches!(
        s.sign_once_mint(&id, amount, &DEST, &[8; 32], never),
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
        s.sign_once_mint(&id, new_lock(8, 100).value_zat, &DEST, &[7; 32], fake_sig)
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
