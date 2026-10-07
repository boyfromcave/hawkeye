//! Opening and migrating the ledger.

mod common;

use hawkeye_store::schema::MIGRATIONS;
use hawkeye_store::{Store, StoreError};

const TABLES: &[&str] = &[
    "burns",
    "chain_blocks",
    "chain_cursor",
    "equivocations_sent",
    "events",
    "intents",
    "locks",
    "pending_mints",
    "set_sigs_seen",
    "sign_once_mint",
    "sign_once_ycash",
    "slash_cases",
    "slash_progress",
    "slash_votes",
    "slash_votes_given",
    "vaults",
];

fn tables(path: &std::path::Path) -> Vec<String> {
    let raw = rusqlite::Connection::open(path).unwrap();
    let mut st = raw
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table'
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn migrates_from_empty_in_memory() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.schema_version().unwrap() as usize, MIGRATIONS.len());
}

#[test]
fn migrates_from_empty_file_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap() as usize, MIGRATIONS.len());
        assert_eq!(s.journal_mode().unwrap(), "wal");
    }
    assert_eq!(tables(&path), TABLES);
    // Reopening applies nothing and keeps the version.
    let s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap() as usize, MIGRATIONS.len());
    drop(s);
    assert_eq!(tables(&path), TABLES);
}

#[test]
fn a_v1_ledger_migrates_to_v2_keeping_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch(MIGRATIONS[0]).unwrap();
        raw.pragma_update(None, "user_version", 1).unwrap();
        raw.execute(
            "INSERT INTO slash_cases (target_key, fault, subject, evidence, state, created_at,
                                      updated_at)
             VALUES (?1, 'GRIEFING', x'01', '{}', 'OPENED', 0, 0)",
            [vec![3u8; 33]],
        )
        .unwrap();
    }
    let mut s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap() as usize, MIGRATIONS.len());
    assert_eq!(tables(&path), TABLES);
    s.tx(|t| {
        let cases = t.slash_cases_in_state(hawkeye_store::SlashState::Opened)?;
        assert_eq!(cases.len(), 1);
        t.set_slash_progress(&hawkeye_store::SlashProgress {
            case_id: cases[0].id,
            act_hex: "00".into(),
            complete: false,
            signatures: 1,
            required: 2,
        })?;
        t.record_slash_vote(cases[0].id, "http://peer", 2, true)?;
        assert_eq!(t.slash_voters(cases[0].id)?, vec!["http://peer".to_owned()]);
        assert_eq!(t.slash_progress(cases[0].id)?.unwrap().signatures, 1);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn restart_records_round_trip() {
    use hawkeye_core::{EthAddress, OutPoint};
    use hawkeye_store::{FaultKind, PendingMintRecord, SeenSetSig, VoteGiven};
    let mut s = common::store();
    s.tx(|t| {
        let pm = PendingMintRecord {
            lock_id: [1; 32],
            tx_hash: [2; 32],
            to: EthAddress([3; 20]),
            amount: 5,
            block: 7,
            since_height: 9,
            proposal: true,
        };
        assert!(t.add_pending_mint(&pm)?);
        assert!(!t.add_pending_mint(&PendingMintRecord {
            since_height: 99,
            ..pm.clone()
        })?);
        assert_eq!(t.pending_mints()?, vec![pm.clone()]);
        t.remove_pending_mint(&pm.lock_id, &pm.tx_hash)?;
        assert!(t.pending_mints()?.is_empty());

        let op = OutPoint::new([4; 32], 1);
        let v = VoteGiven {
            act_prevout: op,
            fault: FaultKind::FraudulentIntent,
            target_key: [2; 33],
            subject: vec![9],
            signed_hex: "ab".into(),
            complete: true,
            signatures: 2,
            required: 2,
            reason: "no memo".into(),
        };
        t.record_vote_given(&v)?;
        t.record_vote_given(&VoteGiven {
            signed_hex: "cd".into(),
            ..v.clone()
        })?;
        assert_eq!(t.vote_given(&op)?, Some(v));

        let sig = SeenSetSig {
            set_id: [5; 32],
            prevout: op,
            member_key: [2; 33],
            role: 2,
            sighash: [6; 32],
            signature: [7; 65],
            txid: [8; 32],
        };
        assert!(t.note_set_sig(&sig)?.is_empty());
        assert!(t.note_set_sig(&sig)?.is_empty(), "the same signature again");
        let other = SeenSetSig {
            sighash: [0x16; 32],
            txid: [0x18; 32],
            ..sig.clone()
        };
        assert_eq!(t.note_set_sig(&other)?, vec![sig.clone()]);
        assert!(t.claim_equivocation(&op, &[2; 33])?);
        assert!(!t.claim_equivocation(&op, &[2; 33])?);
        t.unclaim_equivocation(&op, &[2; 33])?;
        assert!(t.claim_equivocation(&op, &[2; 33])?);
        t.equivocation_sent(&op, &[2; 33], &[1; 32])?;
        t.unclaim_equivocation(&op, &[2; 33])?;
        assert!(
            !t.claim_equivocation(&op, &[2; 33])?,
            "a sent proof stays claimed"
        );
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

#[test]
fn a_newer_ledger_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    drop(Store::open(&path).unwrap());
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.pragma_update(None, "user_version", 99).unwrap();
    drop(raw);
    match Store::open(&path) {
        Err(StoreError::SchemaTooNew { found, supported }) => {
            assert_eq!(found, 99);
            assert_eq!(supported as usize, MIGRATIONS.len());
        }
        Err(e) => panic!("expected SchemaTooNew, got {e}"),
        Ok(_) => panic!("expected SchemaTooNew, opened"),
    }
}

#[test]
fn constraints_are_enforced() {
    let mut s = common::store();
    // Evidence must be JSON.
    let r = s.tx(|t| {
        t.open_slash_case(&hawkeye_store::NewSlashCase {
            target_key: [3; 33],
            fault: hawkeye_store::FaultKind::Griefing,
            subject: vec![1],
            evidence_json: "not json".into(),
            opened_height: None,
        })
    });
    assert!(matches!(r, Err(StoreError::Sqlite(_))));
    // One case per (fault, subject, target).
    s.tx(|t| {
        let new = hawkeye_store::NewSlashCase {
            target_key: [3; 33],
            fault: hawkeye_store::FaultKind::Griefing,
            subject: vec![1],
            evidence_json: r#"{"a":1}"#.into(),
            opened_height: Some(5),
        };
        let (a, created_a) = t.open_slash_case(&new)?;
        let (b, created_b) = t.open_slash_case(&new)?;
        assert!(created_a && !created_b);
        assert_eq!(a, b);
        Ok::<_, StoreError>(())
    })
    .unwrap();
}
