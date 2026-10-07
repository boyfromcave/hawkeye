//! Opening and migrating the ledger.

mod common;

use hawkeye_store::schema::MIGRATIONS;
use hawkeye_store::{Store, StoreError};

const TABLES: &[&str] = &[
    "burns",
    "chain_blocks",
    "chain_cursor",
    "events",
    "intents",
    "locks",
    "sign_once_mint",
    "sign_once_ycash",
    "slash_cases",
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
