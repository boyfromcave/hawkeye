//! V-N1: an edited `hawkeye.db.hwm` does not make the ledger look restored (plan §4.7).

use hawkeye::restore::{self, LEDGER_ID_META};
use hawkeye_core::{OutPoint, SecretKey};
use hawkeye_store::{SignDomain, Store, YcashSignKey};

fn key() -> SecretKey {
    SecretKey::from_bytes(&[7; 32]).unwrap()
}

fn other() -> SecretKey {
    SecretKey::from_bytes(&[8; 32]).unwrap()
}

const SET: [u8; 32] = [0x11; 32];

fn open(dir: &std::path::Path, name: &str) -> (Store, std::path::PathBuf) {
    let db = dir.join(name);
    let store = Store::open(&db).unwrap();
    (store, restore::hwm_path(&db))
}

#[test]
fn edited_mark_refuses_and_sets_no_restore() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, hwm) = open(dir.path(), "hawkeye.db");
    let key = key();
    assert_eq!(
        restore::reconcile_hwm(&mut store, &hwm, &key, &SET)
            .unwrap()
            .as_deref(),
        None
    );
    let id = store.tx(restore::ensure_ledger_id).unwrap();
    restore::write_hwm(&hwm, &key, &SET, &id, 1).unwrap();
    std::fs::write(&hwm, "999\n").unwrap();
    let err = restore::reconcile_hwm(&mut store, &hwm, &key, &SET).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("does not verify"), "{msg}");
    assert!(msg.contains("reset-ledger-hwm"), "{msg}");
    assert!(store.tx(|t| t.meta("ledger_restored")).unwrap().is_none());

    restore::reset_hwm(&hwm, &key, &SET, &id, 1).unwrap();
    let mut parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&hwm).unwrap()).unwrap();
    let mut sig = parsed["sig"].as_str().unwrap().to_owned().into_bytes();
    sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
    parsed["sig"] = String::from_utf8(sig).unwrap().into();
    std::fs::write(&hwm, format!("{parsed}\n")).unwrap();
    assert!(restore::reconcile_hwm(&mut store, &hwm, &key, &SET).is_err());

    restore::reset_from_ledger(&mut store, &hwm, &key, &SET).unwrap();
    assert_eq!(
        restore::reconcile_hwm(&mut store, &hwm, &key, &SET)
            .unwrap()
            .as_deref(),
        None
    );
    assert_eq!(restore::read_hwm(&hwm), 0);
}

#[test]
fn v1_migrates_once_then_a_bare_number_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, hwm) = open(dir.path(), "hawkeye.db");
    std::fs::write(&hwm, "4\n").unwrap();
    let why = restore::reconcile_hwm(&mut store, &hwm, &key(), &SET)
        .unwrap()
        .unwrap();
    assert!(why.contains("says 4"), "{why}");
    let text = std::fs::read_to_string(&hwm).unwrap();
    assert!(text.contains("\"v\":2"), "{text}");
    assert_eq!(restore::read_hwm(&hwm), 4);
    assert!(store.tx(|t| t.meta(LEDGER_ID_META)).unwrap().is_some());
    std::fs::write(&hwm, "999\n").unwrap();
    assert!(
        restore::reconcile_hwm(&mut store, &hwm, &key(), &SET).is_err(),
        "a bare number after the v2 mark exists is an edit"
    );
}

#[test]
fn a_mark_signed_by_another_key_or_ledger_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, hwm) = open(dir.path(), "hawkeye.db");
    let key = key();
    restore::reconcile_hwm(&mut store, &hwm, &key, &SET).unwrap();
    let id = store.tx(restore::ensure_ledger_id).unwrap();
    restore::write_hwm(&hwm, &other(), &SET, &id, 3).unwrap();
    assert!(restore::reconcile_hwm(&mut store, &hwm, &key, &SET).is_err());
    let mut other_id = id;
    other_id[0] ^= 0xff;
    restore::reset_hwm(&hwm, &key, &SET, &other_id, 3).unwrap();
    assert!(restore::reconcile_hwm(&mut store, &hwm, &key, &SET).is_err());
}

#[test]
fn genuine_restore_of_an_older_ledger_is_still_detected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("hawkeye.db");
    let hwm = restore::hwm_path(&db);
    let backup = dir.path().join("backup.db");
    let key = key();
    {
        let mut store = Store::open(&db).unwrap();
        restore::reconcile_hwm(&mut store, &hwm, &key, &SET).unwrap();
    }
    checkpoint(&db);
    std::fs::copy(&db, &backup).unwrap();
    {
        let mut store = Store::open(&db).unwrap();
        store
            .tx(|t| {
                t.sign_once_ycash(
                    &YcashSignKey {
                        domain: SignDomain::YcashUnlock,
                        set_id: SET,
                        prevout: OutPoint::new([0xab; 32], 0),
                    },
                    "00",
                    |_| Ok::<_, std::io::Error>(("01".to_owned(), [0xcd; 32])),
                )
            })
            .unwrap();
        let n = store.tx(|t| t.ycash_signature_count()).unwrap();
        assert_eq!(n, 1);
        let id = store.tx(restore::ensure_ledger_id).unwrap();
        restore::write_hwm(&hwm, &key, &SET, &id, n).unwrap();
    }
    checkpoint(&db);
    for ext in ["", "-wal", "-shm"] {
        let mut live = db.as_os_str().to_owned();
        live.push(ext);
        let p = std::path::PathBuf::from(live);
        if p.exists() {
            std::fs::remove_file(&p).unwrap();
        }
    }
    std::fs::copy(&backup, &db).unwrap();
    let mut restored = Store::open(&db).unwrap();
    let why = restore::reconcile_hwm(&mut restored, &hwm, &key, &SET)
        .unwrap()
        .unwrap();
    assert!(why.contains("holds 0"), "{why}");
    assert!(why.contains("says 1"), "{why}");
    restore::write_hwm(
        &hwm,
        &key,
        &SET,
        &restored.tx(restore::ensure_ledger_id).unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(
        restore::read_hwm(&hwm),
        1,
        "a later write does not lower the mark"
    );
}

fn checkpoint(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
}
