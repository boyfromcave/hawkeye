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
    "sign_once_challenge",
    "sign_once_drill_mint",
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
fn a_v2_ledger_migrates_to_v3_keeping_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch(MIGRATIONS[0]).unwrap();
        raw.execute_batch(MIGRATIONS[1]).unwrap();
        raw.pragma_update(None, "user_version", 2).unwrap();
        raw.execute(
            "INSERT INTO pending_mints (lock_id, tx_hash, recipient, amount, block, since_height,
                                        proposal, created_at)
             VALUES (?1, ?2, ?3, 5, 7, 9, 1, 0)",
            (vec![1u8; 32], vec![2u8; 32], vec![3u8; 20]),
        )
        .unwrap();
    }
    let mut s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap() as usize, MIGRATIONS.len());
    assert_eq!(tables(&path), TABLES);
    s.tx(|t| {
        assert_eq!(t.pending_mints()?.len(), 1);
        assert!(t.challenge_signatures()?.is_empty());
        Ok::<_, StoreError>(())
    })
    .unwrap();
}

/// Schema v4 (NEAR plan NH4): a v3 ledger with Ethereum data in every account column migrates
/// losslessly to chain-neutral text, keeps its sign-once bytes, triggers and foreign keys, and
/// renames the Ethereum cursor `foreign`.
#[test]
fn a_v3_ledger_migrates_to_v4_losslessly() {
    use hawkeye_core::{Destination, EthAddress, Guardian};
    use hawkeye_store::{BurnKey, Chain, LockState};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let (dest, sender, proposer, to) = ([0xd5u8; 20], [0xf1u8; 20], [0xeeu8; 20], [0x0au8; 20]);
    let dep = hawkeye_core::Deployment {
        chain_id: 31337,
        bridge: EthAddress([0xb0; 20]),
    };
    {
        let raw = rusqlite::Connection::open(&path).unwrap();
        for m in &MIGRATIONS[..3] {
            raw.execute_batch(m).unwrap();
        }
        raw.pragma_update(None, "user_version", 3).unwrap();
        raw.execute_batch(
            "INSERT INTO chain_cursor VALUES ('ycash', 10, NULL, 0);
             INSERT INTO chain_cursor VALUES ('ethereum', 164, x'ebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebeb', 0);
             INSERT INTO chain_blocks VALUES ('ethereum', 164, x'ebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebeb');",
        )
        .unwrap();
        raw.execute(
            "INSERT INTO locks (lock_id, txid, vout, value_zat, owner_height, destination,
                                block_hash, block_height, state, created_at, updated_at)
             VALUES (?1, ?2, 0, 1000, 500, ?3, ?4, 7, 'SIGNED', 0, 0)",
            (vec![1u8; 32], vec![2u8; 32], dest.to_vec(), vec![3u8; 32]),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO locks (lock_id, txid, vout, value_zat, owner_height, destination,
                                block_hash, block_height, state, created_at, updated_at)
             VALUES (?1, ?2, 1, 5, 500, NULL, ?3, 7, 'POLICY_REJECTED', 0, 0)",
            (vec![9u8; 32], vec![2u8; 32], vec![3u8; 32]),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO sign_once_mint VALUES (?1, 1000, ?2, ?3, ?4, 11)",
            (vec![1u8; 32], dest.to_vec(), vec![4u8; 32], vec![5u8; 65]),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO intents (txid, vout, value_zat, recipient_hash, vault_hash,
                                  first_seen_height, state, created_at, updated_at)
             VALUES (?1, 0, 400, ?2, ?3, 8, 'MATCHED', 0, 0)",
            (vec![6u8; 32], vec![7u8; 32], vec![8u8; 32]),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO burns (id, chain_id, bridge, nonce, tx_hash, block_number, block_hash,
                                sender, amount, recipient, state, intent_txid, intent_vout,
                                created_at, updated_at)
             VALUES (42, 31337, ?1, 3, ?2, 160, ?3, ?4, 400, ?5, 'INTENT_PENDING', ?6, 0, 0, 0)",
            (
                vec![0xb0u8; 20],
                vec![0xabu8; 32],
                vec![0xccu8; 32],
                sender.to_vec(),
                vec![0x01u8; 32],
                vec![6u8; 32],
            ),
        )
        .unwrap();
        raw.execute(
            "UPDATE intents SET matched_burn = 42 WHERE txid = ?1",
            [vec![6u8; 32]],
        )
        .unwrap();
        raw.execute(
            "INSERT INTO pending_mints VALUES (?1, ?2, ?3, 5, 7, 9, 1, 0)",
            (vec![0xcdu8; 32], vec![2u8; 32], to.to_vec()),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO sign_once_challenge VALUES (?1, '79228162514264337593543950335', ?2, 5,
                                                     ?3, 'no lock', ?4, ?5, 12)",
            (
                vec![0xcdu8; 32],
                proposer.to_vec(),
                to.to_vec(),
                vec![0x44u8; 32],
                vec![0x55u8; 65],
            ),
        )
        .unwrap();
        raw.execute(
            "INSERT INTO sign_once_drill_mint VALUES (?1, 7, ?2, ?3, ?4, 13)",
            (
                vec![0xceu8; 32],
                to.to_vec(),
                vec![0x66u8; 32],
                vec![0x77u8; 65],
            ),
        )
        .unwrap();
    }
    let mut s = Store::open(&path).unwrap();
    assert_eq!(s.schema_version().unwrap(), 4);
    assert_eq!(tables(&path), TABLES);
    let eth = |a: [u8; 20]| Destination::Ethereum(EthAddress(a));
    s.tx(|t| {
        assert_eq!(t.cursor(Chain::Foreign)?.unwrap().height, 164);
        assert_eq!(t.block_hash(Chain::Foreign, 164)?, Some([0xeb; 32]));
        assert_eq!(t.cursor(Chain::Ycash)?.unwrap().height, 10);
        let l = t.lock(&[1; 32])?.unwrap();
        assert_eq!(
            (l.destination, l.state),
            (Some(eth(dest)), LockState::Signed)
        );
        assert_eq!(t.lock(&[9; 32])?.unwrap().destination, None);
        let m = t.mint_signature(&[1; 32])?.unwrap();
        assert_eq!(
            (m.amount, m.to, m.digest, m.signature, m.signed_at),
            (1000, eth(dest), [4; 32], [5; 65], 11)
        );
        let b = t.burn(&BurnKey::new(dep, 3))?.unwrap();
        assert_eq!(
            (b.from, b.tx_hash, b.amount),
            (eth(sender), [0xab; 32], 400)
        );
        assert_eq!(b.intent.unwrap().txid, [6; 32]);
        assert_eq!(t.matcher_burn(&dep, 3)?.unwrap().tx_hash, [0xab; 32]);
        let pm = t.pending_mints()?;
        assert_eq!((pm.len(), &pm[0].to), (1, &eth(to)));
        let c = t.challenge_signatures()?;
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].proposal_id, (1u128 << 96) - 1);
        assert_eq!(c[0].proposer, Guardian::Ethereum(EthAddress(proposer)));
        assert_eq!(
            (&c[0].to, c[0].digest, c[0].signature),
            (&eth(to), [0x44; 32], [0x55; 65])
        );
        let d = t.drill_mint_signature(&[0xce; 32])?.unwrap();
        assert_eq!((d.to, d.signature), (eth(to), [0x77; 65]));
        Ok::<_, StoreError>(())
    })
    .unwrap();
    drop(s);
    // the sign-once triggers and the foreign keys survived the rebuild
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = ON").unwrap();
    for t in [
        "sign_once_mint",
        "sign_once_challenge",
        "sign_once_drill_mint",
    ] {
        assert!(raw.execute(&format!("DELETE FROM {t}"), []).is_err(), "{t}");
        assert!(
            raw.execute(&format!("UPDATE {t} SET amount = 1"), [])
                .is_err(),
            "{t}"
        );
    }
    assert!(
        raw.execute("DELETE FROM burns", []).is_err(),
        "intents.matched_burn → burns"
    );
    assert!(raw.execute("DELETE FROM locks WHERE lock_id = x'0101010101010101010101010101010101010101010101010101010101010101'", []).is_err(), "sign_once_mint → locks");
    let n: i64 = raw
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 0);
    // a v4 column refuses a raw 20-byte address and an unprefixed text
    assert!(
        raw.execute(
            "UPDATE locks SET destination = x'd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5' WHERE vout = 1",
            []
        )
        .is_err()
    );
    assert!(
        raw.execute(
            "UPDATE locks SET destination = 'alice.near' WHERE vout = 1",
            []
        )
        .is_err()
    );
    assert!(
        raw.execute(
            "UPDATE locks SET destination = 'near:alice.near' WHERE vout = 1",
            []
        )
        .is_ok()
    );
}

/// NEAR accounts and guardians round-trip through every v4 column.
#[test]
fn near_accounts_round_trip() {
    use hawkeye_core::{AccountId, Destination, Guardian};
    use hawkeye_store::{BurnKey, ChallengedProposal, NewBurn, PendingMintRecord};
    let mut s = common::store();
    let alice = Destination::Near(AccountId::parse("alice.near").unwrap());
    let evm =
        Destination::Near(AccountId::parse("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap());
    let dep =
        hawkeye_core::near::Domain::new("sandbox", AccountId::parse("wyec.test.near").unwrap())
            .unwrap()
            .deployment();
    s.tx(|t| {
        let pm = PendingMintRecord {
            lock_id: [1; 32],
            tx_hash: [2; 32],
            to: evm.clone(),
            amount: 5,
            block: 7,
            since_height: 9,
            proposal: true,
        };
        t.add_pending_mint(&pm)?;
        assert_eq!(t.pending_mints()?, vec![pm]);
        let b = t.insert_burn(&NewBurn {
            key: BurnKey::new(dep, 0),
            tx_hash: [3; 32],
            block_number: 100,
            block_hash: [4; 32],
            from: alice.clone(),
            amount: 1,
            recipient: [1; 32],
            finalized: true,
        })?;
        assert_eq!(b.from, alice);
        let c = t.sign_once_challenge(
            &ChallengedProposal {
                lock_id: [5; 32],
                proposal_id: 1,
                proposer: Guardian::Secp256k1([9; 64]),
                amount: 5,
                to: alice.clone(),
            },
            "no lock",
            &[6; 32],
            |_| Ok::<_, StoreError>([7; 65]),
        )?;
        assert_eq!(c.proposer, Guardian::Secp256k1([9; 64]));
        assert_eq!(t.challenge_signatures()?, vec![c]);
        let d = t.sign_once_drill_mint(&[8; 32], 5, &evm, &[6; 32], |_| {
            Ok::<_, StoreError>([7; 65])
        })?;
        assert_eq!(d.to, evm);
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
            to: hawkeye_core::Destination::Ethereum(EthAddress([3; 20])),
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
