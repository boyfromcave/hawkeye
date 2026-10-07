//! Replays the node's `sighash.json` (`tests/data/sighash.json`, ycash-dd `dbc1ab0`) through the
//! v3/v4 parser and [`zip243`]. Rows are `[raw_tx, scriptCode, nIn, hashType, branchId,
//! sighash]`, the sighash as `uint256::GetHex()` (reversed), amount 0
//! (`src/test/sighash_tests.cpp` `sighash_from_data`).

use hawkeye_core::bytes::from_hex;
use hawkeye_core::sighash::zip243;
use hawkeye_core::tx::{Transaction, TxFormat};
use serde_json::Value;

#[test]
fn sighash_json() {
    let rows: Vec<Value> =
        serde_json::from_str(include_str!("data/sighash.json")).expect("sighash.json parses");
    let (mut v3, mut v4, mut sprout, mut comments) = (0, 0, 0, 0);
    let mut flavours = std::collections::BTreeSet::new();
    for row in &rows {
        let row = row.as_array().expect("row");
        if row.len() == 1 {
            comments += 1;
            continue;
        }
        assert_eq!(row.len(), 6, "{row:?}");
        let raw = from_hex(row[0].as_str().unwrap()).unwrap();
        // Sprout v1/v2 (fOverwintered clear) is out of scope: counted, not checked.
        if raw[3] & 0x80 == 0 {
            sprout += 1;
            continue;
        }
        let tx = Transaction::parse(&raw).unwrap_or_else(|e| panic!("parse: {e} {row:?}"));
        assert_eq!(tx.to_bytes().unwrap(), raw, "round trip");
        let script = from_hex(row[1].as_str().unwrap()).unwrap();
        let n_in = row[2].as_u64().unwrap() as usize;
        let hash_type = row[3].as_i64().unwrap() as i32 as u32;
        let branch = row[4].as_u64().unwrap() as u32;
        let mut want = from_hex(row[5].as_str().unwrap()).unwrap();
        want.reverse();
        let got = zip243(&tx, n_in, &script, 0, hash_type, branch).unwrap();
        assert_eq!(got.to_vec(), want, "{row:?}");
        match tx.format {
            TxFormat::OverwinterV3 => v3 += 1,
            TxFormat::SaplingV4 => v4 += 1,
        }
        let base = hash_type & 0x1f;
        flavours.insert((
            if (1..=3).contains(&base) { base } else { 1 },
            hash_type & 0x80 != 0,
        ));
    }
    eprintln!(
        "sighash.json: {v3} v3 + {v4} v4 checked, {sprout} Sprout skipped, {comments} comment"
    );
    assert_eq!((v3, v4, sprout, comments), (139, 130, 231, 1));
    // ALL / NONE / SINGLE, each with and without ANYONECANPAY
    assert_eq!(flavours.len(), 6, "{flavours:?}");
}

/// The shielded and JoinSplit branches are exercised: some v4 vector has spends, outputs and
/// JoinSplits, some v3 vector has JoinSplits.
#[test]
fn sighash_json_covers_shielded_parts() {
    let rows: Vec<Value> = serde_json::from_str(include_str!("data/sighash.json")).unwrap();
    let (mut spends, mut outputs, mut js3, mut js4) = (0, 0, 0, 0);
    for row in rows
        .iter()
        .filter_map(Value::as_array)
        .filter(|r| r.len() == 6)
    {
        let raw = from_hex(row[0].as_str().unwrap()).unwrap();
        let Ok(tx) = Transaction::parse(&raw) else {
            continue;
        };
        spends += usize::from(!tx.shielded_spends.is_empty());
        outputs += usize::from(!tx.shielded_outputs.is_empty());
        match tx.format {
            TxFormat::OverwinterV3 => js3 += usize::from(!tx.joinsplits.is_empty()),
            TxFormat::SaplingV4 => js4 += usize::from(!tx.joinsplits.is_empty()),
        }
    }
    assert!(spends > 0 && outputs > 0 && js3 > 0 && js4 > 0);
}
