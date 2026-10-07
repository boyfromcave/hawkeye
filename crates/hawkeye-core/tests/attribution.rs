//! `attribute_template_input` against the node's template spends (`vault_vectors.json`
//! `spends`, ycash-dd `dbc1ab0`): each attributes to exactly its recorded signers with the
//! recorded sighash; every way the input can be wrong is refused or names other keys.

use hawkeye_core::attribution::{VAULT_BRANCH_ID, attribute_template_input};
use hawkeye_core::bytes::{OutPoint, from_hex, from_hex_array};
use hawkeye_core::script::{OP_1, OP_2, OP_3, p2pkh_script};
use hawkeye_core::setsig::Role;
use hawkeye_core::sighash::{SIGHASH_ALL, zip243};
use hawkeye_core::tx::Transaction;
use hawkeye_core::{Error, PubKey33};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("data/vault_vectors.json")).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().unwrap()).unwrap()
}

struct Spend {
    name: String,
    tx: Vec<u8>,
    n_in: usize,
    spk: Vec<u8>,
    amount: u64,
    branch: u32,
    sighash: [u8; 32],
    set_id: [u8; 32],
    role: u8,
    set_sig_msg: Vec<u8>,
    sigs: Vec<Vec<u8>>,
    signers: Vec<PubKey33>,
}

fn spends() -> Vec<Spend> {
    let v = vectors();
    let keys: Vec<(String, PubKey33)> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            (
                k["label"].as_str().unwrap().to_owned(),
                from_hex_array("key", k["pubkey"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let out: Vec<Spend> = v["spends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Spend {
            name: c["name"].as_str().unwrap().to_owned(),
            tx: hx(&c["tx"]),
            n_in: c["nIn"].as_u64().unwrap() as usize,
            spk: hx(&c["scriptCode"]),
            amount: c["amount"].as_u64().unwrap(),
            branch: c["branchId"].as_u64().unwrap() as u32,
            sighash: from_hex_array("sighash", c["sighash"].as_str().unwrap()).unwrap(),
            set_id: from_hex_array("setId", c["setId"].as_str().unwrap()).unwrap(),
            role: c["role"].as_u64().unwrap() as u8,
            set_sig_msg: hx(&c["setSigMsg"]),
            sigs: c["sigs"].as_array().unwrap().iter().map(hx).collect(),
            signers: c["signers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    keys.iter()
                        .find(|(l, _)| l == s.as_str().unwrap())
                        .unwrap()
                        .1
                })
                .collect(),
        })
        .collect();
    assert!(out.iter().any(|s| s.role == 1) && out.iter().any(|s| s.role == 2));
    out
}

fn with_script_sig(tx: &[u8], n_in: usize, script_sig: Vec<u8>) -> Vec<u8> {
    let mut t = Transaction::parse(tx).unwrap();
    t.vin[n_in].script_sig = script_sig;
    t.to_bytes().unwrap()
}

/// A scriptSig of the given pushes (each 65 or 64 bytes) and a final opcode.
fn script_sig(args: &[&[u8]], last: u8) -> Vec<u8> {
    let mut s = Vec::new();
    for a in args {
        s.push(a.len() as u8);
        s.extend_from_slice(a);
    }
    s.push(last);
    s
}

#[test]
fn spends_attribute_to_recorded_signers() {
    for s in spends() {
        assert_eq!(s.branch, VAULT_BRANCH_ID, "{}", s.name);
        let tx = Transaction::parse(&s.tx).unwrap();
        assert_eq!(tx.to_bytes().unwrap(), s.tx, "{} round trip", s.name);
        assert_eq!(
            zip243(&tx, s.n_in, &s.spk, s.amount, SIGHASH_ALL, s.branch).unwrap(),
            s.sighash,
            "{} sighash",
            s.name
        );

        let a = attribute_template_input(&s.tx, s.n_in, &s.spk, s.amount, s.branch).unwrap();
        assert_eq!(a.sighash, s.sighash, "{}", s.name);
        assert_eq!(a.set_id, s.set_id, "{}", s.name);
        assert_eq!(a.role.byte(), s.role, "{}", s.name);
        assert_eq!(a.prevout, tx.vin[s.n_in].prevout, "{}", s.name);
        assert_eq!(a.set_sig_msg().to_vec(), s.set_sig_msg, "{}", s.name);
        let keys: Vec<PubKey33> = a.signers.iter().map(|x| x.pubkey).collect();
        assert_eq!(keys, s.signers, "{} signers", s.name);
        let sigs: Vec<Vec<u8>> = a.signers.iter().map(|x| x.signature.to_vec()).collect();
        assert_eq!(sigs, s.sigs, "{} sigs", s.name);
    }
}

#[test]
fn roles() {
    for s in spends() {
        let a = attribute_template_input(&s.tx, s.n_in, &s.spk, s.amount, s.branch).unwrap();
        let want = if s.role == 1 {
            Role::Unlock
        } else {
            Role::Cancel
        };
        assert_eq!(a.role, want);
    }
}

/// Anything the sighash commits to, changed, names other keys (never the recorded signers).
#[test]
fn sighash_binds_amount_branch_and_tx() {
    for s in spends() {
        let others = |a: hawkeye_core::attribution::Attribution| {
            assert_ne!(a.sighash, s.sighash, "{}", s.name);
            for x in &a.signers {
                assert!(!s.signers.contains(&x.pubkey), "{}", s.name);
            }
        };
        others(attribute_template_input(&s.tx, s.n_in, &s.spk, s.amount + 1, s.branch).unwrap());
        others(attribute_template_input(&s.tx, s.n_in, &s.spk, s.amount, 0x76b8_09bb).unwrap());
        let mut t = Transaction::parse(&s.tx).unwrap();
        t.vout[0].value -= 1;
        others(
            attribute_template_input(&t.to_bytes().unwrap(), s.n_in, &s.spk, s.amount, s.branch)
                .unwrap(),
        );
        let mut t = Transaction::parse(&s.tx).unwrap();
        t.lock_time += 1;
        others(
            attribute_template_input(&t.to_bytes().unwrap(), s.n_in, &s.spk, s.amount, s.branch)
                .unwrap(),
        );
    }
}

#[test]
fn wrong_selector() {
    for s in spends() {
        let sigs: Vec<&[u8]> = s.sigs.iter().map(Vec::as_slice).collect();
        // V: OWNER (2), OWNER-RELEASED (3); I: RELEASE (1), OWNER-RELEASED (3).
        let wrong: &[u8] = if s.role == 1 {
            &[OP_2, OP_3]
        } else {
            &[OP_1, OP_3]
        };
        for &op in wrong {
            let tx = with_script_sig(&s.tx, s.n_in, script_sig(&sigs, op));
            assert!(
                matches!(
                    attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
                    Err(Error::Selector(_))
                ),
                "{} selector {op:#x}",
                s.name
            );
        }
        // selector pushed as data, not as the opcode
        let mut ss = script_sig(&sigs, 0x01); // a one-byte push …
        ss.push(s.role); // … of the selector value
        let tx = with_script_sig(&s.tx, s.n_in, ss);
        assert!(matches!(
            attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Selector(_))
        ));
        // no signatures at all
        let sel = if s.role == 1 { OP_1 } else { OP_2 };
        let tx = with_script_sig(&s.tx, s.n_in, vec![sel]);
        assert_eq!(
            attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Selector("no set signatures"))
        );
        // not push-only
        let tx = with_script_sig(&s.tx, s.n_in, vec![0x76, sel]);
        assert!(matches!(
            attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Selector(_))
        ));
    }
}

#[test]
fn not_a_template() {
    for s in spends() {
        let p2pkh = p2pkh_script(&[7; 20]);
        assert!(matches!(
            attribute_template_input(&s.tx, s.n_in, &p2pkh, s.amount, s.branch),
            Err(Error::Template(_))
        ));
        assert!(matches!(
            attribute_template_input(&s.tx, s.n_in, &[], s.amount, s.branch),
            Err(Error::Template(_))
        ));
        // template-shaped but a field out of range: corrupt the 4-byte tag push into 3 bytes
        let mut bad = s.spk.clone();
        bad[0] = 0x03;
        bad.remove(1);
        assert!(attribute_template_input(&s.tx, s.n_in, &bad, s.amount, s.branch).is_err());
    }
}

#[test]
fn malformed_signatures() {
    for s in spends() {
        let sel = if s.role == 1 { OP_1 } else { OP_2 };
        let good = s.sigs[0].clone();
        // header outside 31..34 (an uncompressed-key signmessage header)
        let mut h = good.clone();
        h[0] = 27;
        // high S: s → n − s
        let mut high = good.clone();
        high[33..].copy_from_slice(&negate_s(&good[33..]));
        // r = 0
        let mut zero_r = good.clone();
        zero_r[1..33].fill(0);
        for (what, sig) in [("header", h), ("high S", high), ("r = 0", zero_r)] {
            let tx = with_script_sig(&s.tx, s.n_in, script_sig(&[&sig], sel));
            assert!(
                matches!(
                    attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
                    Err(Error::Signature(_))
                ),
                "{} {what}",
                s.name
            );
        }
        // 64 bytes
        let tx = with_script_sig(&s.tx, s.n_in, script_sig(&[&good[..64]], sel));
        assert!(matches!(
            attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Length { .. })
        ));
        // one bad signature among good ones fails the whole input
        let mut sigs: Vec<&[u8]> = s.sigs.iter().map(Vec::as_slice).collect();
        sigs.push(&good[..64]);
        let tx = with_script_sig(&s.tx, s.n_in, script_sig(&sigs, sel));
        assert!(attribute_template_input(&tx, s.n_in, &s.spk, s.amount, s.branch).is_err());
    }
}

#[test]
fn bad_transaction_or_index() {
    for s in spends() {
        let n = Transaction::parse(&s.tx).unwrap().vin.len();
        assert_eq!(
            attribute_template_input(&s.tx, n, &s.spk, s.amount, s.branch),
            Err(Error::Tx("input index out of range"))
        );
        // the other input is a plain coin (empty scriptSig): not a template scriptSig
        let other = 1 - s.n_in;
        assert!(attribute_template_input(&s.tx, other, &s.spk, s.amount, s.branch).is_err());
        assert!(matches!(
            attribute_template_input(&s.tx[..s.tx.len() - 1], s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Tx(_))
        ));
        let mut v1 = s.tx.clone();
        v1[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            attribute_template_input(&v1, s.n_in, &s.spk, s.amount, s.branch),
            Err(Error::Tx(_))
        ));
    }
}

/// The prevout reported is the input's, in internal order.
#[test]
fn prevout_is_internal_order() {
    for s in spends() {
        let a = attribute_template_input(&s.tx, s.n_in, &s.spk, s.amount, s.branch).unwrap();
        let pos = 9; // header, group id, vin count; the spends' template input is input 0
        assert_eq!(s.n_in, 0);
        assert_eq!(
            a.prevout,
            OutPoint::from_bytes(&s.tx[pos..pos + 36]).unwrap()
        );
    }
}

/// n − s for a 32-byte big-endian s (secp256k1 order).
fn negate_s(s: &[u8]) -> [u8; 32] {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(N[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[i] = d as u8;
    }
    out
}
