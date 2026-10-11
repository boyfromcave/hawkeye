//! The normative byte encodings of `docs/hawkeye-near-plan.md` §2.3 and §2.4, mirrored from
//! `hawkeye-core::near`. Pure functions: nothing here touches the NEAR host, so the same code
//! builds the digest inside the contract and in the tests.

use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::near;

/// Domain prefix of every attestation digest (N-6).
pub const DOMAIN: &[u8] = b"HawkeyeNear-v1";

/// A 64-byte uncompressed secp256k1 public key (x ‖ y, no `0x04`), as `env::ecrecover` returns it.
pub type GuardianKey = [u8; 64];

/// What a guardian signs (§2.3). The borsh enum tag is the variant index (0..=4).
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh])]
pub enum BridgeMessage {
    /// tag 0: mint `amount` zatoshi of wYEC to `receiver_id` for vault `lock_id` (either path).
    Mint {
        lock_id: [u8; 32],
        amount: u128,
        receiver_id: String,
    },
    /// tag 1: delete optimistic proposal `proposal_id` for `lock_id`.
    Challenge { lock_id: [u8; 32], proposal_id: u64 },
    /// tag 2: replace the guardian set (admin act).
    SetGuardians {
        guardians: Vec<GuardianKey>,
        threshold: u8,
        admin_nonce: u64,
    },
    /// tag 3: pause or unpause (admin act).
    SetPaused { paused: bool, admin_nonce: u64 },
    /// tag 4: set the mint rate limit (admin act).
    SetMintLimit {
        mint_cap: u128,
        cap_window_sec: u64,
        admin_nonce: u64,
    },
}

/// The `ycash_recipient` version byte (Hawkeye plan §4.2 revision 2).
pub const RECIPIENT_VERSION: u8 = 0x02;
/// Kind byte: pay to public key hash (20-byte hash160 follows; 22 bytes in all).
pub const RECIPIENT_KIND_P2PKH: u8 = 0x00;
/// Kind byte: pay to script hash (20-byte hash160 follows; 22 bytes in all).
pub const RECIPIENT_KIND_P2SH: u8 = 0x01;
/// Kind byte: the node's post-quantum `TX_PQPKH` (`scheme ‖ keyHash`, 33 bytes follow; 35 in all).
pub const RECIPIENT_KIND_PQPKH: u8 = 0x02;
/// Length of a P2PKH / P2SH recipient.
pub const RECIPIENT_LEN_HASH160: usize = 22;
/// Length of a PQPKH recipient: also the longest recipient, which `burn_storage_deposit` prices.
pub const RECIPIENT_LEN_PQPKH: usize = 35;
/// The §4.2 post-quantum schemes a PQPKH recipient may name: 1 SLH-DSA-SHA2-128s, 2 FN-DSA-512.
pub const RECIPIENT_SCHEMES: [u8; 2] = [0x01, 0x02];

/// One burn towards Ycash (§2.4, **BurnRecord v2**). `SHA256(borsh(record))` is the `data` field
/// of the `HKN1` memo.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh])]
pub struct BurnRecord {
    pub nonce: u64,
    pub from: String,
    pub amount: u128,
    /// Hawkeye plan §4.2 revision 2: `0x02`, kind (`0x00` P2PKH / `0x01` P2SH / `0x02` PQPKH),
    /// then a 20-byte hash160 or `scheme ‖ keyHash` (33 bytes): 22 or 35 bytes, validated by
    /// [`validate_recipient`] when burned. Borsh: `u32` LE length, then the bytes.
    pub ycash_recipient: Vec<u8>,
    pub block_height: u64,
    pub timestamp_ns: u64,
}

/// Checks a `ycash_recipient` exactly as the Ethereum `WyecBridge` does (Hawkeye plan §4.2
/// revision 2): 22 bytes for kind P2PKH / P2SH, 35 for kind PQPKH with a scheme of 1 or 2,
/// version `0x02`. Anything else would be an unredeemable burn, so it is refused with the
/// `wyec: …` message returned.
pub fn validate_recipient(r: &[u8]) -> Result<(), &'static str> {
    if r.len() != RECIPIENT_LEN_HASH160 && r.len() != RECIPIENT_LEN_PQPKH {
        return Err("wyec: ycash_recipient must be 22 or 35 bytes");
    }
    if r[0] != RECIPIENT_VERSION {
        return Err("wyec: ycash_recipient version must be 2");
    }
    match r[1] {
        RECIPIENT_KIND_P2PKH | RECIPIENT_KIND_P2SH => {
            if r.len() != RECIPIENT_LEN_HASH160 {
                return Err("wyec: a P2PKH or P2SH ycash_recipient must be 22 bytes");
            }
        }
        RECIPIENT_KIND_PQPKH => {
            if r.len() != RECIPIENT_LEN_PQPKH {
                return Err("wyec: a PQPKH ycash_recipient must be 35 bytes");
            }
            if !RECIPIENT_SCHEMES.contains(&r[2]) {
                return Err("wyec: ycash_recipient scheme must be 1 or 2");
            }
        }
        _ => return Err("wyec: ycash_recipient kind must be 0, 1 or 2"),
    }
    Ok(())
}

/// `"HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖ borsh(msg)`; its SHA-256 is the
/// digest a guardian signs.
pub fn digest_preimage(network_id: &str, contract_id: &str, msg: &BridgeMessage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(DOMAIN);
    // Writing into a Vec cannot fail.
    network_id.serialize(&mut buf).expect("vec write");
    contract_id.serialize(&mut buf).expect("vec write");
    msg.serialize(&mut buf).expect("vec write");
    buf
}

/// `borsh(record)`.
pub fn burn_record_bytes(record: &BurnRecord) -> Vec<u8> {
    borsh::to_vec(record).expect("vec write")
}

/// Decodes exactly `N` bytes of hex (either case, no `0x` prefix). `None` on any other input.
pub fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(b[2 * i])? << 4) | nibble(b[2 * i + 1])?;
    }
    Some(out)
}

/// Decodes hex of any even length up to `max` bytes (either case, no `0x` prefix). `None` on an
/// odd length, a non-hex character or more than `max` bytes.
pub fn decode_hex_vec(s: &str, max: usize) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || b.len() > 2 * max {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejects() {
        let x: [u8; 4] = decode_hex("00aBcDff").unwrap();
        assert_eq!(x, [0x00, 0xab, 0xcd, 0xff]);
        assert_eq!(encode_hex(&x), "00abcdff");
        assert!(decode_hex::<4>("00abcd").is_none());
        assert!(decode_hex::<4>("0x00abcd").is_none());
        assert!(decode_hex::<4>("00abcdzz").is_none());
    }

    /// The borsh layout written out by hand, byte for byte, against §2.3.
    #[test]
    fn preimage_layout_is_the_plan_s() {
        let msg = BridgeMessage::Mint {
            lock_id: [0x11; 32],
            amount: 0x0102,
            receiver_id: "alice.near".into(),
        };
        let mut want = b"HawkeyeNear-v1".to_vec();
        want.extend_from_slice(&7u32.to_le_bytes());
        want.extend_from_slice(b"testnet");
        want.extend_from_slice(&9u32.to_le_bytes());
        want.extend_from_slice(b"wyec.near");
        want.push(0); // Mint
        want.extend_from_slice(&[0x11; 32]);
        want.extend_from_slice(&0x0102u128.to_le_bytes());
        want.extend_from_slice(&10u32.to_le_bytes());
        want.extend_from_slice(b"alice.near");
        assert_eq!(digest_preimage("testnet", "wyec.near", &msg), want);

        let msg = BridgeMessage::SetGuardians {
            guardians: vec![[1; 64], [2; 64]],
            threshold: 2,
            admin_nonce: 5,
        };
        let mut want = vec![2u8];
        want.extend_from_slice(&2u32.to_le_bytes());
        want.extend_from_slice(&[1; 64]);
        want.extend_from_slice(&[2; 64]);
        want.push(2);
        want.extend_from_slice(&5u64.to_le_bytes());
        assert_eq!(borsh::to_vec(&msg).unwrap(), want);

        let tags: Vec<u8> = [
            BridgeMessage::Challenge {
                lock_id: [0; 32],
                proposal_id: 1,
            },
            BridgeMessage::SetPaused {
                paused: true,
                admin_nonce: 0,
            },
            BridgeMessage::SetMintLimit {
                mint_cap: 0,
                cap_window_sec: 0,
                admin_nonce: 0,
            },
        ]
        .iter()
        .map(|m| borsh::to_vec(m).unwrap()[0])
        .collect();
        assert_eq!(tags, [1, 3, 4]);
    }

    #[test]
    fn hex_vec_round_trip_and_rejects() {
        assert_eq!(decode_hex_vec("", 35), Some(vec![]));
        assert_eq!(decode_hex_vec("02Ab", 35), Some(vec![0x02, 0xab]));
        assert_eq!(decode_hex_vec(&"00".repeat(35), 35).unwrap().len(), 35);
        assert!(decode_hex_vec(&"00".repeat(36), 35).is_none());
        assert!(decode_hex_vec("0", 35).is_none());
        assert!(decode_hex_vec("0x02", 35).is_none());
        assert!(decode_hex_vec("zz", 35).is_none());
    }

    /// BurnRecord v2: the recipient is a borsh `Vec<u8>` (u32 LE length, then the bytes), so a
    /// 22-byte and a 35-byte record differ in length.
    #[test]
    fn burn_record_layout_is_the_plan_s() {
        for (recipient, len) in [
            (vec![0x02, 0x00, 0xee, 0xee, 0xee], 5usize),
            (
                [&[0x02u8, 0x02, 0x01][..], &[0x11; 32]].concat(),
                RECIPIENT_LEN_PQPKH,
            ),
        ] {
            assert_eq!(recipient.len(), len);
            let r = BurnRecord {
                nonce: 3,
                from: "bob.near".into(),
                amount: 5,
                ycash_recipient: recipient.clone(),
                block_height: 9,
                timestamp_ns: 10,
            };
            let mut want = 3u64.to_le_bytes().to_vec();
            want.extend_from_slice(&8u32.to_le_bytes());
            want.extend_from_slice(b"bob.near");
            want.extend_from_slice(&5u128.to_le_bytes());
            want.extend_from_slice(&(len as u32).to_le_bytes());
            want.extend_from_slice(&recipient);
            want.extend_from_slice(&9u64.to_le_bytes());
            want.extend_from_slice(&10u64.to_le_bytes());
            assert_eq!(burn_record_bytes(&r), want);
            assert_eq!(want.len(), 8 + 4 + 8 + 16 + 4 + len + 8 + 8);
        }
    }

    fn pqpkh(scheme: u8) -> Vec<u8> {
        [
            &[RECIPIENT_VERSION, RECIPIENT_KIND_PQPKH, scheme][..],
            &[0x33; 32],
        ]
        .concat()
    }

    fn hash160(kind: u8) -> Vec<u8> {
        [&[RECIPIENT_VERSION, kind][..], &[0x44; 20]].concat()
    }

    /// Every accept and reject branch of §4.2 revision 2.
    #[test]
    fn recipient_validation() {
        assert_eq!(validate_recipient(&hash160(RECIPIENT_KIND_P2PKH)), Ok(()));
        assert_eq!(validate_recipient(&hash160(RECIPIENT_KIND_P2SH)), Ok(()));
        assert_eq!(validate_recipient(&pqpkh(1)), Ok(()));
        assert_eq!(validate_recipient(&pqpkh(2)), Ok(()));

        let len = "wyec: ycash_recipient must be 22 or 35 bytes";
        assert_eq!(validate_recipient(&[]), Err(len));
        assert_eq!(validate_recipient(&[RECIPIENT_VERSION]), Err(len));
        assert_eq!(validate_recipient(&hash160(0)[..21]), Err(len));
        assert_eq!(
            validate_recipient(&[hash160(0).as_slice(), &[0]].concat()),
            Err(len)
        );
        // the retired 32-byte revision 1 form
        let mut v1 = vec![0u8; 32];
        v1[0] = 0x01;
        v1[12..].copy_from_slice(&[0x44; 20]);
        assert_eq!(validate_recipient(&v1), Err(len));
        assert_eq!(validate_recipient(&pqpkh(1)[..34]), Err(len));
        assert_eq!(
            validate_recipient(&[pqpkh(1).as_slice(), &[0]].concat()),
            Err(len)
        );

        let version = "wyec: ycash_recipient version must be 2";
        for v in [0x00, 0x01, 0x03, 0xff] {
            let mut r = hash160(0);
            r[0] = v;
            assert_eq!(validate_recipient(&r), Err(version), "{v}");
            let mut r = pqpkh(1);
            r[0] = v;
            assert_eq!(validate_recipient(&r), Err(version), "{v}");
        }

        let kind = "wyec: ycash_recipient kind must be 0, 1 or 2";
        for k in [0x03, 0x10, 0xff] {
            let mut r = hash160(0);
            r[1] = k;
            assert_eq!(validate_recipient(&r), Err(kind), "{k}");
            let mut r = pqpkh(1);
            r[1] = k;
            assert_eq!(validate_recipient(&r), Err(kind), "{k}");
        }

        // a kind with the other kind's length
        let mut r = pqpkh(1);
        r[1] = RECIPIENT_KIND_P2PKH;
        assert_eq!(
            validate_recipient(&r),
            Err("wyec: a P2PKH or P2SH ycash_recipient must be 22 bytes")
        );
        r[1] = RECIPIENT_KIND_P2SH;
        assert_eq!(
            validate_recipient(&r),
            Err("wyec: a P2PKH or P2SH ycash_recipient must be 22 bytes")
        );
        let mut r = hash160(0);
        r[1] = RECIPIENT_KIND_PQPKH;
        assert_eq!(
            validate_recipient(&r),
            Err("wyec: a PQPKH ycash_recipient must be 35 bytes")
        );

        let scheme = "wyec: ycash_recipient scheme must be 1 or 2";
        for s in [0x00, 0x03, 0xff] {
            assert_eq!(validate_recipient(&pqpkh(s)), Err(scheme), "{s}");
        }
    }
}
