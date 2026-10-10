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

/// One burn towards Ycash (§2.4). `SHA256(borsh(record))` is the `data` field of the `HKN1` memo.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh])]
pub struct BurnRecord {
    pub nonce: u64,
    pub from: String,
    pub amount: u128,
    /// Hawkeye plan §4.2: version, kind, 10 zero bytes, hash160. Opaque to the contract.
    pub ycash_recipient: [u8; 32],
    pub block_height: u64,
    pub timestamp_ns: u64,
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
    fn burn_record_layout_is_the_plan_s() {
        let r = BurnRecord {
            nonce: 3,
            from: "bob.near".into(),
            amount: 5,
            ycash_recipient: [0xee; 32],
            block_height: 9,
            timestamp_ns: 10,
        };
        let mut want = 3u64.to_le_bytes().to_vec();
        want.extend_from_slice(&8u32.to_le_bytes());
        want.extend_from_slice(b"bob.near");
        want.extend_from_slice(&5u128.to_le_bytes());
        want.extend_from_slice(&[0xee; 32]);
        want.extend_from_slice(&9u64.to_le_bytes());
        want.extend_from_slice(&10u64.to_le_bytes());
        assert_eq!(burn_record_bytes(&r), want);
    }
}
