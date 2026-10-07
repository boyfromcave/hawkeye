//! The Hawkeye memo (plan §4.3, HK-4): an `OP_RETURN` in every unlock naming the burn it pays
//! (kind 1) or the vault it rolls into (kind 2).
//!
//! ```text
//! magic    4   "HKB1"
//! kind     1   0x01 burn release | 0x02 roll
//! chainId  8   u64 LE
//! bridge  20   the WyecBridge address
//! ref      8   u64 LE: kind 1 → the burn nonce; kind 2 → the new V's ownerHeight
//! data    32   kind 1 → the burn's Ethereum txhash; kind 2 → SHA256(new V scriptPubKey)
//! ```
//!
//! The fields total **73** bytes; the plan's prose says 74, its field table (followed here)
//! sums to 73.
//! For kind 2 this crate carries the new vault's `ownerHeight` in `ref` and `SHA256(new V)` in
//! `data`, so that a watcher can rebuild the new V from the V being spent and check it against
//! the intent's `recipientHash` during the window; the plan's literal reading (`ref = 0`, `data`
//! a hash of the parameters) cannot be verified before the release reveals the V.

use crate::bytes::Hash32;
use crate::error::{Error, Result, array};
use crate::eth::EthAddress;
use crate::script::{is_op_return, op_return_script, op_return_single_push};
use crate::template::VaultParams;

/// The memo's magic, `"HKB1"`.
pub const MEMO_MAGIC: [u8; 4] = *b"HKB1";
/// The memo payload length.
pub const MEMO_LEN: usize = 73;

/// The memo's kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemoKind {
    /// A burn release: `ref` = burn nonce, `data` = burn txhash.
    BurnRelease = 1,
    /// A vault roll: `ref` = the new V's `ownerHeight`, `data` = `SHA256(new V)`.
    Roll = 2,
}

/// The bridge deployment a memo (and a burn) belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Deployment {
    /// The Ethereum chain id (1 mainnet, 11155111 Sepolia, 31337 anvil).
    pub chain_id: u64,
    /// The `WyecBridge` address.
    pub bridge: EthAddress,
}

/// A decoded Hawkeye memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HawkeyeMemo {
    /// Burn release or roll.
    pub kind: MemoKind,
    /// The deployment.
    pub deployment: Deployment,
    /// Kind 1: the burn nonce. Kind 2: the new V's `ownerHeight`.
    pub reference: u64,
    /// Kind 1: the burn's txhash. Kind 2: `SHA256(new V scriptPubKey)`.
    pub data: Hash32,
}

impl HawkeyeMemo {
    /// The memo for releasing burn `nonce` (Ethereum tx `tx_hash`).
    pub fn burn_release(deployment: Deployment, nonce: u64, tx_hash: Hash32) -> Self {
        Self {
            kind: MemoKind::BurnRelease,
            deployment,
            reference: nonce,
            data: tx_hash,
        }
    }

    /// The memo for rolling a vault into `new_vault`.
    pub fn roll(deployment: Deployment, new_vault: &VaultParams) -> Result<Self> {
        Ok(Self {
            kind: MemoKind::Roll,
            deployment,
            reference: u64::from(new_vault.owner_height),
            data: new_vault.script_hash()?,
        })
    }

    /// The 73-byte payload.
    pub fn encode(&self) -> [u8; MEMO_LEN] {
        let mut b = [0u8; MEMO_LEN];
        b[..4].copy_from_slice(&MEMO_MAGIC);
        b[4] = self.kind as u8;
        b[5..13].copy_from_slice(&self.deployment.chain_id.to_le_bytes());
        b[13..33].copy_from_slice(self.deployment.bridge.as_bytes());
        b[33..41].copy_from_slice(&self.reference.to_le_bytes());
        b[41..].copy_from_slice(&self.data);
        b
    }

    /// Strictly decode a payload: exact length, magic, known kind; a roll's `ref` must be a
    /// valid `ownerHeight`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let b: [u8; MEMO_LEN] = array("memo", b)?;
        if b[..4] != MEMO_MAGIC {
            return Err(Error::Memo("bad magic"));
        }
        let kind = match b[4] {
            1 => MemoKind::BurnRelease,
            2 => MemoKind::Roll,
            _ => return Err(Error::Memo("unknown kind")),
        };
        let le = |r: core::ops::Range<usize>| u64::from_le_bytes(b[r].try_into().expect("8"));
        let m = Self {
            kind,
            deployment: Deployment {
                chain_id: le(5..13),
                bridge: EthAddress(b[13..33].try_into().expect("20")),
            },
            reference: le(33..41),
            data: b[41..].try_into().expect("32"),
        };
        if kind == MemoKind::Roll
            && !(u64::from(crate::template::OWNER_HEIGHT_MIN)
                ..=u64::from(crate::template::OWNER_HEIGHT_MAX))
                .contains(&m.reference)
        {
            return Err(Error::Memo("roll ownerHeight out of range"));
        }
        Ok(m)
    }

    /// `OP_RETURN <73 bytes>`.
    pub fn to_script(&self) -> Vec<u8> {
        op_return_script(&self.encode())
    }

    /// For a roll memo: the new V, rebuilt from the V being spent with this memo's
    /// `ownerHeight` (every other field kept), checked against `data`.
    pub fn rolled_vault(&self, spent: &VaultParams) -> Result<VaultParams> {
        if self.kind != MemoKind::Roll {
            return Err(Error::Memo("not a roll memo"));
        }
        let new = VaultParams {
            owner_height: u32::try_from(self.reference)
                .map_err(|_| Error::Memo("roll ownerHeight out of range"))?,
            ..*spent
        };
        if new.script_hash()? != self.data {
            return Err(Error::Memo("roll data is not SHA256 of the rebuilt V"));
        }
        Ok(new)
    }
}

/// True if `spk` is an `OP_RETURN` whose first push begins `"HKB1"` (it then must parse).
pub fn is_memo_script(spk: &[u8]) -> bool {
    if !is_op_return(spk) {
        return false;
    }
    matches!(
        crate::script::ops(&spk[1..]).next(),
        Some(Ok(op)) if op.data.is_some_and(|d| d.starts_with(&MEMO_MAGIC))
    )
}

/// Parse a memo output: `Ok(None)` if `spk` is not a memo at all, an error if it claims to be
/// one (see [`is_memo_script`]) and is malformed, else the memo.
pub fn parse_memo_script(spk: &[u8]) -> Result<Option<HawkeyeMemo>> {
    if !is_memo_script(spk) {
        return Ok(None);
    }
    let data = op_return_single_push(spk).ok_or(Error::Memo("not one canonical push"))?;
    HawkeyeMemo::decode(data).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::push;

    fn dep() -> Deployment {
        Deployment {
            chain_id: 11_155_111,
            bridge: EthAddress([0xbb; 20]),
        }
    }

    #[test]
    fn burn_memo_layout() {
        let m = HawkeyeMemo::burn_release(dep(), 0x0102, [0xcc; 32]);
        let b = m.encode();
        assert_eq!(
            hex::encode(b),
            format!(
                "484b423101{}{}{}{}",
                "a736aa0000000000",
                "bb".repeat(20),
                "0201000000000000",
                "cc".repeat(32)
            )
        );
        assert_eq!(HawkeyeMemo::decode(&b).unwrap(), m);
        let s = m.to_script();
        assert_eq!(s.len(), 75);
        assert_eq!(&s[..2], &[0x6a, 73]);
        assert_eq!(parse_memo_script(&s).unwrap(), Some(m));
        assert!(is_memo_script(&s));
    }

    #[test]
    fn roll_memo() {
        let spent = VaultParams {
            tag: *b"WYEC",
            set_id: [1; 32],
            cancel_set_id: [1; 32],
            delay: 6,
            owner_height: 100,
            app_height: 0,
            owner_key: [2; 33],
        };
        let new = VaultParams {
            owner_height: 5000,
            ..spent
        };
        let m = HawkeyeMemo::roll(dep(), &new).unwrap();
        assert_eq!(m.reference, 5000);
        let d = HawkeyeMemo::decode(&m.encode()).unwrap();
        assert_eq!(d.rolled_vault(&spent).unwrap(), new);
        // a different spent vault (another owner key) does not rebuild to the same hash
        let other = VaultParams {
            owner_key: [3; 33],
            ..spent
        };
        assert!(d.rolled_vault(&other).is_err());
        let burn = HawkeyeMemo::burn_release(dep(), 1, [0; 32]);
        assert!(burn.rolled_vault(&spent).is_err());
        let mut b = m.encode();
        b[33..41].copy_from_slice(&0u64.to_le_bytes());
        assert!(HawkeyeMemo::decode(&b).is_err());
    }

    #[test]
    fn rejects() {
        let good = HawkeyeMemo::burn_release(dep(), 7, [0; 32]).encode();
        let mut b = good;
        b[3] = b'2';
        assert_eq!(HawkeyeMemo::decode(&b), Err(Error::Memo("bad magic")));
        let mut b = good;
        b[4] = 3;
        assert_eq!(HawkeyeMemo::decode(&b), Err(Error::Memo("unknown kind")));
        assert!(HawkeyeMemo::decode(&good[..72]).is_err());
        assert!(HawkeyeMemo::decode(&[good.as_slice(), &[0]].concat()).is_err());

        // not memos at all
        assert_eq!(parse_memo_script(&[0x76]).unwrap(), None);
        assert_eq!(
            parse_memo_script(&op_return_script(&[0; 32])).unwrap(),
            None
        );
        assert_eq!(
            parse_memo_script(&op_return_script(b"YV\x01\x03")).unwrap(),
            None
        );
        // claims to be a memo, malformed
        assert!(parse_memo_script(&op_return_script(b"HKB1\x01")).is_err());
        let mut two = HawkeyeMemo::burn_release(dep(), 7, [0; 32]).to_script();
        two.extend_from_slice(&push(&[1]));
        assert!(parse_memo_script(&two).is_err());
        let mut nc = vec![0x6a, 0x4c, 73];
        nc.extend_from_slice(&good);
        assert!(parse_memo_script(&nc).is_err());
    }
}
