//! The Hawkeye memo (plan §4.3, HK-4; NEAR plan §2.2, N-5): an `OP_RETURN` in every unlock
//! naming the burn it pays (kind 1) or the vault it rolls into (kind 2).
//!
//! ```text
//! magic    4   "HKB1" (Ethereum) | "HKN1" (NEAR)
//! kind     1   0x01 burn release | 0x02 roll
//! chainId  8   u64 LE: Ethereum → the chain id; NEAR → SHA256("near:" ‖ network_id)[..8]
//! bridge  20   Ethereum → the WyecBridge address; NEAR → SHA256(contract id)[..20]
//! ref      8   u64 LE: kind 1 → the burn nonce; kind 2 → the new V's ownerHeight
//! data    32   kind 1 → Ethereum: the burn's txhash; NEAR: SHA256(borsh(BurnRecord))
//!              kind 2 → SHA256(new V scriptPubKey)
//! ```
//!
//! The magic says which bridge a memo is for ([`HawkeyeMemo::bridge_kind`]). The functions
//! without a kind ([`HawkeyeMemo::decode`], [`is_memo_script`], [`parse_memo_script`],
//! [`HawkeyeMemo::burn_release`], [`HawkeyeMemo::roll`]) are the Ethereum bridge's, unchanged;
//! the `_for` forms take the kind, and the `_any` forms recognise both magics (the matcher's
//! view: a memo of the other bridge is a memo, for the wrong deployment).
//!
//! The fields total **73** bytes; the plan's prose says 74, its field table (followed here)
//! sums to 73.
//! For kind 2 this crate carries the new vault's `ownerHeight` in `ref` and `SHA256(new V)` in
//! `data`, so that a watcher can rebuild the new V from the V being spent and check it against
//! the intent's `recipientHash` during the window; the plan's literal reading (`ref = 0`, `data`
//! a hash of the parameters) cannot be verified before the release reveals the V.

use crate::bridge::BridgeKind;
use crate::bytes::Hash32;
use crate::error::{Error, Result, array};
use crate::eth::EthAddress;
use crate::script::{is_op_return, op_return_script, op_return_single_push};
use crate::template::VaultParams;

/// The Ethereum memo's magic, `"HKB1"`.
pub const MEMO_MAGIC: [u8; 4] = crate::bridge::MEMO_MAGIC_ETHEREUM;
/// The NEAR memo's magic, `"HKN1"`.
pub const MEMO_MAGIC_NEAR: [u8; 4] = crate::bridge::MEMO_MAGIC_NEAR;
/// The memo payload length.
pub const MEMO_LEN: usize = 73;

/// The memo's kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemoKind {
    /// A burn release: `ref` = burn nonce, `data` = burn txhash (NEAR: burn record hash).
    BurnRelease = 1,
    /// A vault roll: `ref` = the new V's `ownerHeight`, `data` = `SHA256(new V)`.
    Roll = 2,
}

/// The bridge deployment a memo (and a burn) belongs to.
///
/// For NEAR ([`crate::near::Domain::deployment`]) `chain_id` and `bridge` are the hashes of
/// NEAR plan §2.2; the 20 `bridge` bytes are then not an Ethereum address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Deployment {
    /// The Ethereum chain id (1 mainnet, 11155111 Sepolia, 31337 anvil), or NEAR's hashed
    /// network id.
    pub chain_id: u64,
    /// The `WyecBridge` address, or NEAR's hashed contract id.
    pub bridge: EthAddress,
}

/// A decoded Hawkeye memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HawkeyeMemo {
    /// The bridge, from the magic (`HKB1` Ethereum, `HKN1` NEAR).
    pub bridge_kind: BridgeKind,
    /// Burn release or roll.
    pub kind: MemoKind,
    /// The deployment.
    pub deployment: Deployment,
    /// Kind 1: the burn nonce. Kind 2: the new V's `ownerHeight`.
    pub reference: u64,
    /// Kind 1: the burn's txhash (NEAR: `SHA256(borsh(BurnRecord))`). Kind 2:
    /// `SHA256(new V scriptPubKey)`.
    pub data: Hash32,
}

impl HawkeyeMemo {
    /// The Ethereum memo for releasing burn `nonce` (Ethereum tx `tx_hash`).
    pub fn burn_release(deployment: Deployment, nonce: u64, tx_hash: Hash32) -> Self {
        Self::burn_release_for(BridgeKind::Ethereum, deployment, nonce, tx_hash)
    }

    /// The memo of bridge `bridge_kind` for releasing burn `nonce`; `data` is the burn's
    /// Ethereum txhash or NEAR [`crate::near::BurnRecord::hash`].
    pub fn burn_release_for(
        bridge_kind: BridgeKind,
        deployment: Deployment,
        nonce: u64,
        data: Hash32,
    ) -> Self {
        Self {
            bridge_kind,
            kind: MemoKind::BurnRelease,
            deployment,
            reference: nonce,
            data,
        }
    }

    /// The Ethereum memo for rolling a vault into `new_vault`.
    pub fn roll(deployment: Deployment, new_vault: &VaultParams) -> Result<Self> {
        Self::roll_for(BridgeKind::Ethereum, deployment, new_vault)
    }

    /// The memo of bridge `bridge_kind` for rolling a vault into `new_vault`.
    pub fn roll_for(
        bridge_kind: BridgeKind,
        deployment: Deployment,
        new_vault: &VaultParams,
    ) -> Result<Self> {
        Ok(Self {
            bridge_kind,
            kind: MemoKind::Roll,
            deployment,
            reference: u64::from(new_vault.owner_height),
            data: new_vault.script_hash()?,
        })
    }

    /// Whether this memo is for deployment `deployment` of bridge `bridge_kind`.
    pub fn is_for(&self, bridge_kind: BridgeKind, deployment: &Deployment) -> bool {
        self.bridge_kind == bridge_kind && self.deployment == *deployment
    }

    /// The 73-byte payload.
    pub fn encode(&self) -> [u8; MEMO_LEN] {
        let mut b = [0u8; MEMO_LEN];
        b[..4].copy_from_slice(&self.bridge_kind.memo_magic());
        b[4] = self.kind as u8;
        b[5..13].copy_from_slice(&self.deployment.chain_id.to_le_bytes());
        b[13..33].copy_from_slice(self.deployment.bridge.as_bytes());
        b[33..41].copy_from_slice(&self.reference.to_le_bytes());
        b[41..].copy_from_slice(&self.data);
        b
    }

    /// Strictly decode an Ethereum (`HKB1`) payload: exact length, magic, known kind; a roll's
    /// `ref` must be a valid `ownerHeight`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        Self::decode_for(BridgeKind::Ethereum, b)
    }

    /// Strictly decode a payload of bridge `bridge_kind` (its magic only).
    pub fn decode_for(bridge_kind: BridgeKind, b: &[u8]) -> Result<Self> {
        let m = Self::decode_any(b)?;
        if m.bridge_kind != bridge_kind {
            return Err(Error::Memo("bad magic"));
        }
        Ok(m)
    }

    /// Strictly decode a payload of either bridge (`HKB1` or `HKN1`).
    pub fn decode_any(b: &[u8]) -> Result<Self> {
        let b: [u8; MEMO_LEN] = array("memo", b)?;
        let Some(bridge_kind) = BridgeKind::from_memo_magic(&b[..4]) else {
            return Err(Error::Memo("bad magic"));
        };
        let kind = match b[4] {
            1 => MemoKind::BurnRelease,
            2 => MemoKind::Roll,
            _ => return Err(Error::Memo("unknown kind")),
        };
        let le = |r: core::ops::Range<usize>| u64::from_le_bytes(b[r].try_into().expect("8"));
        let m = Self {
            bridge_kind,
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

/// The bridge whose magic the first push of `OP_RETURN` script `spk` begins with.
fn claimed_kind(spk: &[u8]) -> Option<BridgeKind> {
    if !is_op_return(spk) {
        return None;
    }
    match crate::script::ops(&spk[1..]).next() {
        Some(Ok(op)) => op.data.and_then(|d| {
            BridgeKind::ALL
                .into_iter()
                .find(|k| d.starts_with(&k.memo_magic()))
        }),
        _ => None,
    }
}

/// True if `spk` is an `OP_RETURN` whose first push begins `"HKB1"` (it then must parse).
pub fn is_memo_script(spk: &[u8]) -> bool {
    is_memo_script_for(BridgeKind::Ethereum, spk)
}

/// True if `spk` is an `OP_RETURN` whose first push begins bridge `bridge_kind`'s magic.
pub fn is_memo_script_for(bridge_kind: BridgeKind, spk: &[u8]) -> bool {
    claimed_kind(spk) == Some(bridge_kind)
}

/// True if `spk` is an `OP_RETURN` whose first push begins `"HKB1"` or `"HKN1"`.
pub fn is_any_memo_script(spk: &[u8]) -> bool {
    claimed_kind(spk).is_some()
}

/// Parse an Ethereum memo output: `Ok(None)` if `spk` is not an `HKB1` memo at all, an error
/// if it claims to be one (see [`is_memo_script`]) and is malformed, else the memo.
pub fn parse_memo_script(spk: &[u8]) -> Result<Option<HawkeyeMemo>> {
    parse_memo_script_for(BridgeKind::Ethereum, spk)
}

/// [`parse_memo_script`] for bridge `bridge_kind`: a memo of the other bridge is `Ok(None)`.
pub fn parse_memo_script_for(bridge_kind: BridgeKind, spk: &[u8]) -> Result<Option<HawkeyeMemo>> {
    if !is_memo_script_for(bridge_kind, spk) {
        return Ok(None);
    }
    parse_any_memo_script(spk)
}

/// Parse a memo output of either bridge: `Ok(None)` if `spk` claims neither magic.
pub fn parse_any_memo_script(spk: &[u8]) -> Result<Option<HawkeyeMemo>> {
    if !is_any_memo_script(spk) {
        return Ok(None);
    }
    let data = op_return_single_push(spk).ok_or(Error::Memo("not one canonical push"))?;
    HawkeyeMemo::decode_any(data).map(Some)
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

    #[test]
    fn near_memos() {
        let ndep = crate::near::Domain::new(
            "testnet",
            crate::near::AccountId::parse("wyec.testnet").unwrap(),
        )
        .unwrap()
        .deployment();
        let m = HawkeyeMemo::burn_release_for(BridgeKind::Near, ndep, 3, [0xdd; 32]);
        let b = m.encode();
        assert_eq!(&b[..5], b"HKN1\x01");
        assert_eq!(&b[5..13], &ndep.chain_id.to_le_bytes());
        assert_eq!(&b[13..33], ndep.bridge.as_bytes());
        // same layout as HKB1 but for the magic
        let e = HawkeyeMemo::burn_release(ndep, 3, [0xdd; 32]);
        assert_eq!(e.bridge_kind, BridgeKind::Ethereum);
        assert_eq!(&e.encode()[4..], &b[4..]);
        assert_eq!(HawkeyeMemo::decode_any(&b).unwrap(), m);
        assert_eq!(HawkeyeMemo::decode_for(BridgeKind::Near, &b).unwrap(), m);
        // the Ethereum decoder (and every kind-less function) is HKB1 only
        assert_eq!(HawkeyeMemo::decode(&b), Err(Error::Memo("bad magic")));
        assert_eq!(
            HawkeyeMemo::decode_for(BridgeKind::Ethereum, &b),
            Err(Error::Memo("bad magic"))
        );
        let s = m.to_script();
        assert!(!is_memo_script(&s));
        assert!(is_memo_script_for(BridgeKind::Near, &s));
        assert!(is_any_memo_script(&s));
        assert_eq!(parse_memo_script(&s).unwrap(), None);
        assert_eq!(
            parse_memo_script_for(BridgeKind::Near, &s).unwrap(),
            Some(m)
        );
        assert_eq!(parse_any_memo_script(&s).unwrap(), Some(m));
        assert_eq!(parse_any_memo_script(&e.to_script()).unwrap(), Some(e));
        assert_eq!(
            parse_memo_script_for(BridgeKind::Near, &e.to_script()).unwrap(),
            None
        );
        assert!(m.is_for(BridgeKind::Near, &ndep));
        assert!(!m.is_for(BridgeKind::Ethereum, &ndep));
        assert!(!e.is_for(BridgeKind::Near, &ndep));
        assert!(!m.is_for(BridgeKind::Near, &dep()));
        assert_eq!(parse_any_memo_script(&[0x76]).unwrap(), None);
        assert_eq!(
            parse_any_memo_script(&op_return_script(b"HKX1")).unwrap(),
            None
        );
        assert!(parse_any_memo_script(&op_return_script(b"HKN1\x02")).is_err());
        assert!(!is_any_memo_script(&[0x6a, 0x4c]));

        let spent = VaultParams {
            tag: *b"NYEC",
            set_id: [1; 32],
            cancel_set_id: [1; 32],
            delay: 6,
            owner_height: 100,
            app_height: 0,
            owner_key: [2; 33],
        };
        let new = VaultParams {
            owner_height: 7000,
            ..spent
        };
        let r = HawkeyeMemo::roll_for(BridgeKind::Near, ndep, &new).unwrap();
        assert_eq!(&r.encode()[..5], b"HKN1\x02");
        let d = HawkeyeMemo::decode_any(&r.encode()).unwrap();
        assert_eq!(d.rolled_vault(&spent).unwrap(), new);
    }
}
