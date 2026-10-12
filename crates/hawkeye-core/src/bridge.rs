//! Which foreign chain a bridge serves (NEAR plan §0 item 2, N-1, N-3, N-5): the one switch that
//! selects the vault tag, the lock destination's encoding and the memo magic.
//!
//! | Kind | Vault tag | Destination `OP_RETURN` | Memo magic |
//! |---|---|---|---|
//! | [`BridgeKind::Ethereum`] | `WYEC` | 12 zero bytes ‖ 20-byte address (plan §4.1) | `HKB1` |
//! | [`BridgeKind::Near`] | `NYEC` | `"NR1"` ‖ NEAR account id (NEAR plan §2.1) | `HKN1` |

use crate::template::{TAG_NYEC, TAG_WYEC};

/// The Ethereum memo magic, `"HKB1"` (plan §4.3).
pub const MEMO_MAGIC_ETHEREUM: [u8; 4] = *b"HKB1";
/// The NEAR memo magic, `"HKN1"` (NEAR plan §2.2).
pub const MEMO_MAGIC_NEAR: [u8; 4] = *b"HKN1";

/// The foreign chain of one bridge (one Hawkeye process serves one, NEAR plan §0 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BridgeKind {
    /// wYEC on Ethereum (`WyecBridge`).
    Ethereum,
    /// wYEC on NEAR (`wyec-near`).
    Near,
}

impl BridgeKind {
    /// Both kinds.
    pub const ALL: [Self; 2] = [Self::Ethereum, Self::Near];

    /// The vault tag of this bridge's locks.
    pub const fn tag(self) -> [u8; 4] {
        match self {
            Self::Ethereum => TAG_WYEC,
            Self::Near => TAG_NYEC,
        }
    }

    /// The magic of this bridge's memos.
    pub const fn memo_magic(self) -> [u8; 4] {
        match self {
            Self::Ethereum => MEMO_MAGIC_ETHEREUM,
            Self::Near => MEMO_MAGIC_NEAR,
        }
    }

    /// The kind whose vault tag is `tag`.
    pub fn from_tag(tag: &[u8; 4]) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == *tag)
    }

    /// The kind whose memo magic `magic` is.
    pub fn from_memo_magic(magic: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.memo_magic() == magic)
    }

    /// `"Ethereum"` or `"NEAR"` (messages).
    pub const fn title(self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::Near => "NEAR",
        }
    }

    /// `"ethereum"` or `"near"` (config and vector files).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Near => "near",
        }
    }
}

impl core::fmt::Display for BridgeKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for BridgeKind {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or(crate::Error::Near(
                "bridge kind is not \"ethereum\" or \"near\"",
            ))
    }
}

/// A guardian (an attestor as a bridge contract knows it), derived from its Ycash member key:
/// what a bridge's attestation signature recovers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Guardian {
    /// The Ethereum address of the member key (`keccak256(uncompressed)[12..]`).
    Ethereum(crate::eth::EthAddress),
    /// The 64-byte uncompressed secp256k1 key `x ‖ y` (NEAR plan §2.3: what `env::ecrecover`
    /// returns).
    Secp256k1([u8; 64]),
}

impl Guardian {
    /// The guardian as an account (Ethereum: its address; a NEAR guardian key is not one).
    pub fn account(&self) -> Option<crate::lock::Destination> {
        match self {
            Guardian::Ethereum(a) => Some(crate::lock::Destination::Ethereum(*a)),
            Guardian::Secp256k1(_) => None,
        }
    }

    /// The Ethereum address, if this is an Ethereum guardian.
    pub fn ledger_eth(&self) -> Option<crate::eth::EthAddress> {
        match self {
            Guardian::Ethereum(a) => Some(*a),
            Guardian::Secp256k1(_) => None,
        }
    }
}

impl core::fmt::Display for Guardian {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Guardian::Ethereum(a) => f.write_str(&a.to_checksum()),
            Guardian::Secp256k1(k) => {
                f.write_str("0x")?;
                for b in k {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guardians_display() {
        let a = crate::eth::EthAddress([0xab; 20]);
        assert_eq!(Guardian::Ethereum(a).to_string(), a.to_checksum());
        assert_eq!(
            Guardian::Secp256k1([1; 64]).to_string(),
            format!("0x{}", "01".repeat(64))
        );
        assert_eq!(Guardian::Secp256k1([1; 64]).account(), None);
        assert_eq!(Guardian::Ethereum(a).ledger_eth(), Some(a));
    }

    #[test]
    fn kinds() {
        assert_eq!(BridgeKind::Ethereum.tag(), *b"WYEC");
        assert_eq!(BridgeKind::Near.tag(), [0x4e, 0x59, 0x45, 0x43]);
        assert_eq!(BridgeKind::Ethereum.memo_magic(), *b"HKB1");
        assert_eq!(BridgeKind::Near.memo_magic(), *b"HKN1");
        for k in BridgeKind::ALL {
            assert_eq!(BridgeKind::from_tag(&k.tag()), Some(k));
            assert_eq!(BridgeKind::from_memo_magic(&k.memo_magic()), Some(k));
            assert_eq!(k.to_string().parse::<BridgeKind>().unwrap(), k);
            // never "YV" (an act, upgrade finding (27))
            assert!(!k.memo_magic().starts_with(b"YV"));
        }
        assert_eq!(BridgeKind::from_tag(b"YED\0"), None);
        assert_eq!(BridgeKind::from_memo_magic(b"HKB2"), None);
        assert_eq!(BridgeKind::from_memo_magic(b"HKB"), None);
        assert!("solana".parse::<BridgeKind>().is_err());
    }
}
