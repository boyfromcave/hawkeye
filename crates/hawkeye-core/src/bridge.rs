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

#[cfg(test)]
mod tests {
    use super::*;

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
