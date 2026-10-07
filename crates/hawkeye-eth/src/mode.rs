//! How mints reach Ethereum (plan §0 item 4, §3.3, CR-W1).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Ethereum mainnet's chain id.
pub const MAINNET: u64 = 1;

/// The mint path Hawkeye uses.
///
/// - `Threshold { k }`: today's `WyecBridge.mint`, immediate, `k` guardian signatures.
/// - `Optimistic`: CR-W1's `proposeMint` (one guardian signature) → challenge window →
///   `executeMint`; any guardian may `challengeMint`. Until wyec ships CR-W1 this runs only
///   against the anvil test double.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum MintMode {
    Threshold { k: u8 },
    Optimistic,
}

impl MintMode {
    /// Plan §3.3: on mainnet the configured mode must satisfy `optimistic ∨ k ≥ 2` (at `k = 1` a
    /// single stolen key mints to the cap with no window). Checked at start-up. `k = 0` is never
    /// valid (the contract's threshold is at least 1).
    pub fn check_allowed(self, chain_id: u64) -> Result<()> {
        match self {
            MintMode::Threshold { k: 0 } => Err(Error::ModeNotAllowed(self.to_string(), chain_id)),
            MintMode::Threshold { k: 1 } if chain_id == MAINNET => {
                Err(Error::ModeNotAllowed(self.to_string(), chain_id))
            }
            _ => Ok(()),
        }
    }

    /// Signatures needed to submit: `k`, or one proposer signature.
    pub fn signatures_needed(self) -> usize {
        match self {
            MintMode::Threshold { k } => usize::from(k),
            MintMode::Optimistic => 1,
        }
    }
}

impl fmt::Display for MintMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintMode::Threshold { k } => write!(f, "threshold(k={k})"),
            MintMode::Optimistic => f.write_str("optimistic"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_rule() {
        assert!(MintMode::Threshold { k: 1 }.check_allowed(MAINNET).is_err());
        assert!(MintMode::Threshold { k: 2 }.check_allowed(MAINNET).is_ok());
        assert!(MintMode::Optimistic.check_allowed(MAINNET).is_ok());
        assert!(
            MintMode::Threshold { k: 1 }
                .check_allowed(11_155_111)
                .is_ok()
        );
        assert!(MintMode::Threshold { k: 0 }.check_allowed(31_337).is_err());
        assert_eq!(MintMode::Threshold { k: 3 }.signatures_needed(), 3);
        assert_eq!(MintMode::Optimistic.signatures_needed(), 1);
    }

    #[test]
    fn serde_shape() {
        let t: MintMode = serde_json::from_str(r#"{"mode":"threshold","k":2}"#).unwrap();
        assert_eq!(t, MintMode::Threshold { k: 2 });
        let o: MintMode = serde_json::from_str(r#"{"mode":"optimistic"}"#).unwrap();
        assert_eq!(o, MintMode::Optimistic);
    }
}
