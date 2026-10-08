//! How mints reach Ethereum (plan §0 item 4, §3.3; wyec-contract-design.md §4.5).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Ethereum mainnet's chain id.
pub const MAINNET: u64 = 1;

/// The smallest contract threshold mainnet accepts, in every mode (plan §3.3).
pub const MAINNET_MIN_THRESHOLD: u8 = 2;

/// The mint path Hawkeye uses. One `WyecBridge` serves both; the mode is how Hawkeye drives it.
///
/// - `Optimistic` (the Foundation's model): the mint leader calls `proposeMint` with its own
///   EIP-712 `Mint` signature; any attestor that cannot match the proposal to a policy-OK lock
///   challenges it (`challengeMint` with an EIP-712 `Challenge` signature) inside the contract's
///   `challengeWindow`; after the window anyone calls `executeMint`.
/// - `Threshold { k }`: `mint` with `k` guardian signatures, immediate. For overrides and for
///   deployments that want no window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum MintMode {
    Threshold { k: u8 },
    Optimistic,
}

impl MintMode {
    /// The configured mode alone: `k = 0` is never valid; on mainnet a threshold mode needs
    /// `k ≥ 2`. The contract's own threshold is checked by [`check_contract_threshold`], which
    /// mainnet requires in *every* mode.
    pub fn check_allowed(self, chain_id: u64) -> Result<()> {
        match self {
            MintMode::Threshold { k: 0 } => Err(Error::ModeNotAllowed(self.to_string(), chain_id)),
            MintMode::Threshold { k } if chain_id == MAINNET && k < MAINNET_MIN_THRESHOLD => {
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

/// Plan §3.3, the mainnet rule: the bridge's threshold must be at least
/// [`MAINNET_MIN_THRESHOLD`] whatever the mode. At threshold 1 a single key mints through `mint`
/// at once (and can lift the rate limit), so the optimistic window would protect nothing
/// (wyec-contract-design.md §4.5.2). Other chains accept any threshold ≥ 1.
pub fn check_contract_threshold(chain_id: u64, threshold: u8) -> Result<()> {
    if threshold == 0 || (chain_id == MAINNET && threshold < MAINNET_MIN_THRESHOLD) {
        return Err(Error::ThresholdTooLow(threshold));
    }
    Ok(())
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
        // the contract's threshold: >= 2 on mainnet in every mode, >= 1 elsewhere
        assert!(matches!(
            check_contract_threshold(MAINNET, 1),
            Err(Error::ThresholdTooLow(1))
        ));
        assert!(check_contract_threshold(MAINNET, 2).is_ok());
        assert!(check_contract_threshold(31_337, 1).is_ok());
        assert!(check_contract_threshold(31_337, 0).is_err());
    }

    #[test]
    fn serde_shape() {
        let t: MintMode = serde_json::from_str(r#"{"mode":"threshold","k":2}"#).unwrap();
        assert_eq!(t, MintMode::Threshold { k: 2 });
        let o: MintMode = serde_json::from_str(r#"{"mode":"optimistic"}"#).unwrap();
        assert_eq!(o, MintMode::Optimistic);
    }
}
