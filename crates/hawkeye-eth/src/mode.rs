//! How mints reach Ethereum (plan §0 item 4, §3.3; wyec-contract-design.md §4.5).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Ethereum mainnet's chain id.
pub const MAINNET: u64 = 1;

/// The smallest contract threshold mainnet accepts, in every mode (plan §3.3).
pub const MAINNET_MIN_THRESHOLD: u8 = 2;

/// Two epochs of 32 slots of 12 s: the nominal time to finality on Ethereum mainnet.
pub const ETH_FINALITY_NOMINAL_SECS: u64 = 2 * 32 * 12; // 768

/// The smallest `challengeWindow` mainnet accepts (audit 05/H-2; wyec's
/// `MIN_MAINNET_CHALLENGE_WINDOW`, the same two hours). The watcher's usable share is ¾ of the
/// window (`challenge_due` keeps a quarter as margin), and that share must cover two finality
/// periods (a one-epoch stall still leaves a challenge in time even for an attestor on the old,
/// finalized-only scan), `C_Y` = 20 Ycash blocks for the lock-absent rule (20 × 75 s) and a
/// submission margin (600 s): ¾ W ≥ 1,536 + 1,500 + 600 ⇒ W ≥ 4,848 s, rounded up to two hours.
/// A floor below which Hawkeye refuses to start, not a recommendation: the P8 value may be far
/// larger.
pub const MAINNET_MIN_CHALLENGE_WINDOW_SECS: u64 = 2 * 60 * 60; // 7_200

// The derivation holds: three quarters of the floor cover two finality periods, 20 Ycash blocks
// of 75 s and the 600 s submission margin.
const _: () = assert!(
    MAINNET_MIN_CHALLENGE_WINDOW_SECS * 3 / 4 >= 2 * ETH_FINALITY_NOMINAL_SECS + 20 * 75 + 600
);

/// `finalized` not advancing for this long while new blocks keep coming is a finality stall:
/// three epochs (it normally moves every 6.4 min).
pub const ETH_FINALITY_STALL_SECS: u64 = 3 * 32 * 12; // 1_152

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

/// Audit 05/H-2, the mainnet window floor: the contract's `challengeWindow` must be at least
/// [`MAINNET_MIN_CHALLENGE_WINDOW_SECS`] on chain [`MAINNET`]; other chains accept any window.
pub fn check_challenge_window(chain_id: u64, window: u64) -> Result<()> {
    if chain_id == MAINNET && window < MAINNET_MIN_CHALLENGE_WINDOW_SECS {
        return Err(Error::ChallengeWindowTooShort(window));
    }
    Ok(())
}

/// Audit 05/H-2, the mainnet rate-limit rule: `mintCap` must be non-zero on chain [`MAINNET`]
/// (0 is the contract's "no limit"); other chains accept 0.
pub fn check_mint_cap(chain_id: u64, mint_cap: u128) -> Result<()> {
    if chain_id == MAINNET && mint_cap == 0 {
        return Err(Error::MintCapUnbounded);
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
    fn mainnet_window_and_cap_floors() {
        assert_eq!(MAINNET_MIN_CHALLENGE_WINDOW_SECS, 7_200);
        assert_eq!(ETH_FINALITY_NOMINAL_SECS, 768);
        assert_eq!(ETH_FINALITY_STALL_SECS, 1_152);
        assert!(matches!(
            check_challenge_window(MAINNET, 7_199),
            Err(Error::ChallengeWindowTooShort(7_199))
        ));
        assert!(check_challenge_window(MAINNET, 7_200).is_ok());
        assert!(check_challenge_window(31_337, 60).is_ok());
        assert!(check_challenge_window(11_155_111, 1).is_ok());
        assert!(matches!(
            check_mint_cap(MAINNET, 0),
            Err(Error::MintCapUnbounded)
        ));
        assert!(check_mint_cap(MAINNET, 1).is_ok());
        assert!(check_mint_cap(31_337, 0).is_ok());
        assert!(check_mint_cap(11_155_111, 0).is_ok());
    }

    #[test]
    fn serde_shape() {
        let t: MintMode = serde_json::from_str(r#"{"mode":"threshold","k":2}"#).unwrap();
        assert_eq!(t, MintMode::Threshold { k: 2 });
        let o: MintMode = serde_json::from_str(r#"{"mode":"optimistic"}"#).unwrap();
        assert_eq!(o, MintMode::Optimistic);
    }
}
