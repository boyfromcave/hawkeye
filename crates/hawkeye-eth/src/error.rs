//! The adapter's error type.

use alloy::primitives::{Address, B256, TxHash};

/// Everything `hawkeye-eth` can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The endpoint serves another chain than the configured one.
    #[error("wrong chain: configured {expected}, endpoint reports {got}")]
    WrongChain { expected: u64, got: u64 },
    /// No contract code at a configured address.
    #[error("no contract code at {0}")]
    NoCode(Address),
    /// The bridge's `token()` is not the configured token, or the token's `bridge()` is not the
    /// configured bridge (a retired bridge after `setBridge`, or a misconfiguration).
    #[error(
        "bridge/token mismatch: bridge {bridge} -> token {bridge_token}, token {token} -> bridge {token_bridge}"
    )]
    PairMismatch {
        bridge: Address,
        bridge_token: Address,
        token: Address,
        token_bridge: Address,
    },
    /// A write was attempted on a client built without a wallet.
    #[error("this client has no signer: it is read-only")]
    ReadOnly,
    /// The call would revert (or did, in a mined transaction); `reason` is the decoded custom
    /// error of WyecBridge or WrappedYcash when it could be decoded (`Name(Name { .. })`, see
    /// [`Error::is_revert`]).
    #[error("reverted: {reason}")]
    Reverted { reason: String, tx: Option<TxHash> },
    /// A signature is not 65 bytes `r ‖ s ‖ v` with `v ∈ {27, 28}`, is high-S, or fails to recover.
    #[error("bad signature #{index}: {reason}")]
    BadSignature { index: usize, reason: String },
    /// Two signatures recover to the same signer (the contract would reject the set).
    #[error("duplicate signer {0}")]
    DuplicateSigner(Address),
    /// Fewer signatures than the mode's threshold.
    #[error("{got} signatures, threshold needs {need}")]
    TooFewSignatures { got: usize, need: usize },
    /// The mint mode is not allowed on this chain (plan §3.3: on mainnet the threshold mint needs
    /// k ≥ 2 in every mode).
    #[error("mint mode {0} is not allowed on chain {1}")]
    ModeNotAllowed(String, u64),
    /// The contract's threshold is below the mainnet minimum (plan §3.3): at threshold 1 one key
    /// mints through `mint` at once, so the optimistic window protects nothing.
    #[error(
        "the bridge's threshold is {0}: mainnet needs >= 2 in every mint mode (one key would skip the challenge window)"
    )]
    ThresholdTooLow(u8),
    /// The node has no `finalized` block and no fallback depth is configured.
    #[error("the node reports no finalized block and no fallback confirmation depth is configured")]
    NoFinalized,
    /// An expected log was missing from a receipt.
    #[error("no {event} log in receipt of {tx}")]
    MissingLog { event: &'static str, tx: TxHash },
    /// A log claimed to be one of the bridge's events but did not decode.
    #[error("undecodable {event} log in tx {tx:?}: {reason}")]
    BadLog {
        event: &'static str,
        tx: Option<B256>,
        reason: String,
    },
    /// The predicted token address did not match the deployed one.
    #[error("token deployed at {got}, predicted {predicted}")]
    Prediction { predicted: Address, got: Address },
    /// A configuration value is unusable.
    #[error("config: {0}")]
    Config(String),
    /// JSON-RPC transport or node error.
    #[error("rpc: {0}")]
    Rpc(String),
    /// Deployment-file I/O or JSON.
    #[error("deployment file: {0}")]
    DeploymentFile(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// Whether this is a revert with the contract's custom error `name` (e.g. `"ProposerVetoed"`,
    /// `"ProposalPending"`, `"LockConsumed"`).
    pub fn is_revert(&self, name: &str) -> bool {
        matches!(self, Error::Reverted { reason, .. }
            if reason.strip_prefix(name).is_some_and(|r| r.is_empty() || r.starts_with('(')))
    }
}

impl From<alloy::transports::TransportError> for Error {
    fn from(e: alloy::transports::TransportError) -> Self {
        Error::Rpc(e.to_string())
    }
}

impl From<alloy::providers::PendingTransactionError> for Error {
    fn from(e: alloy::providers::PendingTransactionError) -> Self {
        Error::Rpc(e.to_string())
    }
}

impl From<alloy::contract::Error> for Error {
    fn from(e: alloy::contract::Error) -> Self {
        match crate::bindings::decode_revert(&e) {
            Some(reason) => Error::Reverted { reason, tx: None },
            None => Error::Rpc(e.to_string()),
        }
    }
}
