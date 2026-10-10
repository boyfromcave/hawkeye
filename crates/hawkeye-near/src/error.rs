//! Errors of the NEAR adapter, and the contract's panic messages mapped to the names the engine
//! matches (the Ethereum bridge's custom-error names, where one exists).

use serde_json::Value;

/// A NEAR adapter failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Transport: the request did not get a JSON-RPC answer.
    #[error("http: {0}")]
    Http(String),
    /// A JSON-RPC error (`name`, `cause.name`), with its message and data.
    #[error("rpc {name}{}: {message}", cause.as_ref().map(|c| format!("/{c}")).unwrap_or_default())]
    Rpc {
        /// `error.name` (`HANDLER_ERROR`, `REQUEST_VALIDATION_ERROR`, …).
        name: String,
        /// `error.cause.name` (`UNKNOWN_BLOCK`, `INVALID_TRANSACTION`, `TIMEOUT_ERROR`, …).
        cause: Option<String>,
        /// `error.message` and the data's text.
        message: String,
        /// `error.data` (an `InvalidTxError` is here).
        data: Option<Value>,
    },
    /// The contract panicked (a view call or a transaction's function call): the text after
    /// `Smart contract panicked: `.
    #[error("panicked: {0}")]
    Panic(String),
    /// A transaction failed for another reason than a contract panic (out of gas, an action
    /// error such as a missing account).
    #[error("transaction failed: {0}")]
    TxFailed(String),
    /// An answer that does not decode.
    #[error("decode: {0}")]
    Decode(String),
    /// A key file or signing key problem.
    #[error("key: {0}")]
    Key(String),
}

/// An adapter result.
pub type Result<T> = std::result::Result<T, Error>;

/// The `wyec-near` panic messages (`near/src/lib.rs`) and the names the engine matches. The
/// first four are the Ethereum bridge's custom errors the engine already handles
/// (`LockConsumed`, `ProposalPending`, `NoProposal`, `MintRateLimited`); the rest are named
/// alike.
pub const PANIC_NAMES: &[(&str, &str)] = &[
    ("wyec: lock consumed", "LockConsumed"),
    ("wyec: proposal pending", "ProposalPending"),
    ("wyec: no such proposal", "NoProposal"),
    ("wyec: mint rate limited", "MintRateLimited"),
    ("wyec: challenge window open", "ChallengeWindowOpen"),
    ("wyec: proposer not a guardian", "ProposerNotGuardian"),
    ("wyec: proposer vetoed for this lock", "ProposerVetoed"),
    ("wyec: not a guardian", "NotGuardian"),
    ("wyec: paused", "EnforcedPause"),
    ("wyec: zero amount", "ZeroAmount"),
    ("wyec: below threshold", "BelowThreshold"),
    (
        "wyec: signers not strictly ascending",
        "SignersNotAscending",
    ),
    ("wyec: bad signature v", "BadSignature"),
    ("wyec: bad signature", "BadSignature"),
    ("wyec: signature must be 65 bytes of hex", "BadSignature"),
    ("wyec: lock_id must be 32 bytes of hex", "BadLockId"),
    (
        "wyec: ycash_recipient must be 32 bytes of hex",
        "BadRecipient",
    ),
    (
        "wyec: attached deposit below the burn record's storage cost",
        "InsufficientDeposit",
    ),
    (
        "Requires attached deposit of at least 1 yoctoNEAR",
        "InsufficientDeposit",
    ),
    (
        "The account doesn't have enough balance",
        "InsufficientBalance",
    ),
    ("wyec: bad guardian set", "BadGuardianSet"),
    ("wyec: bad mint limit", "BadMintLimit"),
    ("wyec: already paused", "AlreadyPaused"),
    ("wyec: not paused", "NotPaused"),
];

/// The name of a contract panic message, if it is one of [`PANIC_NAMES`].
pub fn panic_name(message: &str) -> Option<&'static str> {
    PANIC_NAMES
        .iter()
        .find(|(m, _)| message == *m)
        .map(|(_, n)| *n)
}

/// The panic text inside a NEAR error string (`… Smart contract panicked: wyec: … "))`), if
/// there is one.
pub fn extract_panic(text: &str) -> Option<String> {
    const P: &str = "Smart contract panicked: ";
    let rest = &text[text.find(P)? + P.len()..];
    // a Debug-printed error ends the message at the closing quote
    let end = rest.find('"').unwrap_or(rest.len());
    Some(rest[..end].trim_end_matches('\\').replace("\\'", "'"))
}

/// The panic text in any string of a JSON value (an RPC error or a failed status).
pub fn find_panic(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => extract_panic(s),
        serde_json::Value::Array(a) => a.iter().find_map(find_panic),
        serde_json::Value::Object(m) => m.values().find_map(find_panic),
        _ => None,
    }
}

impl Error {
    /// The contract error name of a panic ([`panic_name`]).
    pub fn revert_name(&self) -> Option<&'static str> {
        match self {
            Error::Panic(m) => panic_name(m),
            _ => None,
        }
    }

    /// Whether the node does not have this block (a skipped height, or garbage-collected).
    pub fn is_unknown_block(&self) -> bool {
        matches!(self, Error::Rpc { cause: Some(c), .. } if c == "UNKNOWN_BLOCK")
    }

    /// Whether the transaction's nonce was refused (another transaction used it).
    pub fn is_invalid_nonce(&self) -> bool {
        match self {
            Error::Rpc { data, message, .. } => {
                message.contains("InvalidNonce")
                    || data
                        .as_ref()
                        .is_some_and(|d| d.to_string().contains("InvalidNonce"))
            }
            _ => false,
        }
    }

    /// Whether the node gave up waiting for the transaction (it may still execute).
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Rpc { cause: Some(c), .. } if c == "TIMEOUT_ERROR")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panics_are_extracted_and_named() {
        let vm = r#"wasm execution failed with error: FunctionCallError(ExecutionError("Smart contract panicked: wyec: lock consumed"))"#;
        assert_eq!(extract_panic(vm).as_deref(), Some("wyec: lock consumed"));
        assert_eq!(
            extract_panic("Smart contract panicked: wyec: no such proposal").as_deref(),
            Some("wyec: no such proposal")
        );
        assert_eq!(extract_panic("Exceeded the prepaid gas."), None);
        let e = Error::Panic("wyec: lock consumed".into());
        assert_eq!(e.revert_name(), Some("LockConsumed"));
        assert_eq!(e.to_string(), "panicked: wyec: lock consumed");
        // whole messages only: "wyec: not a guardian" is not "wyec: proposer not a guardian"
        assert_eq!(panic_name("wyec: not a guardian"), Some("NotGuardian"));
        assert_eq!(
            panic_name("wyec: proposer not a guardian"),
            Some("ProposerNotGuardian")
        );
        assert_eq!(panic_name("wyec: something new"), None);
        assert_eq!(Error::TxFailed("x".into()).revert_name(), None);
        // every panic string of the contract source is named
        for (m, n) in PANIC_NAMES {
            assert_eq!(panic_name(m), Some(*n));
        }
    }

    #[test]
    fn rpc_error_classes() {
        let unknown = Error::Rpc {
            name: "HANDLER_ERROR".into(),
            cause: Some("UNKNOWN_BLOCK".into()),
            message: "DB Not Found Error: BLOCK HEIGHT: 12".into(),
            data: None,
        };
        assert!(unknown.is_unknown_block() && !unknown.is_invalid_nonce());
        assert_eq!(
            unknown.to_string(),
            "rpc HANDLER_ERROR/UNKNOWN_BLOCK: DB Not Found Error: BLOCK HEIGHT: 12"
        );
        let nonce = Error::Rpc {
            name: "HANDLER_ERROR".into(),
            cause: Some("INVALID_TRANSACTION".into()),
            message: "invalid transaction".into(),
            data: Some(serde_json::json!({"TxExecutionError": {"InvalidTxError":
                {"InvalidNonce": {"tx_nonce": 5, "ak_nonce": 9}}}})),
        };
        assert!(nonce.is_invalid_nonce() && !nonce.is_unknown_block() && !nonce.is_timeout());
    }
}
