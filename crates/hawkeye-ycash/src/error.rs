//! Errors, and recognition of the reasons `doc/vault-rpc.md` ("Error reasons") lets a client rely on.

use std::fmt;

/// JSON-RPC error codes the node uses (ycash-dd `src/rpc/protocol.h`).
pub mod codes {
    pub const MISC_ERROR: i64 = -1;
    pub const TYPE_ERROR: i64 = -3;
    pub const WALLET_ERROR: i64 = -4;
    pub const INVALID_ADDRESS_OR_KEY: i64 = -5;
    pub const WALLET_INSUFFICIENT_FUNDS: i64 = -6;
    pub const INVALID_PARAMETER: i64 = -8;
    pub const DATABASE_ERROR: i64 = -20;
    pub const DESERIALIZATION_ERROR: i64 = -22;
    pub const VERIFY_ERROR: i64 = -25;
    pub const TRANSACTION_ERROR: i64 = -25;
    pub const VERIFY_REJECTED: i64 = -26;
    pub const TRANSACTION_REJECTED: i64 = -26;
    pub const VERIFY_ALREADY_IN_CHAIN: i64 = -27;
    pub const IN_WARMUP: i64 = -28;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const PARSE_ERROR: i64 = -32700;
}

/// Everything a call can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The node answered with a JSON-RPC error.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// Connecting, sending or reading failed.
    #[error("ycashd transport: {0}")]
    Http(#[from] reqwest::Error),
    /// HTTP status without a JSON-RPC body (401: wrong credentials or a stale cookie).
    #[error("ycashd answered HTTP {status}: {body}")]
    Status { status: u16, body: String },
    /// The answer does not have the documented shape.
    #[error("{method}: unexpected answer: {source} (body: {body})")]
    Decode {
        method: String,
        #[source]
        source: serde_json::Error,
        body: String,
    },
    /// Reading the cookie file failed.
    #[error("ycashd cookie {path}: {source}")]
    Cookie {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A request could not be built (a parameter that does not serialize).
    #[error("building {method}: {source}")]
    Request {
        method: String,
        #[source]
        source: serde_json::Error,
    },
}

impl Error {
    /// The node's JSON-RPC error, if that is what this is.
    pub fn rpc(&self) -> Option<&RpcError> {
        match self {
            Error::Rpc(e) => Some(e),
            _ => None,
        }
    }

    /// [`RpcError::reason`] of an RPC error.
    pub fn reason(&self) -> Option<ErrorReason> {
        self.rpc().and_then(RpcError::reason)
    }

    /// Transport-level and warm-up failures, worth retrying unchanged.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Http(_) => true,
            Error::Status { status, .. } => *status >= 500 || *status == 401,
            Error::Rpc(e) => e.code == codes::IN_WARMUP,
            _ => false,
        }
    }
}

/// A JSON-RPC error answer: the node's code and message, and the method called.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub struct RpcError {
    pub method: String,
    pub code: i64,
    pub message: String,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed ({}): {}",
            self.method, self.code, self.message
        )
    }
}

/// The documented reasons (`vault-rpc.md` "Error reasons", contract `errors[]`), plus the
/// mempool rejection and stock-RPC conditions Hawkeye acts on. Matching is by code and a
/// substring of the message, exactly as the document specifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorReason {
    /// -1 `is not active at the next block`
    NotActive,
    /// -8 `the set parameters are out of range`
    SetParamsOutOfRange,
    /// -5 / -8 `unknown set` (also vault_lock's -5 `must be confirmed sets`)
    UnknownSet,
    /// -4 `this wallet holds no current member key of the set`
    NoCurrentMemberKey,
    /// -8 `unknown act type`
    UnknownActType,
    /// -8 `the transaction carries no YV act`
    NoAct,
    /// -8 `kind must be vault or intent`
    BadKind,
    /// -8 `vault parameters out of range`
    VaultParamsOutOfRange,
    /// -8 `not an unspent vault output`
    NotUnspentVault,
    /// -8 `the recipients' amounts exceed the vault's value`
    RecipientsExceedVault,
    /// -8 `the template input is not an intent`
    TemplateNotIntent,
    /// -8 `the template input is not a vault`
    TemplateNotVault,
    /// -4 `set-sign-once`: this wallet already signed a different spend of the outpoint
    SetSignOnce,
    /// -8 `not an unspent intent output`
    NotUnspentIntent,
    /// -1 `can no longer be cancelled` (the intent matured at `height`)
    CannotCancel { matured_at: Option<u32> },
    /// -1 `matures at height` h
    NotMature { height: Option<u32> },
    /// -1 `the intent is not confirmed` (vault_release of a mempool intent; not in the table)
    IntentNotConfirmed,
    /// -1 `owner branch opens at height` h
    OwnerBranchClosed { height: Option<u32> },
    /// -8 `has no APP branch`
    NoAppBranch,
    /// -1 `the APP branch opens at height` h
    AppBranchClosed { height: Option<u32> },
    /// -6 insufficient confirmed transparent funds
    InsufficientFunds,
    /// -25 `Missing inputs` (an input is spent or unknown)
    MissingInputs,
    /// -27 / -26 `txn-already-in-mempool` / `transaction already in block chain`
    AlreadyKnown,
    /// -26 `"<code>: <reason>"`: the mempool rejected the transaction (e.g. `bad-vault-act-seats`,
    /// `bad-txns-vault-rate`).
    Rejected { code: u32, reason: String },
}

fn height_after(msg: &str, marker: &str) -> Option<u32> {
    let rest = &msg[msg.find(marker)? + marker.len()..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

impl RpcError {
    pub fn new(method: impl Into<String>, code: i64, message: impl Into<String>) -> Self {
        RpcError {
            method: method.into(),
            code,
            message: message.into(),
        }
    }

    fn has(&self, code: i64, s: &str) -> bool {
        self.code == code && self.message.contains(s)
    }

    /// `-26 "<code>: <reason>"` split, for a mempool rejection.
    pub fn rejection(&self) -> Option<(u32, &str)> {
        if self.code != codes::TRANSACTION_REJECTED {
            return None;
        }
        let (c, r) = self.message.split_once(": ")?;
        Some((c.trim().parse().ok()?, r.trim()))
    }

    /// The documented reason this error carries, if any.
    pub fn reason(&self) -> Option<ErrorReason> {
        use ErrorReason as R;
        let m = self.message.as_str();
        Some(if self.has(-1, "is not active at the next block") {
            R::NotActive
        } else if self.has(-8, "the set parameters are out of range") {
            R::SetParamsOutOfRange
        } else if (self.code == -5 || self.code == -8)
            && (m.contains("unknown set") || m.contains("must be confirmed sets"))
        {
            R::UnknownSet
        } else if self.has(-4, "this wallet holds no current member key of the set") {
            R::NoCurrentMemberKey
        } else if self.has(-8, "unknown act type") {
            R::UnknownActType
        } else if self.has(-8, "the transaction carries no YV act") {
            R::NoAct
        } else if self.has(-8, "kind must be vault or intent") {
            R::BadKind
        } else if self.has(-8, "vault parameters out of range") {
            R::VaultParamsOutOfRange
        } else if self.has(-8, "not an unspent vault output") {
            R::NotUnspentVault
        } else if self.has(-8, "the recipients' amounts exceed the vault's value") {
            R::RecipientsExceedVault
        } else if self.has(-8, "the template input is not an intent") {
            R::TemplateNotIntent
        } else if self.has(-8, "the template input is not a vault") {
            R::TemplateNotVault
        } else if self.has(-4, "set-sign-once") {
            R::SetSignOnce
        } else if self.has(-8, "not an unspent intent output") {
            R::NotUnspentIntent
        } else if self.has(-1, "can no longer be cancelled") {
            R::CannotCancel {
                matured_at: height_after(m, "matured at height"),
            }
        } else if self.has(-1, "matures at height") {
            R::NotMature {
                height: height_after(m, "matures at height"),
            }
        } else if self.has(-1, "the intent is not confirmed") {
            R::IntentNotConfirmed
        } else if self.has(-1, "owner branch opens at height") {
            R::OwnerBranchClosed {
                height: height_after(m, "opens at height"),
            }
        } else if self.has(-8, "has no APP branch") {
            R::NoAppBranch
        } else if self.has(-1, "the APP branch opens at height") {
            R::AppBranchClosed {
                height: height_after(m, "opens at height"),
            }
        } else if self.code == codes::WALLET_INSUFFICIENT_FUNDS {
            R::InsufficientFunds
        } else if self.has(-25, "Missing inputs") || self.has(-25, "missing-inputs") {
            R::MissingInputs
        } else if self.code == codes::VERIFY_ALREADY_IN_CHAIN
            || self.has(-26, "txn-already-in-mempool")
            || self.has(-26, "txn-already-known")
        {
            R::AlreadyKnown
        } else if let Some((code, reason)) = self.rejection() {
            R::Rejected {
                code,
                reason: reason.to_owned(),
            }
        } else {
            return None;
        })
    }

    /// `set-sign-once`: the wallet refused to sign a second, different spend (never retry with a
    /// rebuilt transaction; collect signatures on the one already signed).
    pub fn is_set_sign_once(&self) -> bool {
        self.has(-4, "set-sign-once")
    }

    /// A mempool rejection whose reason is a vault rule (`bad-vault-*` act rules or
    /// `bad-txns-vault-*` template rules); returns the reason.
    pub fn bad_vault(&self) -> Option<&str> {
        let (_, r) = self.rejection()?;
        (r.starts_with("bad-vault-") || r.starts_with("bad-txns-vault-")).then_some(r)
    }

    /// `vault_release` before the intent matures: the height it matures at.
    pub fn matures_at_height(&self) -> Option<u32> {
        match self.reason()? {
            ErrorReason::NotMature { height } => height,
            _ => None,
        }
    }

    /// `vault_buildcancel` after the delay: the cancel window has closed.
    pub fn is_cancel_window_closed(&self) -> bool {
        matches!(self.reason(), Some(ErrorReason::CannotCancel { .. }))
    }

    /// The transaction is already in the mempool or the chain (an idempotent re-send).
    pub fn is_already_known(&self) -> bool {
        matches!(self.reason(), Some(ErrorReason::AlreadyKnown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(code: i64, m: &str) -> RpcError {
        RpcError::new("x", code, m)
    }

    #[test]
    fn documented_reasons() {
        // Every row of vault-rpc.md "Error reasons", with the node's actual message text
        // (src/rpc/vault.cpp) where it is longer than the documented substring.
        let rows: Vec<(RpcError, ErrorReason)> = vec![
            (
                e(
                    -1,
                    "the vault upgrade is not active at the next block (height 5)",
                ),
                ErrorReason::NotActive,
            ),
            (
                e(
                    -8,
                    "the set parameters are out of range (plan §15.5 row 0x01)",
                ),
                ErrorReason::SetParamsOutOfRange,
            ),
            (
                e(-5, &format!("unknown set {}", "00".repeat(32))),
                ErrorReason::UnknownSet,
            ),
            (
                e(-5, "setid and cancelsetid must be confirmed sets"),
                ErrorReason::UnknownSet,
            ),
            (
                e(-4, "this wallet holds no current member key of the set"),
                ErrorReason::NoCurrentMemberKey,
            ),
            (
                e(-26, "16: bad-vault-act-seats"),
                ErrorReason::Rejected {
                    code: 16,
                    reason: "bad-vault-act-seats".into(),
                },
            ),
            (e(-8, "unknown act type"), ErrorReason::UnknownActType),
            (
                e(-8, "the transaction carries no YV act"),
                ErrorReason::NoAct,
            ),
            (e(-8, "kind must be vault or intent"), ErrorReason::BadKind),
            (
                e(-8, "vault parameters out of range (plan §15.3)"),
                ErrorReason::VaultParamsOutOfRange,
            ),
            (
                e(-8, "not an unspent vault output"),
                ErrorReason::NotUnspentVault,
            ),
            (
                e(-8, "the recipients' amounts exceed the vault's value"),
                ErrorReason::RecipientsExceedVault,
            ),
            (
                e(-8, "the template input is not an intent"),
                ErrorReason::TemplateNotIntent,
            ),
            (
                e(-8, "the template input is not a vault"),
                ErrorReason::TemplateNotVault,
            ),
            (
                e(
                    -4,
                    "set-sign-once: this wallet already signed a different unlock (role 1, sighash ab) of x:0 for set y; ...",
                ),
                ErrorReason::SetSignOnce,
            ),
            (
                e(-8, "not an unspent intent output"),
                ErrorReason::NotUnspentIntent,
            ),
            (
                e(
                    -1,
                    "the intent matured at height 120; it can no longer be cancelled",
                ),
                ErrorReason::CannotCancel {
                    matured_at: Some(120),
                },
            ),
            (
                e(-1, "the intent matures at height 130"),
                ErrorReason::NotMature { height: Some(130) },
            ),
            (
                e(
                    -1,
                    "the owner branch opens at height 441 and the set is not released",
                ),
                ErrorReason::OwnerBranchClosed { height: Some(441) },
            ),
            (
                e(-8, "the vault has no APP branch (appheight 0, S-4)"),
                ErrorReason::NoAppBranch,
            ),
            (
                e(-1, "the APP branch opens at height 99"),
                ErrorReason::AppBranchClosed { height: Some(99) },
            ),
            (
                e(-1, "the intent is not confirmed"),
                ErrorReason::IntentNotConfirmed,
            ),
            (
                e(
                    -6,
                    "insufficient confirmed transparent funds: need 0.0001 more",
                ),
                ErrorReason::InsufficientFunds,
            ),
            (e(-25, "Missing inputs"), ErrorReason::MissingInputs),
            (
                e(-27, "transaction already in block chain"),
                ErrorReason::AlreadyKnown,
            ),
            (
                e(-26, "18: txn-already-in-mempool"),
                ErrorReason::AlreadyKnown,
            ),
        ];
        for (err, want) in rows {
            assert_eq!(err.reason(), Some(want), "{err}");
        }
        assert_eq!(e(-8, "something else").reason(), None);
        // code matters: a -8 with the sign-once text is not the wallet's refusal
        assert!(!e(-8, "set-sign-once").is_set_sign_once());
    }

    #[test]
    fn helpers() {
        assert!(e(-4, "set-sign-once: ...").is_set_sign_once());
        assert_eq!(
            e(-26, "16: bad-vault-act-seats").bad_vault(),
            Some("bad-vault-act-seats")
        );
        assert_eq!(
            e(-26, "16: bad-txns-vault-rate").bad_vault(),
            Some("bad-txns-vault-rate")
        );
        assert_eq!(e(-26, "64: dust").bad_vault(), None);
        assert_eq!(e(-26, "64: dust").rejection(), Some((64, "dust")));
        assert_eq!(
            e(-1, "the intent matures at height 77").matures_at_height(),
            Some(77)
        );
        assert!(
            e(
                -1,
                "the intent matured at height 1; it can no longer be cancelled"
            )
            .is_cancel_window_closed()
        );
        assert!(e(-27, "transaction already in block chain").is_already_known());
        let err = Error::Rpc(e(-28, "Loading block index..."));
        assert!(err.is_transient());
        assert_eq!(
            Error::Rpc(e(-4, "set-sign-once")).reason(),
            Some(ErrorReason::SetSignOnce)
        );
    }
}
