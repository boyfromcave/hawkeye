//! The crate's error type.

use thiserror::Error;

use crate::state::ObjectKind;

/// A boxed error from a caller-supplied signer.
pub type SignerError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Every way a ledger operation can fail.
#[derive(Debug, Error)]
pub enum StoreError {
    /// SQLite itself failed (I/O, constraint, busy, …).
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The edge `from → to` is not in the object's §5.1 machine (or is a rewind-only edge).
    #[error("illegal {kind} transition {from} -> {to} for {id}")]
    IllegalTransition {
        /// The machine.
        kind: ObjectKind,
        /// The object's id as the event log prints it.
        id: String,
        /// The stored state.
        from: String,
        /// The requested state.
        to: String,
    },

    /// A sign-once record already exists for this key with different signed content: the
    /// signer was **not** called (plan HK-7, AGENTS.md rule 7).
    #[error("sign-once conflict in {domain} for {key}: {detail}")]
    SignOnceConflict {
        /// The sign-once domain (`eip712-mint`, `ycash-unlock`, `ycash-cancel`, `ycash-act`).
        domain: &'static str,
        /// The record key as hex.
        key: String,
        /// What differs.
        detail: String,
    },

    /// The caller-supplied signer failed; nothing was recorded.
    #[error("signer failed: {0}")]
    Signer(#[source] SignerError),

    /// No such object.
    #[error("{kind} {id} not found")]
    NotFound {
        /// The machine (or table) looked in.
        kind: ObjectKind,
        /// The id looked for.
        id: String,
    },

    /// The object already exists with different immutable fields.
    #[error("{kind} {id} already exists with different content")]
    Duplicate {
        /// The machine.
        kind: ObjectKind,
        /// The id.
        id: String,
    },

    /// A stored value does not decode (bad length, unknown state name, …).
    #[error("corrupt ledger: {0}")]
    Corrupt(String),

    /// An argument that the ledger refuses (e.g. a `Foreign` classification).
    #[error("invalid argument: {0}")]
    Invalid(String),

    /// The database was written by a newer Hawkeye (its `user_version` is above every known
    /// migration).
    #[error("ledger schema version {found} is newer than this build's {supported}")]
    SchemaTooNew {
        /// The file's `user_version`.
        found: u32,
        /// The highest version this build knows.
        supported: u32,
    },

    /// A chain cursor may only move forward through `advance`; going back is a rewind.
    #[error("{chain} cursor regression: at {current}, asked for {requested}")]
    CursorRegression {
        /// The chain.
        chain: &'static str,
        /// The current cursor height.
        current: u64,
        /// The requested height.
        requested: u64,
    },

    /// An Ethereum rewind would remove a burn the ledger holds as finalized: Ethereum finality
    /// was violated (or the cursor is wrong). The rewind is refused; this is an operator alarm.
    #[error("ethereum rewind to {to} would un-finalize burn {burn} at block {block}")]
    FinalizedReorg {
        /// The rewind target.
        to: u64,
        /// The burn id.
        burn: String,
        /// The burn's block number.
        block: u64,
    },
}

/// `Result` with [`StoreError`].
pub type Result<T> = core::result::Result<T, StoreError>;

impl StoreError {
    pub(crate) fn corrupt(what: impl Into<String>) -> Self {
        Self::Corrupt(what.into())
    }
}
