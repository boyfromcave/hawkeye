//! The crate's error type.

use thiserror::Error;

/// Every way a `hawkeye-core` decode, parse or check can fail.
///
/// The variants name the layer that rejected the input; the `&'static str` payloads are short
/// reason codes for logs and evidence bundles, not a stable interface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// A byte string had the wrong length.
    #[error("{what}: expected {expected} bytes, got {got}")]
    Length {
        /// What was being read.
        what: &'static str,
        /// The required length.
        expected: usize,
        /// The length given.
        got: usize,
    },
    /// Not valid hexadecimal.
    #[error("invalid hex: {0}")]
    Hex(&'static str),
    /// A script that does not decode (a push running past the end, a non-push where one is
    /// required, a non-minimal number).
    #[error("bad script: {0}")]
    Script(&'static str),
    /// A script that is not exactly the expected vault-primitive template (§15.3 of the upgrade
    /// plan: shape, minimal pushes, field ranges).
    #[error("not a template: {0}")]
    Template(&'static str),
    /// A scriptSig whose selector does not parse (S-1).
    #[error("bad selector: {0}")]
    Selector(&'static str),
    /// A public or secret key that is not usable.
    #[error("bad key: {0}")]
    Key(&'static str),
    /// A signature that fails the strict rules or does not recover.
    #[error("bad signature: {0}")]
    Signature(&'static str),
    /// A transparent address that does not decode for the network.
    #[error("bad address: {0}")]
    Address(&'static str),
    /// A `ycashRecipient` bytes32 that does not decode (plan §4.2).
    #[error("bad recipient: {0}")]
    Recipient(&'static str),
    /// A Hawkeye `HKB1` / `HKN1` memo that does not decode (plan §4.3, NEAR plan §2.2).
    #[error("bad memo: {0}")]
    Memo(&'static str),
    /// A lock destination `OP_RETURN` that does not decode (plan §4.1 rule 3, NEAR plan §2.1).
    #[error("bad destination: {0}")]
    Destination(&'static str),
    /// A NEAR encoding that is not valid: an account id outside NEAR's rules, an empty network
    /// id, a signature `v` outside {0, 1} (NEAR plan §2).
    #[error("bad NEAR encoding: {0}")]
    Near(&'static str),
    /// A transaction that does not parse as Overwinter v3 / Sapling v4, or an input index it
    /// does not have.
    #[error("bad transaction: {0}")]
    Tx(&'static str),
}

/// `Result` with [`enum@Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Check a slice's length and copy it into an array.
pub(crate) fn array<const N: usize>(what: &'static str, b: &[u8]) -> Result<[u8; N]> {
    b.try_into().map_err(|_| Error::Length {
        what,
        expected: N,
        got: b.len(),
    })
}
