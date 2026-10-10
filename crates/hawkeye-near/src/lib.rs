//! `hawkeye-near`: Hawkeye's NEAR adapter (NEAR plan `docs/hawkeye-near-plan.md` §4 item 2,
//! phase NH4) — everything the daemon needs to drive the `wyec-near` contract (`near/`) over
//! standard NEAR JSON-RPC, with no NEAR SDK crate in the daemon.
//!
//! | Module | Contents |
//! |---|---|
//! | [`tx`] | a hand-rolled Borsh codec for `TransactionV0` / `SignedTransaction` with `FunctionCall` actions, golden-vectored against `near-primitives` |
//! | [`keys`] | the relayer's ed25519 key from a NEAR credentials JSON file |
//! | [`rpc`] | the JSON-RPC client: views at `final` or a block, `block`, `EXPERIMENTAL_changes`, `EXPERIMENTAL_receipt`, access keys, `send_tx` (`FINAL`) |
//! | [`contract`] | the `wyec-near` client: typed views, the relayer's calls (nonce handling), the block scanner |
//! | [`error`] | errors, and the contract's panic messages mapped to the engine's error names |
//! | `mock` | (feature `mock`) a mock NEAR RPC node with a model of the contract |
//!
//! The attestation scheme (digests, signatures, guardian keys) is `hawkeye-core::near`'s; this
//! crate never signs an attestation, only the relayer's transaction envelopes.

pub mod contract;
pub mod error;
pub mod keys;
#[cfg(feature = "mock")]
pub mod mock;
pub mod rpc;
pub mod tx;

pub use contract::{CallOutcome, NearEvent, NearScanned, ProposalStatus, ScanOutput, WyecNear};
pub use error::{Error, Result};
pub use keys::KeyFile;
pub use rpc::{BlockRef, NearRpc};
