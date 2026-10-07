//! Hawkeye's adapter to `ycashd` (plan §6, phase H2).
//!
//! - [`YcashRpc`]: an async JSON-RPC client typed to the vault primitive's 21 `set_*` / `vault_*`
//!   RPCs (`ycash-dd/doc/vault-rpc.md`, `doc/vault-rpc-contract.json`) and the stock RPCs Hawkeye
//!   uses. Amounts are exact integer zatoshi ([`Amount`]); errors carry the node's code and message
//!   and recognise the documented reasons ([`RpcError::reason`]).
//! - [`tx`]: a v4 (Sapling-format) transaction codec — decode, re-encode byte-exactly, txid — and
//!   [`tx::insert_op_return`], which writes Hawkeye's burn-reference memo (plan §3.2, §4.3) into
//!   `vault_buildunlock`'s unsigned transaction.
//! - `mock` (feature `mock`): an in-process mock `ycashd` for tests.
//!
//! Hawkeye reaches the node only through these RPCs (workspace rule 2): no `yed_*` call exists here.

pub mod amount;
pub mod client;
pub mod error;
pub mod json;
#[cfg(feature = "mock")]
pub mod mock;
pub mod primitives;
pub mod stock;
pub mod tx;
pub mod types;

pub use amount::Amount;
pub use client::{Auth, YcashRpc};
pub use error::{Error, ErrorReason, RpcError};
pub use primitives::{Bytes32, Hash256, HexBytes, OutPoint, PubKey};
