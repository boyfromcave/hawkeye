//! `hawkeye-core`: the pure half of Hawkeye, the wYEC bridge attestor (plan
//! `docs/hawkeye-bridge-plan.md` §4, §5.2, §6). No I/O, no async.
//!
//! | Module | Contents |
//! |---|---|
//! | [`bytes`] | sha256 / sha256d / hash160 / keccak256, txid display ↔ internal order, [`OutPoint`] |
//! | [`script`] | opcodes, `CScriptNum`, canonical pushes, op iteration, P2PKH / P2SH / `OP_RETURN` |
//! | [`keys`] | [`SecretKey`], compressed keys, member ordering |
//! | [`template`] | the vault V, intent I and bond B templates, selectors (upgrade plan §15.3) |
//! | [`setsig`] | `SetSigMsg`, `ActMsg`, 65-byte recoverable compact signatures (§15.2, §4.5) |
//! | [`tx`] | Overwinter v3 / Sapling v4 transaction parser and serialiser (sighash fields) |
//! | [`sighash`] | ZIP-243 (v4) and ZIP-143 (v3) transparent signature hashes |
//! | [`attribution`] | the signers of a V UNLOCK or I CANCEL input (§2.3, §4.5) |
//! | [`eth`] | [`EthAddress`], address of a member key, `r‖s‖v` signatures, signer order |
//! | [`eip712`] | `WyecBridge` domain and the `Mint` / `SetGuardians` / `SetPaused` / `SetBridge` digests (§4.4) |
//! | [`lock`] | `lockId` and the lock destination `OP_RETURN` (§4.1) |
//! | [`recipient`] | the `ycashRecipient` bytes32 codec (§4.2) |
//! | [`address`] | Ycash transparent addresses (base58check) |
//! | [`memo`] | the `HKB1` memo (§4.3) |
//! | [`policy`] | the lock policy (§4.1) |
//! | [`matcher`] | intent classification (§3.2) |
//! | [`leader`] | the leader schedule (§5.2) |
//!
//! Ycash hashes and outpoints are in internal byte order throughout.

pub mod address;
pub mod attribution;
pub mod bytes;
pub mod eip712;
mod error;
pub mod eth;
pub mod keys;
pub mod leader;
pub mod lock;
pub mod matcher;
pub mod memo;
pub mod policy;
pub mod recipient;
pub mod script;
pub mod setsig;
pub mod sighash;
pub mod template;
pub mod tx;

pub use attribution::VAULT_BRANCH_ID;
pub use bytes::{Hash32, OutPoint};
pub use error::{Error, Result};
pub use eth::EthAddress;
pub use keys::{PubKey33, SecretKey};
pub use memo::{Deployment, HawkeyeMemo};
pub use recipient::YcashRecipient;
pub use template::{IntentParams, VaultParams};
