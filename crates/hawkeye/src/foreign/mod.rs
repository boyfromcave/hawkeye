//! The foreign-chain adapter (NEAR plan §4 item 2): everything the engine needs from the chain
//! the wrapped token lives on, behind one trait, in chain-neutral types.
//!
//! The engine holds an `Arc<dyn ForeignChain>` and never names Ethereum: it scans finalized
//! burns, mints, proposals, challenges and admin events ([`ForeignChain::scan`]), reads the
//! bridge's state (consumed lock ids, the live proposal and its status, vetoes, the rate limit,
//! the supply, pause, threshold, guardians), submits threshold mints, proposals, challenges and
//! executions, and burns (CLI and drills). The attestation scheme — the digest a guardian signs
//! and the signature's format — is the companion trait [`AttestationScheme`], a supertrait, so
//! it can be tested without a node:
//!
//! | Chain | Digest | Signature | Guardian |
//! |---|---|---|---|
//! | Ethereum ([`ethereum`]) | EIP-712 (main plan §4.4) | 65 bytes `r ‖ s ‖ v`, `v ∈ {27, 28}`, low S | 20-byte address |
//! | NEAR (NH4) | `SHA256("HawkeyeNear-v1" ‖ borsh …)` (NEAR plan §2.3) | 65 bytes `r ‖ s ‖ v`, `v ∈ {0, 1}`, low S | 64-byte uncompressed key |
//!
//! Neutral types: amounts are `u128` base units (= zatoshi, both tokens have 8 decimals), lock
//! ids, transaction and block hashes `[u8; 32]`, accounts an [`Account`] and guardians a
//! [`Guardian`] (typed per chain), proposal ids `u128`, times Unix seconds.
//!
//! One Hawkeye process runs one bridge (NEAR plan §0 item 5): one adapter, one vault tag
//! (`[bridge] tag`), one ledger. The adapter also names the memo magic its burns are released
//! under (Ethereum `HKB1`, NEAR `HKN1`) and the [`Deployment`] the memo and the ledger's burn
//! keys carry.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::{Deployment, EthAddress, PubKey33, SecretKey};

use crate::config::Settings;

pub mod ethereum;

pub use ethereum::{Eip712Scheme, EthereumChain};

/// Plan §3.3: on mainnet the bridge's threshold is at least 2 in every mint mode (at 1 a single
/// key mints through the threshold path at once and skips the challenge window), on either chain.
pub const MAINNET_MIN_THRESHOLD: u8 = 2;

/// The chain a bridge's wrapped token lives on (`[foreign] kind`): `hawkeye-core`'s switch of
/// vault tag (`WYEC` / `NYEC`), lock destination and memo magic (`HKB1` / `HKN1`).
pub use hawkeye_core::BridgeKind;

/// An account on the foreign chain — a mint's receiver, a burner, a pauser: `hawkeye-core`'s
/// lock [`Destination`](hawkeye_core::Destination) (an Ethereum address, or a NEAR account id).
pub use hawkeye_core::Destination as Account;

/// A guardian (an attestor as the foreign contract knows it), derived from its Ycash member key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Guardian {
    /// The Ethereum address of the member key (`keccak256(uncompressed)[12..]`).
    Ethereum(EthAddress),
    /// The 64-byte uncompressed secp256k1 key `x ‖ y` (NEAR plan §2.3: what `env::ecrecover`
    /// returns).
    Secp256k1([u8; 64]),
}

impl Guardian {
    /// The guardian as an account (Ethereum: its address; a NEAR guardian key is not one).
    pub fn account(&self) -> Option<Account> {
        match self {
            Guardian::Ethereum(a) => Some(Account::Ethereum(*a)),
            Guardian::Secp256k1(_) => None,
        }
    }

    /// The 20-byte form the ledger stores (schema v2 keeps Ethereum addresses for proposers).
    pub fn ledger_eth(&self) -> Option<EthAddress> {
        match self {
            Guardian::Ethereum(a) => Some(*a),
            Guardian::Secp256k1(_) => None,
        }
    }
}

impl fmt::Display for Guardian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Guardian::Ethereum(a) => f.write_str(&a.to_checksum()),
            Guardian::Secp256k1(k) => write!(f, "0x{}", hex::encode(k)),
        }
    }
}

/// A foreign transaction hash, displayed `0x`-hex (as alloy prints a `B256`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TxId(pub Hash32);

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// An adapter failure. Its text is the underlying client's; a contract rejection also carries
/// its decoded reason (`Name(..)`), which [`ForeignError::is_revert`] matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignError {
    message: String,
    revert: Option<String>,
}

impl ForeignError {
    /// A failure that is not a contract rejection.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            revert: None,
        }
    }

    /// A contract rejection with its decoded `reason` (`ProposalPending`, `NoProposal(..)`, …).
    pub fn revert(message: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            revert: Some(reason.into()),
        }
    }

    /// Whether this is a rejection by the contract's error `name` (`"NoProposal"`,
    /// `"ProposalPending"`, `"LockConsumed"`, `"MintRateLimited"`, …).
    pub fn is_revert(&self, name: &str) -> bool {
        self.revert.as_deref().is_some_and(|reason| {
            reason
                .strip_prefix(name)
                .is_some_and(|r| r.is_empty() || r.starts_with('('))
        })
    }
}

impl fmt::Display for ForeignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForeignError {}

/// An adapter result.
pub type ForeignResult<T> = std::result::Result<T, ForeignError>;

/// The boxed, `Send` future the adapter's async methods return (object-safe async).
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = ForeignResult<T>> + Send + 'a>>;

/// Where an event sits on the foreign chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventMeta {
    /// Block height (Ethereum block number, NEAR block height).
    pub height: u64,
    /// That block's hash.
    pub block_hash: Hash32,
    /// The transaction that emitted it.
    pub tx: TxId,
    /// Position within the block (log index; NEAR: the record's index).
    pub index: u64,
}

/// A bridge event, chain-neutral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignEvent {
    /// A burn to release on Ycash.
    Burn {
        /// The bridge's burn nonce.
        nonce: u64,
        /// The burner.
        from: Account,
        /// Base units (= zatoshi).
        amount: u128,
        /// Main plan §4.2 bytes32.
        ycash_recipient: Hash32,
    },
    /// A mint happened (threshold mint, or an executed proposal).
    Minted {
        /// The lock minted against.
        lock_id: Hash32,
        /// The receiver.
        to: Account,
        /// Base units.
        amount: u128,
    },
    /// An optimistic proposal opened.
    MintProposed {
        /// The lock.
        lock_id: Hash32,
        /// The contract's non-zero proposal id.
        proposal_id: u128,
        /// The guardian whose signature opened it.
        proposer: Guardian,
        /// The receiver.
        to: Account,
        /// Base units.
        amount: u128,
        /// Unix seconds from which it can be executed.
        eta: u64,
    },
    /// A proposal was challenged (deleted; its proposer barred from the lock).
    MintChallenged {
        /// The lock.
        lock_id: Hash32,
        /// The proposal.
        proposal_id: u128,
        /// Who challenged.
        challenger: Guardian,
    },
    /// The guardian set rotated.
    GuardiansChanged {
        /// The new set's size.
        count: usize,
        /// The new threshold.
        threshold: u8,
    },
    /// The mint rate limit changed.
    MintLimitChanged {
        /// Base units per window (0: no limit; saturated at `u128::MAX`).
        mint_cap: u128,
        /// The window, seconds (saturated at `u128::MAX`).
        cap_window: u128,
    },
    /// Paused or unpaused.
    Paused {
        /// Paused now.
        paused: bool,
        /// By whom.
        by: Account,
    },
}

/// An event and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    /// Its position.
    pub meta: EventMeta,
    /// The event.
    pub event: ForeignEvent,
}

/// The events of a finalized range, in chain order, and the hash of its last block (the
/// ledger's cursor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBatch {
    /// Events in chain order.
    pub events: Vec<Scanned>,
    /// The hash of the range's last block.
    pub to_hash: Hash32,
}

/// An optimistic proposal as the contract holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Non-zero proposal id.
    pub id: u128,
    /// Base units.
    pub amount: u128,
    /// The receiver.
    pub to: Account,
    /// The guardian whose signature opened it.
    pub proposer: Guardian,
    /// Unix seconds from which it executes.
    pub eta: u64,
}

/// What executing a lock's proposal would find now (pause and rate limit aside).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    /// No proposal.
    None,
    /// Inside the challenge window.
    Pending,
    /// Executable.
    Ready,
    /// Its proposer left the guardian set: not executable, may be replaced.
    Void,
}

/// A mined foreign transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mined {
    /// Its hash.
    pub tx: TxId,
    /// Its block height.
    pub height: u64,
}

/// A mined proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proposed {
    /// The transaction.
    pub mined: Mined,
    /// The proposal it opened.
    pub proposal_id: u128,
    /// When it becomes executable (Unix seconds).
    pub eta: u64,
}

/// A mined burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Burned {
    /// The transaction.
    pub mined: Mined,
    /// The nonce the bridge assigned.
    pub nonce: u64,
}

/// What the start-up check read from the live bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeInfo {
    /// The contract's signature threshold (k of the threshold path).
    pub threshold: u8,
    /// The optimistic path's challenge window, seconds.
    pub challenge_window: u64,
}

/// The attestation scheme of a bridge contract: what a guardian signs, how, and who signed.
/// Pure (no I/O); a supertrait of [`ForeignChain`].
pub trait AttestationScheme {
    /// The guardian the contract knows for Ycash member key `member` (33-byte compressed).
    fn guardian_of(&self, member: &PubKey33) -> ForeignResult<Guardian>;

    /// The digest of `Mint(lockId, amount, to)` for this deployment.
    fn mint_digest(&self, lock_id: &Hash32, amount: u64, to: &Account) -> ForeignResult<Hash32>;

    /// The digest of `Challenge(lockId, proposalId)` for this deployment.
    fn challenge_digest(&self, lock_id: &Hash32, proposal_id: u128) -> Hash32;

    /// Sign `digest` with the member key in the contract's 65-byte format.
    fn sign(&self, key: &SecretKey, digest: &Hash32) -> ForeignResult<[u8; 65]>;

    /// The guardian a 65-byte signature over `digest` recovers to.
    fn recover(&self, digest: &Hash32, sig: &[u8]) -> ForeignResult<Guardian>;

    /// Parse an account in the chain's text form (Ethereum: hex, EIP-55 checked when mixed
    /// case; NEAR: an account id).
    fn parse_account(&self, text: &str) -> ForeignResult<Account>;
}

/// One bridge deployment on a foreign chain, as the engine drives it.
///
/// Reads are of the chain's **final** state where the chain distinguishes (the scan cursor never
/// passes [`finalized_height`](Self::finalized_height)); [`now`](Self::now) is the latest
/// block's clock, the one a proposal's `eta` is compared with. Writes are signed and paid by the
/// adapter's own sender (Ethereum: the member key's account; NEAR: the operator's relayer key)
/// and return once mined; a contract rejection is a [`ForeignError`] with
/// [`is_revert`](ForeignError::is_revert).
pub trait ForeignChain: AttestationScheme + Send + Sync {
    // ------------------------------------------------------------- identity

    /// The bridge kind (its vault tag and memo magic).
    fn kind(&self) -> BridgeKind;

    /// The deployment id the memo (`chainId ‖ bridge`) and the ledger's burn keys carry.
    fn deployment(&self) -> Deployment;

    /// The 4-byte magic of this bridge's Hawkeye memo (Ethereum `HKB1`, NEAR `HKN1`).
    fn memo_magic(&self) -> [u8; 4] {
        self.kind().memo_magic()
    }

    // ------------------------------------------------------------- start-up

    /// Read the live bridge's threshold and challenge window and hold them to the plan §3.3
    /// rules (`mainnet`: threshold ≥ 2 in every mode).
    fn check_bridge(&self, mainnet: bool) -> BoxFut<'_, BridgeInfo>;

    // ------------------------------------------------------------- cursor and scanning

    /// The highest height treated as final.
    fn finalized_height(&self) -> BoxFut<'_, u64>;

    /// The bridge's events in `[from, to]` (both final), in chain order.
    fn scan(&self, from: u64, to: u64) -> BoxFut<'_, ScanBatch>;

    /// The latest block's timestamp, Unix seconds.
    fn now(&self) -> BoxFut<'_, u64>;

    // ------------------------------------------------------------- reads

    /// The current guardians.
    fn guardians(&self) -> BoxFut<'_, Vec<Guardian>>;

    /// The contract's threshold.
    fn threshold(&self) -> BoxFut<'_, u8>;

    /// The optimistic path's challenge window, seconds (immutable).
    fn challenge_window(&self) -> BoxFut<'_, u64>;

    /// Whether `lock_id` has been minted (the contract's replay key).
    fn consumed(&self, lock_id: Hash32) -> BoxFut<'_, bool>;

    /// The live or void proposal for `lock_id`, if any.
    fn proposal(&self, lock_id: Hash32) -> BoxFut<'_, Option<Proposal>>;

    /// What executing `lock_id`'s proposal would find now.
    fn proposal_status(&self, lock_id: Hash32) -> BoxFut<'_, ProposalStatus>;

    /// Whether `who`'s proposal for `lock_id` was challenged (it may not propose it again).
    fn vetoed(&self, lock_id: Hash32, who: Guardian) -> BoxFut<'_, bool>;

    /// Base units mintable now under the rate limit (`u128::MAX` without one).
    fn mint_available(&self) -> BoxFut<'_, u128>;

    /// The wrapped token's total supply, base units.
    fn total_supply(&self) -> BoxFut<'_, u128>;

    /// Whether the bridge is paused.
    fn paused(&self) -> BoxFut<'_, bool>;

    /// The guardian signatures a mint or proposal transaction carried (the evidence of a
    /// fraudulent mint); empty if the transaction is unknown or is neither.
    fn mint_signatures(&self, tx: TxId) -> BoxFut<'_, Vec<Vec<u8>>>;

    // ------------------------------------------------------------- writes

    /// The threshold path: mint `amount` to `to` against `lock_id` with at least `k` guardian
    /// signatures (ordered as the contract needs here).
    fn threshold_mint(
        &self,
        k: u8,
        lock_id: Hash32,
        amount: u64,
        to: Account,
        sigs: Vec<[u8; 65]>,
    ) -> BoxFut<'_, Mined>;

    /// The optimistic path: open a proposal with one guardian's `Mint` signature.
    fn propose_mint(
        &self,
        lock_id: Hash32,
        amount: u64,
        to: Account,
        sig: [u8; 65],
    ) -> BoxFut<'_, Proposed>;

    /// Challenge proposal `proposal_id` of `lock_id` with a guardian's `Challenge` signature.
    fn challenge_mint(
        &self,
        lock_id: Hash32,
        proposal_id: u128,
        sig: [u8; 65],
    ) -> BoxFut<'_, Mined>;

    /// Execute `lock_id`'s proposal (anyone, after its `eta`).
    fn execute_mint(&self, lock_id: Hash32) -> BoxFut<'_, Mined>;

    /// Burn `amount` from the sender to `ycash_recipient` (main plan §4.2; CLI, devnet, drills).
    fn burn(&self, amount: u64, ycash_recipient: Hash32) -> BoxFut<'_, Burned>;
}

/// Connect the configured foreign chain with `key` as the sender (Ethereum: the key's account
/// signs and pays gas).
pub async fn connect(s: &Settings, key: &SecretKey) -> Result<Arc<dyn ForeignChain>> {
    match s.foreign {
        BridgeKind::Ethereum => Ok(Arc::new(EthereumChain::connect(s, key).await?)),
        BridgeKind::Near => Err(anyhow!(
            "foreign.kind \"near\": the NEAR adapter is not built yet (NEAR plan NH4)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revert_names_match_whole_errors_only() {
        let e = ForeignError::revert("reverted: NoProposal(..)", "NoProposal(NoProposal { })");
        assert!(e.is_revert("NoProposal"));
        assert!(!e.is_revert("No"));
        assert!(!e.is_revert("ProposalPending"));
        assert!(ForeignError::revert("x", "LockConsumed").is_revert("LockConsumed"));
        assert!(!ForeignError::new("rpc: LockConsumed").is_revert("LockConsumed"));
        assert_eq!(e.to_string(), "reverted: NoProposal(..)");
    }

    #[test]
    fn displays() {
        let a = EthAddress([0xab; 20]);
        assert_eq!(Account::Ethereum(a).to_string(), a.to_checksum());
        assert_eq!(Guardian::Ethereum(a).to_string(), a.to_checksum());
        let n = hawkeye_core::AccountId::parse("alice.near").unwrap();
        assert_eq!(Account::Near(n.clone()).to_string(), "alice.near");
        assert_eq!(Account::Near(n).ethereum(), None);
        assert_eq!(Guardian::Ethereum(a).account(), Some(Account::Ethereum(a)));
        assert_eq!(Guardian::Secp256k1([1; 64]).account(), None);
        assert_eq!(
            Guardian::Secp256k1([1; 64]).to_string(),
            format!("0x{}", "01".repeat(64))
        );
    }
}
