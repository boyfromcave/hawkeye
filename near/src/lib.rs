//! `wyec-near`: Wrapped Ycash (wYEC) on NEAR — a NEP-141/145/148 token and the Hawkeye bridge
//! policy in one contract (`docs/hawkeye-near-plan.md` §3, N-7).
//!
//! The bridge semantics mirror the Ethereum `WyecBridge` (wyec repo,
//! `contracts/WyecBridge.sol`, `docs/wyec-contract-design.md` §4):
//!
//! * **Threshold mint** (`mint`): `threshold` signatures of distinct current guardians over
//!   `BridgeMessage::Mint`, ordered by strictly ascending recovered public key (64-byte
//!   lexicographic order: the Ethereum rule, "strictly ascending recovered address", restated for
//!   NEAR's key-based identities). More than `threshold` signatures are accepted. Mints at once,
//!   consumes `lock_id`, and deletes any pending optimistic proposal for it.
//! * **Optimistic mint** (`propose_mint` → challenge window → `execute_mint`): one guardian's
//!   signature over the same `Mint` message opens a proposal; during `challenge_window_sec` any
//!   one guardian's `Challenge { lock_id, proposal_id }` signature deletes it and vetoes the
//!   proposer for that lock; after the window anyone executes. A proposal whose proposer has been
//!   rotated out is void (not executable, replaceable by a new proposal).
//! * **Rate limit**: `mint_cap` zatoshi per fixed window `floor(now_sec / cap_window_sec)`, shared
//!   by both paths and applied when the mint happens; `mint_cap == 0` disables it.
//! * **Burn** (`burn`): the holder's unconditional act; appends a [`BurnRecord`] to on-chain state
//!   (N-8) and emits `ft_burn` + `wyec_bridge/burn_to_ycash`.
//! * **Admin acts** (`set_guardians`, `set_paused`, `set_mint_limit`): `threshold` of the current
//!   guardians over a message carrying the shared `admin_nonce`. Pause stops mint, propose,
//!   execute and burn; never challenge, transfers or storage management.
//!
//! Every signature may be submitted by anyone: guardian keys hold no NEAR. There is no owner key,
//! no upgrade method (N-9).

pub mod encoding;

use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::events::{FtBurn, FtMint};
use near_contract_standards::fungible_token::metadata::{
    FT_METADATA_SPEC, FungibleTokenMetadata, FungibleTokenMetadataProvider,
};
use near_contract_standards::fungible_token::resolver::FungibleTokenResolver;
use near_contract_standards::storage_management::{
    StorageBalance, StorageBalanceBounds, StorageManagement,
};
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::{self, Value, json};
use near_sdk::store::{LookupMap, LookupSet, Vector};
use near_sdk::{
    AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise, PromiseOrValue, env, near,
    require,
};

pub use encoding::{BridgeMessage, BurnRecord, GuardianKey};
use encoding::{burn_record_bytes, decode_hex, digest_preimage, encode_hex};

/// NEP-297 `standard` of this contract's own events.
pub const EVENT_STANDARD: &str = "wyec_bridge";
/// NEP-297 `version` of this contract's own events.
pub const EVENT_VERSION: &str = "1.0.0";
/// Most records `get_burns` returns per call.
pub const MAX_BURNS_PER_PAGE: u64 = 100;
/// Storage bytes a [`BurnRecord`] adds, excluding the `from` account id's length: NEAR's 40-byte
/// per-record overhead, the 5-byte `Vector` key (prefix + u32 index) and the 76 fixed bytes of the
/// borsh record (8 + 4 + 16 + 32 + 8 + 8).
pub const BURN_RECORD_FIXED_BYTES: u64 = 40 + 5 + 76;

const NS_PER_SEC: u64 = 1_000_000_000;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Token,
    Consumed,
    Proposals,
    Vetoed,
    Burns,
}

/// A pending optimistic mint.
#[derive(Clone, Debug)]
#[near(serializers = [borsh])]
pub struct Proposal {
    /// Unique, non-zero, increasing (`proposal_count` at proposal time).
    pub id: u64,
    /// The guardian whose `Mint` signature opened it.
    pub proposer: GuardianKey,
    pub receiver_id: AccountId,
    pub amount: u128,
    /// Earliest block time (seconds) at which `execute_mint` succeeds.
    pub eta_sec: u64,
}

/// What `execute_mint(lock_id)` would find right now (pause and rate limit aside).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub enum ProposalStatus {
    /// No proposal for this lock.
    None,
    /// Inside the challenge window.
    Pending,
    /// Window passed, proposer still a guardian: executable.
    Ready,
    /// Proposer no longer a guardian: not executable, may be re-proposed.
    Void,
}

/// JSON view of a [`Proposal`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub struct ProposalView {
    pub proposal_id: u64,
    /// Hex of the proposer's 64-byte public key.
    pub proposer: String,
    pub receiver_id: AccountId,
    pub amount: U128,
    pub eta_sec: u64,
    pub status: ProposalStatus,
}

/// JSON view of a [`BurnRecord`], with the SHA-256 of its borsh encoding (the `HKN1` memo data).
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub struct BurnView {
    pub nonce: u64,
    pub from: AccountId,
    pub amount: U128,
    /// Hex of the 32-byte Ycash recipient.
    pub ycash_recipient: String,
    pub block_height: u64,
    pub timestamp_ns: U64,
    /// Hex of `SHA256(borsh(record))`.
    pub record_hash: String,
}

/// JSON view of the bridge configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [json])]
pub struct ConfigView {
    pub network_id: String,
    pub contract_id: AccountId,
    pub guardians: Vec<String>,
    pub threshold: u8,
    pub challenge_window_sec: u64,
    pub mint_cap: U128,
    pub cap_window_sec: u64,
    pub admin_nonce: u64,
    pub paused: bool,
    pub proposal_count: u64,
    pub burn_count: u64,
    pub total_supply: U128,
}

#[near(
    contract_state,
    contract_metadata(
        standard(standard = "nep141", version = "1.0.0"),
        standard(standard = "nep145", version = "1.0.0"),
        standard(standard = "nep148", version = "1.0.0"),
        standard(standard = "wyec_bridge", version = "1.0.0"),
    )
)]
#[derive(PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    /// Bound into every digest (`mainnet`, `testnet`, `sandbox`, …).
    network_id: String,
    /// The current guardian set, in the order it was set.
    guardians: Vec<GuardianKey>,
    /// Signatures needed by `mint` and every admin act.
    threshold: u8,
    /// Seconds between `propose_mint` and the earliest `execute_mint` (> 0). Fixed for the
    /// contract's life, as on Ethereum.
    challenge_window_sec: u64,
    /// Locks that have minted (either path). Never cleared.
    consumed: LookupSet<[u8; 32]>,
    /// Pending optimistic mints, at most one per lock.
    proposals: LookupMap<[u8; 32], Proposal>,
    /// Proposals ever opened; the last id issued.
    proposal_count: u64,
    /// `(lock_id, proposer)` pairs whose proposal was challenged: that proposer may not propose
    /// that lock again (its public Mint signature could otherwise be replayed after every
    /// challenge). Other guardians and the threshold path still can.
    vetoed: LookupSet<([u8; 32], GuardianKey)>,
    /// Every burn towards Ycash; the index is the burn nonce.
    burns: Vector<BurnRecord>,
    /// Bound into every admin act; shared by all of them.
    admin_nonce: u64,
    paused: bool,
    /// Most zatoshi both mint paths together may mint per window; 0 = no limit.
    mint_cap: u128,
    cap_window_sec: u64,
    /// Index of the window `minted_in_window` counts.
    mint_window: u64,
    minted_in_window: u128,
}

// ------------------------------------------------------------------------------------- bridge

#[near]
impl Contract {
    /// `guardians`: hex of 64-byte uncompressed secp256k1 public keys (x ‖ y). `threshold`: 1..=len
    /// (≥ 2 wherever the optimistic path is the security model). `challenge_window_sec` > 0.
    /// `mint_cap` zatoshi per `cap_window_sec`; `mint_cap == 0` disables the limit, otherwise
    /// `cap_window_sec` > 0.
    #[init]
    pub fn new(
        network_id: String,
        guardians: Vec<String>,
        threshold: u8,
        challenge_window_sec: u64,
        mint_cap: U128,
        cap_window_sec: u64,
    ) -> Self {
        require!(!network_id.is_empty(), "wyec: empty network_id");
        require!(challenge_window_sec > 0, "wyec: zero challenge window");
        let mut this = Self {
            token: FungibleToken::new(StorageKey::Token),
            network_id,
            guardians: Vec::new(),
            threshold: 0,
            challenge_window_sec,
            consumed: LookupSet::new(StorageKey::Consumed),
            proposals: LookupMap::new(StorageKey::Proposals),
            proposal_count: 0,
            vetoed: LookupSet::new(StorageKey::Vetoed),
            burns: Vector::new(StorageKey::Burns),
            admin_nonce: 0,
            paused: false,
            mint_cap: 0,
            cap_window_sec: 0,
            mint_window: 0,
            minted_in_window: 0,
        };
        this.internal_set_guardians(parse_guardians(&guardians), threshold);
        this.internal_set_mint_limit(mint_cap.0, cap_window_sec);
        this
    }

    // ------------------------------------------------------------- mint: threshold path

    /// Mints `amount` to `receiver_id` for `lock_id` on `threshold` guardian signatures,
    /// immediately. Clears any pending optimistic proposal for the lock. Registers the
    /// receiver's storage from the contract balance if needed (N-10). Callable by anyone.
    /// `sigs`: hex of 65-byte `r ‖ s ‖ v` (v ∈ {0,1}, low-S) over the `Mint` digest, ordered by
    /// strictly ascending recovered public key.
    pub fn mint(
        &mut self,
        lock_id: String,
        amount: U128,
        receiver_id: AccountId,
        sigs: Vec<String>,
    ) {
        self.assert_not_paused();
        let lock_id = parse_lock_id(&lock_id);
        require!(!self.consumed.contains(&lock_id), "wyec: lock consumed");
        let digest = self.digest(&BridgeMessage::Mint {
            lock_id,
            amount: amount.0,
            receiver_id: receiver_id.to_string(),
        });
        self.check_threshold(&digest, &sigs);
        self.proposals.remove(&lock_id);
        self.internal_mint(lock_id, amount.0, &receiver_id);
    }

    // ------------------------------------------------------------- mint: optimistic path

    /// Opens an optimistic mint on ONE current guardian's signature over the same `Mint` digest
    /// the threshold path verifies. Callable by anyone. A void proposal (proposer rotated out) is
    /// replaced. Returns the new proposal id.
    pub fn propose_mint(
        &mut self,
        lock_id: String,
        amount: U128,
        receiver_id: AccountId,
        sig: String,
    ) -> u64 {
        self.assert_not_paused();
        let lock_id = parse_lock_id(&lock_id);
        require!(!self.consumed.contains(&lock_id), "wyec: lock consumed");
        require!(amount.0 != 0, "wyec: zero amount");
        if let Some(p) = self.proposals.get(&lock_id) {
            require!(!self.is_guardian(&p.proposer), "wyec: proposal pending");
        }
        let digest = self.digest(&BridgeMessage::Mint {
            lock_id,
            amount: amount.0,
            receiver_id: receiver_id.to_string(),
        });
        let signer = recover(&digest, &sig);
        require!(self.is_guardian(&signer), "wyec: not a guardian");
        require!(
            !self.vetoed.contains(&(lock_id, signer)),
            "wyec: proposer vetoed for this lock"
        );

        self.proposal_count += 1;
        let id = self.proposal_count;
        let eta_sec = now_sec() + self.challenge_window_sec;
        emit(
            "mint_proposed",
            json!({
                "lock_id": encode_hex(&lock_id),
                "proposal_id": id,
                "proposer": encode_hex(&signer),
                "receiver_id": receiver_id,
                "amount": U128(amount.0),
                "eta_sec": eta_sec,
            }),
        );
        self.proposals.insert(
            lock_id,
            Proposal {
                id,
                proposer: signer,
                receiver_id,
                amount: amount.0,
                eta_sec,
            },
        );
        id
    }

    /// Deletes proposal `proposal_id` for `lock_id` on ANY one current guardian's signature over
    /// `Challenge { lock_id, proposal_id }`, and vetoes the proposer for that lock. Callable by
    /// anyone, also while paused. The lock is not consumed: another guardian may re-propose it, or
    /// the threshold path mint it. A guardian may challenge its own proposal.
    pub fn challenge_mint(&mut self, lock_id: String, proposal_id: u64, sig: String) {
        let lock_id = parse_lock_id(&lock_id);
        let proposer = match self.proposals.get(&lock_id) {
            Some(p) if p.id == proposal_id => p.proposer,
            _ => env::panic_str("wyec: no such proposal"),
        };
        let digest = self.digest(&BridgeMessage::Challenge {
            lock_id,
            proposal_id,
        });
        let signer = recover(&digest, &sig);
        require!(self.is_guardian(&signer), "wyec: not a guardian");
        self.vetoed.insert((lock_id, proposer));
        self.proposals.remove(&lock_id);
        emit(
            "mint_challenged",
            json!({
                "lock_id": encode_hex(&lock_id),
                "proposal_id": proposal_id,
                "proposer": encode_hex(&proposer),
                "challenger": encode_hex(&signer),
            }),
        );
    }

    /// Executes the proposal for `lock_id` once its window has passed and while its proposer is
    /// still a guardian. Callable by anyone. Subject to the rate limit: a proposal over the limit
    /// stays pending and can be executed in a later window.
    pub fn execute_mint(&mut self, lock_id: String) {
        self.assert_not_paused();
        let lock_id = parse_lock_id(&lock_id);
        let p = match self.proposals.get(&lock_id) {
            Some(p) => p.clone(),
            None => env::panic_str("wyec: no such proposal"),
        };
        require!(now_sec() >= p.eta_sec, "wyec: challenge window open");
        require!(
            self.is_guardian(&p.proposer),
            "wyec: proposer not a guardian"
        );
        // Invariant: a lock with a proposal is never consumed (propose checks; mint clears).
        self.proposals.remove(&lock_id);
        self.internal_mint(lock_id, p.amount, &p.receiver_id);
    }

    // ---------------------------------------------------------------------------- burn

    /// Burns `amount` of the caller's wYEC for release to `ycash_recipient` on Ycash (hex of 32
    /// bytes, Hawkeye plan §4.2: `0x01`, kind `0x00` P2PKH / `0x01` P2SH, 10 zero bytes,
    /// hash160; opaque here). Unconditional for the holder; stopped only by pause.
    ///
    /// Deposit: at least 1 yoctoNEAR (full-access-key confirmation, NEP-141 style) **and** the
    /// storage cost of the appended record (`burn_storage_deposit`); the excess is refunded.
    /// Returns the burn nonce.
    #[payable]
    pub fn burn(&mut self, amount: U128, ycash_recipient: String) -> u64 {
        self.assert_not_paused();
        let deposit = env::attached_deposit();
        require!(
            !deposit.is_zero(),
            "Requires attached deposit of at least 1 yoctoNEAR"
        );
        let ycash_recipient: [u8; 32] = decode_hex(&ycash_recipient)
            .unwrap_or_else(|| env::panic_str("wyec: ycash_recipient must be 32 bytes of hex"));
        let from = env::predecessor_account_id();
        let cost = burn_storage_cost(&from);
        require!(
            deposit >= cost,
            "wyec: attached deposit below the burn record's storage cost"
        );

        self.token.internal_withdraw(&from, amount.0);
        let nonce = u64::from(self.burns.len());
        let record = BurnRecord {
            nonce,
            from: from.to_string(),
            amount: amount.0,
            ycash_recipient,
            block_height: env::block_height(),
            timestamp_ns: env::block_timestamp(),
        };
        FtBurn {
            owner_id: &from,
            amount,
            memo: Some("burn_to_ycash"),
        }
        .emit();
        emit(
            "burn_to_ycash",
            serde_json::to_value(burn_view(&record)).expect("json"),
        );
        self.burns.push(record);

        let refund = deposit.saturating_sub(cost);
        if !refund.is_zero() {
            Promise::new(from).transfer(refund).detach();
        }
        nonce
    }

    // ---------------------------------------------------------------- admin (threshold)

    /// Replaces the guardian set and threshold; `sigs`: threshold of the CURRENT set over
    /// `SetGuardians { guardians, threshold, admin_nonce }`. Works while paused.
    pub fn set_guardians(&mut self, guardians: Vec<String>, threshold: u8, sigs: Vec<String>) {
        let guardians = parse_guardians(&guardians);
        let digest = self.digest(&BridgeMessage::SetGuardians {
            guardians: guardians.clone(),
            threshold,
            admin_nonce: self.admin_nonce,
        });
        self.check_threshold(&digest, &sigs);
        self.admin_nonce += 1;
        self.internal_set_guardians(guardians, threshold);
    }

    /// Pauses or unpauses mint (both paths), execute and burn; never challenge, transfers or
    /// storage management. Setting the current state fails. `sigs`: threshold over
    /// `SetPaused { paused, admin_nonce }`.
    pub fn set_paused(&mut self, paused: bool, sigs: Vec<String>) {
        let digest = self.digest(&BridgeMessage::SetPaused {
            paused,
            admin_nonce: self.admin_nonce,
        });
        self.check_threshold(&digest, &sigs);
        self.admin_nonce += 1;
        require!(
            self.paused != paused,
            if paused {
                "wyec: already paused"
            } else {
                "wyec: not paused"
            }
        );
        self.paused = paused;
        emit("paused", json!({ "paused": paused }));
    }

    /// Sets the mint rate limit for both paths and restarts the window's running total.
    /// `sigs`: threshold over `SetMintLimit { mint_cap, cap_window_sec, admin_nonce }`.
    /// Works while paused.
    pub fn set_mint_limit(&mut self, mint_cap: U128, cap_window_sec: u64, sigs: Vec<String>) {
        let digest = self.digest(&BridgeMessage::SetMintLimit {
            mint_cap: mint_cap.0,
            cap_window_sec,
            admin_nonce: self.admin_nonce,
        });
        self.check_threshold(&digest, &sigs);
        self.admin_nonce += 1;
        self.internal_set_mint_limit(mint_cap.0, cap_window_sec);
    }

    // ---------------------------------------------------------------------------- views

    /// Hex of the current guardian keys, in the order they were set.
    pub fn get_guardians(&self) -> Vec<String> {
        self.guardians.iter().map(|g| encode_hex(g)).collect()
    }

    pub fn get_threshold(&self) -> u8 {
        self.threshold
    }

    pub fn get_admin_nonce(&self) -> u64 {
        self.admin_nonce
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn is_consumed(&self, lock_id: String) -> bool {
        self.consumed.contains(&parse_lock_id(&lock_id))
    }

    /// Whether `guardian` (hex key) is barred from proposing `lock_id`.
    pub fn is_vetoed(&self, lock_id: String, guardian: String) -> bool {
        let g: GuardianKey =
            decode_hex(&guardian).unwrap_or_else(|| env::panic_str("wyec: bad guardian key"));
        self.vetoed.contains(&(parse_lock_id(&lock_id), g))
    }

    /// The proposal for `lock_id`, with its status (pause and rate limit aside).
    pub fn get_proposal(&self, lock_id: String) -> Option<ProposalView> {
        self.proposals
            .get(&parse_lock_id(&lock_id))
            .map(|p| ProposalView {
                proposal_id: p.id,
                proposer: encode_hex(&p.proposer),
                receiver_id: p.receiver_id.clone(),
                amount: U128(p.amount),
                eta_sec: p.eta_sec,
                status: self.status_of(p),
            })
    }

    pub fn proposal_status(&self, lock_id: String) -> ProposalStatus {
        self.proposals
            .get(&parse_lock_id(&lock_id))
            .map_or(ProposalStatus::None, |p| self.status_of(p))
    }

    /// Burn records with nonce in `[from_nonce, from_nonce + limit)`, at most
    /// [`MAX_BURNS_PER_PAGE`].
    pub fn get_burns(&self, from_nonce: u64, limit: u64) -> Vec<BurnView> {
        let len = u64::from(self.burns.len());
        let end = from_nonce
            .saturating_add(limit.min(MAX_BURNS_PER_PAGE))
            .min(len);
        (from_nonce..end)
            .map(|n| burn_view(self.burns.get(n as u32).expect("in range")))
            .collect()
    }

    pub fn get_burn_count(&self) -> u64 {
        u64::from(self.burns.len())
    }

    /// The deposit `burn` needs from `account_id` (the record's storage cost).
    pub fn burn_storage_deposit(&self, account_id: AccountId) -> NearToken {
        burn_storage_cost(&account_id)
    }

    /// Zatoshi mintable now under the rate limit (`u128::MAX` if no limit).
    pub fn mint_available(&self) -> U128 {
        if self.mint_cap == 0 {
            return U128(u128::MAX);
        }
        U128(self.mint_cap - self.used_in_window(now_sec() / self.cap_window_sec))
    }

    /// Hex of the digest a guardian signs for a mint (either path).
    pub fn mint_digest(&self, lock_id: String, amount: U128, receiver_id: AccountId) -> String {
        encode_hex(&self.digest(&BridgeMessage::Mint {
            lock_id: parse_lock_id(&lock_id),
            amount: amount.0,
            receiver_id: receiver_id.to_string(),
        }))
    }

    /// Hex of the digest a guardian signs to challenge proposal `proposal_id`.
    pub fn challenge_digest(&self, lock_id: String, proposal_id: u64) -> String {
        encode_hex(&self.digest(&BridgeMessage::Challenge {
            lock_id: parse_lock_id(&lock_id),
            proposal_id,
        }))
    }

    pub fn config(&self) -> ConfigView {
        ConfigView {
            network_id: self.network_id.clone(),
            contract_id: env::current_account_id(),
            guardians: self.get_guardians(),
            threshold: self.threshold,
            challenge_window_sec: self.challenge_window_sec,
            mint_cap: U128(self.mint_cap),
            cap_window_sec: self.cap_window_sec,
            admin_nonce: self.admin_nonce,
            paused: self.paused,
            proposal_count: self.proposal_count,
            burn_count: u64::from(self.burns.len()),
            total_supply: U128(self.token.total_supply),
        }
    }
}

// ---------------------------------------------------------------------------- internals

impl Contract {
    /// `SHA256("HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖ borsh(msg))`, §2.3.
    pub fn digest(&self, msg: &BridgeMessage) -> [u8; 32] {
        env::sha256_array(digest_preimage(
            &self.network_id,
            env::current_account_id().as_str(),
            msg,
        ))
    }

    fn is_guardian(&self, key: &GuardianKey) -> bool {
        self.guardians.contains(key)
    }

    fn assert_not_paused(&self) {
        require!(!self.paused, "wyec: paused");
    }

    fn status_of(&self, p: &Proposal) -> ProposalStatus {
        if !self.is_guardian(&p.proposer) {
            ProposalStatus::Void
        } else if now_sec() < p.eta_sec {
            ProposalStatus::Pending
        } else {
            ProposalStatus::Ready
        }
    }

    fn used_in_window(&self, window: u64) -> u128 {
        if window == self.mint_window {
            self.minted_in_window
        } else {
            0
        }
    }

    /// At least `threshold` signatures, recovering to strictly ascending current-guardian keys.
    fn check_threshold(&self, digest: &[u8; 32], sigs: &[String]) {
        require!(
            sigs.len() >= usize::from(self.threshold),
            "wyec: below threshold"
        );
        let mut last: Option<GuardianKey> = None;
        for sig in sigs {
            let signer = recover(digest, sig);
            if let Some(prev) = last {
                require!(signer > prev, "wyec: signers not strictly ascending");
            }
            require!(self.is_guardian(&signer), "wyec: not a guardian");
            last = Some(signer);
        }
    }

    /// Consumes `lock_id`, applies the rate limit, registers the receiver if needed and mints.
    /// The caller has checked authorisation.
    fn internal_mint(&mut self, lock_id: [u8; 32], amount: u128, receiver_id: &AccountId) {
        self.consumed.insert(lock_id);
        if self.mint_cap != 0 {
            // Invariant: minted_in_window <= mint_cap (raised only within the cap; reset on change).
            let w = now_sec() / self.cap_window_sec;
            let used = self.used_in_window(w);
            require!(amount <= self.mint_cap - used, "wyec: mint rate limited");
            self.mint_window = w;
            self.minted_in_window = used + amount;
        }
        if !self.token.accounts.contains_key(receiver_id) {
            // N-10: the depositor cannot register on NEAR; the contract balance pays.
            self.token.internal_register_account(receiver_id);
        }
        self.token.internal_deposit(receiver_id, amount);
        FtMint {
            owner_id: receiver_id,
            amount: U128(amount),
            memo: Some("mint_from_ycash"),
        }
        .emit();
        emit(
            "minted",
            json!({
                "lock_id": encode_hex(&lock_id),
                "receiver_id": receiver_id,
                "amount": U128(amount),
            }),
        );
    }

    fn internal_set_guardians(&mut self, guardians: Vec<GuardianKey>, threshold: u8) {
        require!(
            threshold != 0 && usize::from(threshold) <= guardians.len(),
            "wyec: bad guardian set"
        );
        for (i, g) in guardians.iter().enumerate() {
            require!(
                *g != [0u8; 64] && !guardians[..i].contains(g),
                "wyec: bad guardian set"
            );
        }
        emit(
            "guardians_changed",
            json!({
                "guardians": guardians.iter().map(|g| encode_hex(g)).collect::<Vec<_>>(),
                "threshold": threshold,
            }),
        );
        self.guardians = guardians;
        self.threshold = threshold;
    }

    /// The running total restarts: a quorum able to set the cap could raise it anyway.
    fn internal_set_mint_limit(&mut self, mint_cap: u128, cap_window_sec: u64) {
        require!(mint_cap == 0 || cap_window_sec != 0, "wyec: bad mint limit");
        self.mint_cap = mint_cap;
        self.cap_window_sec = cap_window_sec;
        self.mint_window = if mint_cap == 0 {
            0
        } else {
            now_sec() / cap_window_sec
        };
        self.minted_in_window = 0;
        emit(
            "mint_limit_changed",
            json!({ "mint_cap": U128(mint_cap), "cap_window_sec": cap_window_sec }),
        );
    }
}

fn now_sec() -> u64 {
    env::block_timestamp() / NS_PER_SEC
}

fn parse_lock_id(s: &str) -> [u8; 32] {
    decode_hex(s).unwrap_or_else(|| env::panic_str("wyec: lock_id must be 32 bytes of hex"))
}

fn parse_guardians(keys: &[String]) -> Vec<GuardianKey> {
    keys.iter()
        .map(|k| decode_hex(k).unwrap_or_else(|| env::panic_str("wyec: bad guardian key")))
        .collect()
}

/// The 64-byte key that signed `digest`; panics on a malformed, high-S or unrecoverable signature.
fn recover(digest: &[u8; 32], sig_hex: &str) -> GuardianKey {
    let sig: [u8; 65] = decode_hex(sig_hex)
        .unwrap_or_else(|| env::panic_str("wyec: signature must be 65 bytes of hex"));
    require!(sig[64] <= 1, "wyec: bad signature v");
    // malleability_flag = true: high-S signatures are rejected (low-S, N-6).
    env::ecrecover(digest, &sig[..64], sig[64], true)
        .unwrap_or_else(|| env::panic_str("wyec: bad signature"))
}

fn burn_storage_cost(from: &AccountId) -> NearToken {
    env::storage_byte_cost().saturating_mul(u128::from(BURN_RECORD_FIXED_BYTES + from.len() as u64))
}

fn burn_view(r: &BurnRecord) -> BurnView {
    BurnView {
        nonce: r.nonce,
        from: r.from.parse().expect("stored account id"),
        amount: U128(r.amount),
        ycash_recipient: encode_hex(&r.ycash_recipient),
        block_height: r.block_height,
        timestamp_ns: U64(r.timestamp_ns),
        record_hash: encode_hex(&env::sha256_array(burn_record_bytes(r))),
    }
}

/// NEP-297 event of this contract's own standard; `data` is a one-element array.
fn emit(event: &str, data: Value) {
    let ev = json!({
        "standard": EVENT_STANDARD,
        "version": EVENT_VERSION,
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{ev}"));
}

// ------------------------------------------------------------------------ NEP-141/145/148

#[near]
impl FungibleTokenCore for Contract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id, amount, memo)
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenResolver for Contract {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used, burned) =
            self.token
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);
        if burned > 0 {
            // The sender unregistered mid-transfer: the standard burns the refund. No Ycash
            // release follows (no BurnRecord): supply only shrinks, the backing invariant holds.
            FtBurn {
                owner_id: &sender_id,
                amount: U128(burned),
                memo: Some("unregistered"),
            }
            .emit();
        }
        used.into()
    }
}

#[near]
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    /// `force = true` with a positive balance destroys that balance (NEP-145); no Ycash release
    /// follows. Use `burn` to redeem.
    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        match self.token.internal_storage_unregister(force) {
            Some((account_id, balance)) => {
                if balance > 0 {
                    FtBurn {
                        owner_id: &account_id,
                        amount: U128(balance),
                        memo: Some("unregistered"),
                    }
                    .emit();
                }
                true
            }
            None => false,
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Wrapped Ycash".to_string(),
            symbol: "wYEC".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 8,
        }
    }
}

#[cfg(test)]
mod tests;
