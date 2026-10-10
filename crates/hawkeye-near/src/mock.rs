//! A mock NEAR JSON-RPC node (feature `mock`) running a model of the `wyec-near` contract, for
//! this crate's tests and the daemon's engine tests.
//!
//! It answers the methods [`NearRpc`](crate::rpc::NearRpc) uses — `block`, `query`
//! (`call_function`, `view_access_key`), `EXPERIMENTAL_changes`, `EXPERIMENTAL_receipt`,
//! `send_tx` — in nearcore 2.x's shapes, and executes signed transactions for real: the Borsh
//! is decoded with this crate's codec, the ed25519 signature verified, the access-key nonce and
//! the block hash checked. Each transaction is one block holding one receipt; a successful call
//! records a data change caused by that receipt. Every block keeps a snapshot of the contract, so
//! views at a past block (`block_id`) answer as the node would.
//!
//! The contract model ([`Contract`]) follows `near/src/lib.rs` method by method — the same
//! checks in the same order, the same panic messages, the same JSON — with the digests and
//! signature recovery of `hawkeye-core::near` (the contract's own encodings, golden-vectored on
//! both sides). It is not NEAR: no gas, no storage staking except the burn deposit rule, no
//! promises (refunds are not modelled), and a block is final as soon as it exists.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hawkeye_core::AccountId;
use hawkeye_core::near::{BridgeMessage, BurnRecord, Domain, GuardianKey, recover_guardian};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::rpc::{b58, hash_from_b58};
use crate::tx::{Action, SignedTransaction};

/// `env::storage_byte_cost()`: 10^19 yoctoNEAR per byte.
pub const STORAGE_BYTE_COST: u128 = 10_000_000_000_000_000_000;
/// `BURN_RECORD_FIXED_BYTES` of the contract.
pub const BURN_RECORD_FIXED_BYTES: u128 = 40 + 5 + 76;
/// The first block's timestamp: 2026-01-01T00:00:00Z.
pub const GENESIS_NS: u64 = 1_767_225_600_000_000_000;
const NS: u64 = 1_000_000_000;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ------------------------------------------------------------------------------------ contract

/// A pending proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Id.
    pub id: u64,
    /// The proposer's key.
    pub proposer: GuardianKey,
    /// The receiver.
    pub receiver_id: String,
    /// zatoshi.
    pub amount: u128,
    /// Unix seconds.
    pub eta_sec: u64,
}

/// The `wyec-near` contract's state, as `near/src/lib.rs` keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// The network id in every digest.
    pub network_id: String,
    /// Current guardians, in set order.
    pub guardians: Vec<GuardianKey>,
    /// Threshold.
    pub threshold: u8,
    /// Challenge window, seconds.
    pub challenge_window_sec: u64,
    /// Consumed lock ids.
    pub consumed: BTreeSet<[u8; 32]>,
    /// Pending proposals.
    pub proposals: BTreeMap<[u8; 32], Proposal>,
    /// Proposals ever opened.
    pub proposal_count: u64,
    /// Vetoed (lock, proposer) pairs.
    pub vetoed: BTreeSet<([u8; 32], GuardianKey)>,
    /// Burn records.
    pub burns: Vec<BurnRecord>,
    /// Admin nonce.
    pub admin_nonce: u64,
    /// Paused.
    pub paused: bool,
    /// Rate limit (0: none).
    pub mint_cap: u128,
    /// Window seconds.
    pub cap_window_sec: u64,
    /// Current window index.
    pub mint_window: u64,
    /// Minted in it.
    pub minted_in_window: u128,
    /// Token balances (registered accounts).
    pub balances: BTreeMap<String, u128>,
    /// Total supply.
    pub total_supply: u128,
}

type Exec = Result<Value, String>;

fn arg<'a>(a: &'a Value, k: &str) -> Result<&'a Value, String> {
    a.get(k)
        .ok_or_else(|| format!("Failed to deserialize input from JSON.: missing field `{k}`"))
}

fn arg_str<'a>(a: &'a Value, k: &str) -> Result<&'a str, String> {
    arg(a, k)?
        .as_str()
        .ok_or_else(|| format!("Failed to deserialize input from JSON.: `{k}` is not a string"))
}

fn arg_u128(a: &Value, k: &str) -> Result<u128, String> {
    arg_str(a, k)?
        .parse()
        .map_err(|_| format!("Failed to deserialize input from JSON.: `{k}` is not a U128"))
}

fn arg_u64(a: &Value, k: &str) -> Result<u64, String> {
    arg(a, k)?
        .as_u64()
        .ok_or_else(|| format!("Failed to deserialize input from JSON.: `{k}` is not a u64"))
}

fn arg_account(a: &Value, k: &str) -> Result<AccountId, String> {
    AccountId::parse(arg_str(a, k)?)
        .map_err(|_| format!("Failed to deserialize input from JSON.: `{k}` is not an account id"))
}

fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s).ok()?.try_into().ok()
}

fn require(c: bool, msg: &str) -> Result<(), String> {
    if c { Ok(()) } else { Err(msg.to_owned()) }
}

fn lock_arg(a: &Value) -> Result<[u8; 32], String> {
    decode_hex(arg_str(a, "lock_id")?).ok_or_else(|| "wyec: lock_id must be 32 bytes of hex".into())
}

fn recover(digest: &[u8; 32], sig_hex: &str) -> Result<GuardianKey, String> {
    let sig: [u8; 65] =
        decode_hex(sig_hex).ok_or_else(|| "wyec: signature must be 65 bytes of hex".to_owned())?;
    require(sig[64] <= 1, "wyec: bad signature v")?;
    recover_guardian(digest, &sig).map_err(|_| "wyec: bad signature".to_owned())
}

/// The context a call runs in.
#[derive(Debug, Clone, Copy)]
pub struct Env<'a> {
    /// The digest domain (network id, contract account).
    pub domain: &'a Domain,
    /// The caller.
    pub predecessor: &'a str,
    /// Attached yoctoNEAR.
    pub deposit: u128,
    /// Block height.
    pub height: u64,
    /// Block timestamp, ns.
    pub timestamp_ns: u64,
}

impl Contract {
    /// `new(network_id, guardians, threshold, challenge_window_sec, mint_cap, cap_window_sec)`.
    pub fn new(
        network_id: &str,
        guardians: Vec<GuardianKey>,
        threshold: u8,
        challenge_window_sec: u64,
        mint_cap: u128,
        cap_window_sec: u64,
    ) -> Self {
        assert!(!network_id.is_empty() && challenge_window_sec > 0);
        assert!(threshold != 0 && usize::from(threshold) <= guardians.len());
        assert!(mint_cap == 0 || cap_window_sec != 0);
        Self {
            network_id: network_id.into(),
            guardians,
            threshold,
            challenge_window_sec,
            consumed: BTreeSet::new(),
            proposals: BTreeMap::new(),
            proposal_count: 0,
            vetoed: BTreeSet::new(),
            burns: vec![],
            admin_nonce: 0,
            paused: false,
            mint_cap,
            cap_window_sec,
            mint_window: if mint_cap == 0 {
                0
            } else {
                GENESIS_NS / NS / cap_window_sec
            },
            minted_in_window: 0,
            balances: BTreeMap::new(),
            total_supply: 0,
        }
    }

    fn is_guardian(&self, k: &GuardianKey) -> bool {
        self.guardians.contains(k)
    }

    fn status(&self, p: &Proposal, now: u64) -> &'static str {
        if !self.is_guardian(&p.proposer) {
            "Void"
        } else if now < p.eta_sec {
            "Pending"
        } else {
            "Ready"
        }
    }

    fn used_in_window(&self, w: u64) -> u128 {
        if w == self.mint_window {
            self.minted_in_window
        } else {
            0
        }
    }

    fn check_threshold(&self, digest: &[u8; 32], sigs: &Value) -> Result<(), String> {
        let sigs = sigs
            .as_array()
            .ok_or("Failed to deserialize input from JSON.: `sigs` is not an array")?;
        require(
            sigs.len() >= usize::from(self.threshold),
            "wyec: below threshold",
        )?;
        let mut last: Option<GuardianKey> = None;
        for s in sigs {
            let signer = recover(digest, s.as_str().unwrap_or(""))?;
            if let Some(prev) = last {
                require(signer > prev, "wyec: signers not strictly ascending")?;
            }
            require(self.is_guardian(&signer), "wyec: not a guardian")?;
            last = Some(signer);
        }
        Ok(())
    }

    fn internal_mint(
        &mut self,
        lock_id: [u8; 32],
        amount: u128,
        receiver: &str,
        now: u64,
    ) -> Result<(), String> {
        self.consumed.insert(lock_id);
        if self.mint_cap != 0 {
            let w = now / self.cap_window_sec;
            let used = self.used_in_window(w);
            require(amount <= self.mint_cap - used, "wyec: mint rate limited")?;
            self.mint_window = w;
            self.minted_in_window = used + amount;
        }
        *self.balances.entry(receiver.to_owned()).or_insert(0) += amount;
        self.total_supply += amount;
        Ok(())
    }

    /// Execute a change method. On `Err` (a panic) the caller discards the changed state.
    pub fn call(&mut self, env: Env<'_>, method: &str, a: &Value) -> Exec {
        let now = env.timestamp_ns / NS;
        let digest = |m: BridgeMessage| env.domain.digest(&m);
        match method {
            "mint" => {
                require(!self.paused, "wyec: paused")?;
                let lock_id = lock_arg(a)?;
                let amount = arg_u128(a, "amount")?;
                let receiver_id = arg_account(a, "receiver_id")?;
                require(!self.consumed.contains(&lock_id), "wyec: lock consumed")?;
                let d = digest(BridgeMessage::Mint {
                    lock_id,
                    amount,
                    receiver_id: receiver_id.clone(),
                });
                self.check_threshold(&d, arg(a, "sigs")?)?;
                self.proposals.remove(&lock_id);
                self.internal_mint(lock_id, amount, receiver_id.as_str(), now)?;
                Ok(Value::Null)
            }
            "propose_mint" => {
                require(!self.paused, "wyec: paused")?;
                let lock_id = lock_arg(a)?;
                let amount = arg_u128(a, "amount")?;
                let receiver_id = arg_account(a, "receiver_id")?;
                require(!self.consumed.contains(&lock_id), "wyec: lock consumed")?;
                require(amount != 0, "wyec: zero amount")?;
                if let Some(p) = self.proposals.get(&lock_id) {
                    require(!self.is_guardian(&p.proposer), "wyec: proposal pending")?;
                }
                let d = digest(BridgeMessage::Mint {
                    lock_id,
                    amount,
                    receiver_id: receiver_id.clone(),
                });
                let signer = recover(&d, arg_str(a, "sig")?)?;
                require(self.is_guardian(&signer), "wyec: not a guardian")?;
                require(
                    !self.vetoed.contains(&(lock_id, signer)),
                    "wyec: proposer vetoed for this lock",
                )?;
                self.proposal_count += 1;
                let id = self.proposal_count;
                self.proposals.insert(
                    lock_id,
                    Proposal {
                        id,
                        proposer: signer,
                        receiver_id: receiver_id.to_string(),
                        amount,
                        eta_sec: now + self.challenge_window_sec,
                    },
                );
                Ok(json!(id))
            }
            "challenge_mint" => {
                let lock_id = lock_arg(a)?;
                let proposal_id = arg_u64(a, "proposal_id")?;
                let proposer = match self.proposals.get(&lock_id) {
                    Some(p) if p.id == proposal_id => p.proposer,
                    _ => return Err("wyec: no such proposal".into()),
                };
                let d = digest(BridgeMessage::Challenge {
                    lock_id,
                    proposal_id,
                });
                let signer = recover(&d, arg_str(a, "sig")?)?;
                require(self.is_guardian(&signer), "wyec: not a guardian")?;
                self.vetoed.insert((lock_id, proposer));
                self.proposals.remove(&lock_id);
                Ok(Value::Null)
            }
            "execute_mint" => {
                require(!self.paused, "wyec: paused")?;
                let lock_id = lock_arg(a)?;
                let p = self
                    .proposals
                    .get(&lock_id)
                    .cloned()
                    .ok_or("wyec: no such proposal")?;
                require(now >= p.eta_sec, "wyec: challenge window open")?;
                require(
                    self.is_guardian(&p.proposer),
                    "wyec: proposer not a guardian",
                )?;
                self.proposals.remove(&lock_id);
                self.internal_mint(lock_id, p.amount, &p.receiver_id, now)?;
                Ok(Value::Null)
            }
            "burn" => {
                require(!self.paused, "wyec: paused")?;
                require(
                    env.deposit != 0,
                    "Requires attached deposit of at least 1 yoctoNEAR",
                )?;
                let amount = arg_u128(a, "amount")?;
                let ycash_recipient: [u8; 32] = decode_hex(arg_str(a, "ycash_recipient")?)
                    .ok_or("wyec: ycash_recipient must be 32 bytes of hex")?;
                let from = env.predecessor;
                let cost = burn_storage_cost(from);
                require(
                    env.deposit >= cost,
                    "wyec: attached deposit below the burn record's storage cost",
                )?;
                let bal = self
                    .balances
                    .get_mut(from)
                    .ok_or_else(|| format!("The account {from} is not registered"))?;
                require(*bal >= amount, "The account doesn't have enough balance")?;
                *bal -= amount;
                self.total_supply -= amount;
                let nonce = self.burns.len() as u64;
                self.burns.push(BurnRecord {
                    nonce,
                    from: AccountId::parse(from).map_err(|e| e.to_string())?,
                    amount,
                    ycash_recipient,
                    block_height: env.height,
                    timestamp_ns: env.timestamp_ns,
                });
                Ok(json!(nonce))
            }
            "set_guardians" => {
                let guardians: Vec<GuardianKey> = arg(a, "guardians")?
                    .as_array()
                    .ok_or("Failed to deserialize input from JSON.")?
                    .iter()
                    .map(|g| decode_hex(g.as_str().unwrap_or("")).ok_or("wyec: bad guardian key"))
                    .collect::<Result<_, _>>()?;
                let threshold =
                    u8::try_from(arg_u64(a, "threshold")?).map_err(|e| e.to_string())?;
                let d = digest(BridgeMessage::SetGuardians {
                    guardians: guardians.clone(),
                    threshold,
                    admin_nonce: self.admin_nonce,
                });
                self.check_threshold(&d, arg(a, "sigs")?)?;
                self.admin_nonce += 1;
                require(
                    threshold != 0 && usize::from(threshold) <= guardians.len(),
                    "wyec: bad guardian set",
                )?;
                for (i, g) in guardians.iter().enumerate() {
                    require(
                        *g != [0u8; 64] && !guardians[..i].contains(g),
                        "wyec: bad guardian set",
                    )?;
                }
                self.guardians = guardians;
                self.threshold = threshold;
                Ok(Value::Null)
            }
            "set_paused" => {
                let paused = arg(a, "paused")?
                    .as_bool()
                    .ok_or("Failed to deserialize input from JSON.")?;
                let d = digest(BridgeMessage::SetPaused {
                    paused,
                    admin_nonce: self.admin_nonce,
                });
                self.check_threshold(&d, arg(a, "sigs")?)?;
                self.admin_nonce += 1;
                require(
                    self.paused != paused,
                    if paused {
                        "wyec: already paused"
                    } else {
                        "wyec: not paused"
                    },
                )?;
                self.paused = paused;
                Ok(Value::Null)
            }
            "set_mint_limit" => {
                let mint_cap = arg_u128(a, "mint_cap")?;
                let cap_window_sec = arg_u64(a, "cap_window_sec")?;
                let d = digest(BridgeMessage::SetMintLimit {
                    mint_cap,
                    cap_window_sec,
                    admin_nonce: self.admin_nonce,
                });
                self.check_threshold(&d, arg(a, "sigs")?)?;
                self.admin_nonce += 1;
                require(mint_cap == 0 || cap_window_sec != 0, "wyec: bad mint limit")?;
                self.mint_cap = mint_cap;
                self.cap_window_sec = cap_window_sec;
                self.mint_window = if mint_cap == 0 {
                    0
                } else {
                    now / cap_window_sec
                };
                self.minted_in_window = 0;
                Ok(Value::Null)
            }
            "ft_transfer" => {
                require(
                    env.deposit == 1,
                    "Requires attached deposit of exactly 1 yoctoNEAR",
                )?;
                let to = arg_account(a, "receiver_id")?;
                let amount = arg_u128(a, "amount")?;
                let from = env.predecessor;
                let bal = self
                    .balances
                    .get_mut(from)
                    .ok_or_else(|| format!("The account {from} is not registered"))?;
                require(*bal >= amount, "The account doesn't have enough balance")?;
                *bal -= amount;
                *self.balances.entry(to.to_string()).or_insert(0) += amount;
                Ok(Value::Null)
            }
            other => Err(format!("MethodNotFound: {other}")),
        }
    }

    /// Answer a view method.
    pub fn view(&self, domain: &Domain, method: &str, a: &Value, now_ns: u64) -> Exec {
        let now = now_ns / NS;
        let proposal_view = |lock: &[u8; 32]| {
            self.proposals.get(lock).map(|p| {
                json!({"proposal_id": p.id, "proposer": hex::encode(p.proposer),
                       "receiver_id": p.receiver_id, "amount": p.amount.to_string(),
                       "eta_sec": p.eta_sec, "status": self.status(p, now)})
            })
        };
        Ok(match method {
            "get_guardians" => json!(self.guardians.iter().map(hex::encode).collect::<Vec<_>>()),
            "get_threshold" => json!(self.threshold),
            "get_admin_nonce" => json!(self.admin_nonce),
            "is_paused" => json!(self.paused),
            "is_consumed" => json!(self.consumed.contains(&lock_arg(a)?)),
            "is_vetoed" => {
                let g: GuardianKey =
                    decode_hex(arg_str(a, "guardian")?).ok_or("wyec: bad guardian key")?;
                json!(self.vetoed.contains(&(lock_arg(a)?, g)))
            }
            "get_proposal" => proposal_view(&lock_arg(a)?).unwrap_or(Value::Null),
            "proposal_status" => json!(
                self.proposals
                    .get(&lock_arg(a)?)
                    .map_or("None", |p| self.status(p, now))
            ),
            "get_burns" => {
                let from = arg_u64(a, "from_nonce")?;
                let limit = arg_u64(a, "limit")?.min(100);
                let len = self.burns.len() as u64;
                let end = from.saturating_add(limit).min(len);
                json!(
                    (from..end)
                        .map(|n| burn_view(&self.burns[n as usize]))
                        .collect::<Vec<_>>()
                )
            }
            "get_burn_count" => json!(self.burns.len()),
            "burn_storage_deposit" => {
                json!(burn_storage_cost(arg_str(a, "account_id")?).to_string())
            }
            "mint_available" => {
                if self.mint_cap == 0 {
                    json!(u128::MAX.to_string())
                } else {
                    json!(
                        (self.mint_cap - self.used_in_window(now / self.cap_window_sec))
                            .to_string()
                    )
                }
            }
            "ft_total_supply" => json!(self.total_supply.to_string()),
            "ft_balance_of" => json!(
                self.balances
                    .get(arg_str(a, "account_id")?)
                    .copied()
                    .unwrap_or(0)
                    .to_string()
            ),
            "config" => json!({
                "network_id": self.network_id, "contract_id": domain.contract_id.as_str(),
                "guardians": self.guardians.iter().map(hex::encode).collect::<Vec<_>>(),
                "threshold": self.threshold, "challenge_window_sec": self.challenge_window_sec,
                "mint_cap": self.mint_cap.to_string(), "cap_window_sec": self.cap_window_sec,
                "admin_nonce": self.admin_nonce, "paused": self.paused,
                "proposal_count": self.proposal_count, "burn_count": self.burns.len(),
                "total_supply": self.total_supply.to_string()}),
            other => return Err(format!("MethodNotFound: {other}")),
        })
    }
}

/// The deposit `burn` needs from `from`.
pub fn burn_storage_cost(from: &str) -> u128 {
    STORAGE_BYTE_COST * (BURN_RECORD_FIXED_BYTES + from.len() as u128)
}

fn burn_view(r: &BurnRecord) -> Value {
    json!({"nonce": r.nonce, "from": r.from.as_str(), "amount": r.amount.to_string(),
           "ycash_recipient": hex::encode(r.ycash_recipient), "block_height": r.block_height,
           "timestamp_ns": r.timestamp_ns.to_string(), "record_hash": hex::encode(r.hash())})
}

// ------------------------------------------------------------------------------------- chain

/// One block.
#[derive(Debug, Clone)]
pub struct Block {
    /// Height.
    pub height: u64,
    /// Hash.
    pub hash: [u8; 32],
    /// Parent hash.
    pub prev_hash: [u8; 32],
    /// Unix ns.
    pub timestamp_ns: u64,
    /// The receipts that changed the contract's state in it.
    pub changed_by: Vec<[u8; 32]>,
    /// The contract after the block.
    pub contract: Contract,
}

/// A receipt the mock executed.
#[derive(Debug, Clone)]
pub struct Receipt {
    /// Id.
    pub id: [u8; 32],
    /// Sender.
    pub predecessor_id: String,
    /// Receiver.
    pub receiver_id: String,
    /// `(method, args, deposit)` of each function call.
    pub calls: Vec<(String, Vec<u8>, u128)>,
}

/// A transaction the mock received (for assertions).
#[derive(Debug, Clone)]
pub struct Sent {
    /// The signer.
    pub signer: String,
    /// The methods called.
    pub methods: Vec<String>,
    /// The panic message, if it failed.
    pub error: Option<String>,
    /// The block it executed in.
    pub height: u64,
}

/// The mock node's state.
#[derive(Debug)]
pub struct MockState {
    /// The contract's deployment.
    pub domain: Domain,
    /// Blocks by height (heights may be skipped).
    pub blocks: Vec<Block>,
    /// The live contract (the last block's, plus nothing pending).
    pub contract: Contract,
    /// Access keys: (account, public key) → nonce.
    pub access_keys: HashMap<(String, [u8; 32]), u64>,
    /// Receipts by id.
    pub receipts: HashMap<[u8; 32], Receipt>,
    /// Transactions received.
    pub sent: Vec<Sent>,
    /// RPC methods called (`query:call_function:get_proposal`, `send_tx`, …).
    pub calls: Vec<String>,
    /// Seconds between consecutive blocks.
    pub block_time: u64,
    /// Answers `send_tx` with this JSON-RPC error (once each), before executing anything.
    pub send_errors: Vec<Value>,
    /// Blocks below this height are "garbage-collected": unknown, and `status` reports it as the
    /// earliest kept height.
    pub pruned_below: u64,
    next_height: u64,
    next_ts: u64,
}

impl MockState {
    /// A chain at height 1 with `contract` deployed at `domain`.
    pub fn new(domain: Domain, contract: Contract) -> Self {
        let mut s = Self {
            domain,
            blocks: vec![],
            contract,
            access_keys: HashMap::new(),
            receipts: HashMap::new(),
            sent: vec![],
            calls: vec![],
            block_time: 1,
            send_errors: vec![],
            pruned_below: 0,
            next_height: 1,
            next_ts: GENESIS_NS,
        };
        s.produce(vec![]);
        s
    }

    /// Register an ed25519 access key of `account` (nonce 0).
    pub fn add_access_key(&mut self, account: &str, public_key: [u8; 32]) {
        self.access_keys.insert((account.to_owned(), public_key), 0);
    }

    fn produce(&mut self, changed_by: Vec<[u8; 32]>) -> &Block {
        let height = self.next_height;
        let prev_hash = self.blocks.last().map_or([0; 32], |b| b.hash);
        let hash = sha(&[b"mock-near-block", &height.to_le_bytes(), &prev_hash]);
        let b = Block {
            height,
            hash,
            prev_hash,
            timestamp_ns: self.next_ts,
            changed_by,
            contract: self.contract.clone(),
        };
        self.blocks.push(b);
        self.next_height += 1;
        self.next_ts += self.block_time * NS;
        self.blocks.last().expect("just pushed")
    }

    /// Produce `n` empty blocks.
    pub fn produce_blocks(&mut self, n: u64) {
        for _ in 0..n {
            self.produce(vec![]);
        }
    }

    /// Skip `n` heights (NEAR may produce no block at a height).
    pub fn skip_heights(&mut self, n: u64) {
        self.next_height += n;
    }

    /// Advance the clock by `secs` and produce a block.
    pub fn warp(&mut self, secs: u64) {
        self.next_ts += secs * NS;
        self.produce(vec![]);
    }

    /// The final (= latest) block.
    pub fn head(&self) -> &Block {
        self.blocks.last().expect("genesis")
    }

    /// The timestamp the next block will carry, ns.
    pub fn next_timestamp_ns(&self) -> u64 {
        self.next_ts
    }

    /// RPC calls whose label starts with `prefix`.
    pub fn calls_to(&self, prefix: &str) -> usize {
        self.calls.iter().filter(|c| c.starts_with(prefix)).count()
    }

    fn block_by(&self, p: &Value) -> Result<&Block, Value> {
        let unknown = |what: String| {
            json!({"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_BLOCK", "info": {}},
                   "code": -32000, "message": "Server error",
                   "data": format!("DB Not Found Error: {what}")})
        };
        match p.get("block_id") {
            None => Ok(self.head()),
            Some(Value::Number(n)) => {
                let h = n.as_u64().unwrap_or(u64::MAX);
                self.blocks
                    .iter()
                    .find(|b| b.height == h && h >= self.pruned_below)
                    .ok_or_else(|| unknown(format!("BLOCK HEIGHT: {h}")))
            }
            Some(Value::String(s)) => {
                let h = hash_from_b58(s).map_err(|_| unknown(s.clone()))?;
                self.blocks
                    .iter()
                    .find(|b| b.hash == h)
                    .ok_or_else(|| unknown(format!("BLOCK: {s}")))
            }
            Some(_) => Err(unknown("bad block_id".into())),
        }
    }

    /// Execute one signed transaction in a new block; the `send_tx` result or a JSON-RPC
    /// error.
    pub fn execute(&mut self, signed: &SignedTransaction) -> Result<Value, Value> {
        let invalid = |what: Value| {
            json!({"name": "HANDLER_ERROR", "cause": {"name": "INVALID_TRANSACTION", "info": {}},
                   "code": -32000, "message": "Server error",
                   "data": {"TxExecutionError": {"InvalidTxError": what}}})
        };
        if !signed.verify() {
            return Err(invalid(json!("InvalidSignature")));
        }
        let t = &signed.transaction;
        let key = (t.signer_id.to_string(), t.public_key);
        let Some(ak) = self.access_keys.get(&key).copied() else {
            return Err(invalid(
                json!({"InvalidAccessKeyError": "AccessKeyNotFound"}),
            ));
        };
        if t.nonce <= ak {
            return Err(invalid(
                json!({"InvalidNonce": {"tx_nonce": t.nonce, "ak_nonce": ak}}),
            ));
        }
        if !self.blocks.iter().any(|b| b.hash == t.block_hash) {
            return Err(invalid(json!("Expired")));
        }
        self.access_keys.insert(key, t.nonce);
        let tx_hash = signed.hash();
        let receipt_id = sha(&[b"mock-near-receipt", &tx_hash]);
        let height = self.next_height;
        let ts = self.next_ts;
        let mut calls = vec![];
        let mut result: Result<Value, String> = Ok(Value::Null);
        let before = self.contract.clone();
        for a in &t.actions {
            let Action::FunctionCall(f) = a else { continue };
            calls.push((f.method_name.clone(), f.args.clone(), f.deposit));
            if t.receiver_id != self.domain.contract_id {
                result = Err(format!("account {} has no contract", t.receiver_id));
                break;
            }
            let args: Value = match serde_json::from_slice(&f.args) {
                Ok(v) => v,
                Err(e) => {
                    result = Err(format!("Failed to deserialize input from JSON.: {e}"));
                    break;
                }
            };
            let env = Env {
                domain: &self.domain,
                predecessor: t.signer_id.as_str(),
                deposit: f.deposit,
                height,
                timestamp_ns: ts,
            };
            result = self.contract.call(env, &f.method_name, &args);
            if result.is_err() {
                break;
            }
        }
        if result.is_err() {
            self.contract = before;
        }
        self.receipts.insert(
            receipt_id,
            Receipt {
                id: receipt_id,
                predecessor_id: t.signer_id.to_string(),
                receiver_id: t.receiver_id.to_string(),
                calls: calls.clone(),
            },
        );
        self.sent.push(Sent {
            signer: t.signer_id.to_string(),
            methods: calls.iter().map(|c| c.0.clone()).collect(),
            error: result.as_ref().err().cloned(),
            height,
        });
        let changed = if result.is_ok() {
            vec![receipt_id]
        } else {
            vec![]
        };
        let block_hash = self.produce(changed).hash;
        let status = match &result {
            Ok(v) => {
                let bytes = if v.is_null() {
                    vec![]
                } else {
                    serde_json::to_vec(v).expect("JSON")
                };
                json!({"SuccessValue": B64.encode(bytes)})
            }
            Err(p) => json!({"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError":
                {"ExecutionError": format!("Smart contract panicked: {p}")}}}}}),
        };
        Ok(json!({
            "final_execution_status": "FINAL",
            "status": status,
            "transaction": {"hash": b58(&tx_hash), "signer_id": t.signer_id.as_str(),
                            "receiver_id": t.receiver_id.as_str(), "nonce": t.nonce},
            "transaction_outcome": {"id": b58(&tx_hash), "block_hash": b58(&block_hash),
                                    "outcome": {"logs": [], "status": {"SuccessReceiptId": b58(&receipt_id)}}},
            "receipts_outcome": [{"id": b58(&receipt_id), "block_hash": b58(&block_hash),
                                  "outcome": {"logs": [], "status": status}}],
        }))
    }

    fn rpc(&mut self, method: &str, p: &Value) -> Result<Value, Value> {
        match method {
            "block" => {
                self.calls.push("block".into());
                let b = self.block_by(p)?;
                Ok(json!({"header": {"height": b.height, "hash": b58(&b.hash),
                    "prev_hash": b58(&b.prev_hash), "timestamp": b.timestamp_ns,
                    "timestamp_nanosec": b.timestamp_ns.to_string()}, "chunks": []}))
            }
            "query" => match p.get("request_type").and_then(Value::as_str) {
                Some("call_function") => {
                    let m = p.get("method_name").and_then(Value::as_str).unwrap_or("");
                    self.calls.push(format!("query:call_function:{m}"));
                    let b = self.block_by(p)?;
                    if p.get("account_id").and_then(Value::as_str)
                        != Some(self.domain.contract_id.as_str())
                    {
                        return Err(
                            json!({"name": "HANDLER_ERROR", "cause": {"name": "NO_CONTRACT_CODE", "info": {}},
                                          "code": -32000, "message": "Server error"}),
                        );
                    }
                    let args: Value = p
                        .get("args_base64")
                        .and_then(Value::as_str)
                        .and_then(|s| B64.decode(s).ok())
                        .and_then(|b| serde_json::from_slice(&b).ok())
                        .unwrap_or(Value::Null);
                    match b.contract.view(&self.domain, m, &args, b.timestamp_ns) {
                        Ok(v) => Ok(json!({"result": serde_json::to_vec(&v).expect("JSON"),
                            "logs": [], "block_height": b.height, "block_hash": b58(&b.hash)})),
                        Err(e) => Err(json!({"name": "HANDLER_ERROR",
                            "cause": {"name": "CONTRACT_EXECUTION_ERROR", "info": {"vm_error":
                                format!("wasm execution failed with error: FunctionCallError(ExecutionError(\"Smart contract panicked: {e}\"))"),
                                "block_height": b.height, "block_hash": b58(&b.hash)}},
                            "code": -32000, "message": "Server error"})),
                    }
                }
                Some("view_access_key") => {
                    self.calls.push("query:view_access_key".into());
                    let acct = p.get("account_id").and_then(Value::as_str).unwrap_or("");
                    let pk = p
                        .get("public_key")
                        .and_then(Value::as_str)
                        .and_then(|s| crate::keys::decode_key_text(s).ok())
                        .and_then(|v| <[u8; 32]>::try_from(v).ok());
                    let head = self.head();
                    match pk.and_then(|pk| self.access_keys.get(&(acct.to_owned(), pk))) {
                        Some(n) => Ok(json!({"nonce": n, "permission": "FullAccess",
                            "block_height": head.height, "block_hash": b58(&head.hash)})),
                        None => Err(json!({"name": "HANDLER_ERROR",
                            "cause": {"name": "UNKNOWN_ACCESS_KEY", "info": {}},
                            "code": -32000, "message": "Server error"})),
                    }
                }
                other => Err(json!({"name": "REQUEST_VALIDATION_ERROR",
                    "cause": {"name": "PARSE_ERROR", "info": {}},
                    "message": format!("request_type {other:?} not mocked")})),
            },
            "status" => {
                self.calls.push("status".into());
                let earliest = self
                    .blocks
                    .iter()
                    .map(|b| b.height)
                    .find(|h| *h >= self.pruned_below)
                    .unwrap_or(0);
                let head = self.head();
                Ok(json!({"chain_id": self.domain.network_id, "sync_info": {
                    "latest_block_height": head.height, "latest_block_hash": b58(&head.hash),
                    "earliest_block_height": earliest, "syncing": false}}))
            }
            "EXPERIMENTAL_changes" => {
                self.calls.push("EXPERIMENTAL_changes".into());
                let b = self.block_by(p)?;
                let wants = p
                    .get("account_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|a| {
                        a.iter()
                            .any(|x| x.as_str() == Some(self.domain.contract_id.as_str()))
                    });
                let changes: Vec<Value> = if wants {
                    b.changed_by
                        .iter()
                        .map(|r| {
                            json!({"cause": {"type": "receipt_processing", "receipt_hash": b58(r)},
                                   "type": "data_update",
                                   "change": {"account_id": self.domain.contract_id.as_str(),
                                              "key_base64": B64.encode(b"STATE"),
                                              "value_base64": ""}})
                        })
                        .collect()
                } else {
                    vec![]
                };
                Ok(json!({"block_hash": b58(&b.hash), "changes": changes}))
            }
            "EXPERIMENTAL_receipt" => {
                self.calls.push("EXPERIMENTAL_receipt".into());
                let r = p
                    .get("receipt_id")
                    .and_then(Value::as_str)
                    .and_then(|s| hash_from_b58(s).ok())
                    .and_then(|id| self.receipts.get(&id))
                    .ok_or_else(|| {
                        json!({"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_RECEIPT", "info": {}},
                               "code": -32000, "message": "Server error"})
                    })?;
                let actions: Vec<Value> = r
                    .calls
                    .iter()
                    .map(|(m, a, d)| {
                        json!({"FunctionCall": {"method_name": m, "args": B64.encode(a),
                                                "gas": 100_000_000_000_000u64, "deposit": d.to_string()}})
                    })
                    .collect();
                Ok(
                    json!({"predecessor_id": r.predecessor_id, "receiver_id": r.receiver_id,
                    "receipt_id": b58(&r.id),
                    "receipt": {"Action": {"signer_id": r.predecessor_id, "actions": actions}}}),
                )
            }
            "send_tx" | "broadcast_tx_commit" => {
                self.calls.push("send_tx".into());
                if !self.send_errors.is_empty() {
                    return Err(self.send_errors.remove(0));
                }
                let raw = p
                    .get("signed_tx_base64")
                    .or_else(|| p.get(0))
                    .and_then(Value::as_str)
                    .and_then(|s| B64.decode(s).ok())
                    .ok_or_else(|| {
                        json!({"name": "REQUEST_VALIDATION_ERROR",
                        "cause": {"name": "PARSE_ERROR", "info": {}}, "message": "bad base64"})
                    })?;
                let signed = SignedTransaction::decode(&raw).map_err(|e| {
                    json!({"name": "REQUEST_VALIDATION_ERROR",
                           "cause": {"name": "PARSE_ERROR", "info": {}}, "message": e.to_string()})
                })?;
                self.execute(&signed)
            }
            other => Err(json!({"name": "REQUEST_VALIDATION_ERROR",
                "cause": {"name": "METHOD_NOT_FOUND", "info": {}},
                "message": format!("method {other} not mocked")})),
        }
    }
}

type Shared = Arc<Mutex<MockState>>;

async fn handle(State(st): State<Shared>, body: String) -> Response {
    let req: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let res = st
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .rpc(method, &params);
    let body = match res {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
    };
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// A running mock node.
pub struct MockNear {
    addr: SocketAddr,
    state: Shared,
    _stop: oneshot::Sender<()>,
}

impl MockNear {
    /// Serve `state` on a free localhost port.
    pub async fn start(state: MockState) -> std::io::Result<Self> {
        let state = Arc::new(Mutex::new(state));
        let app = Router::new()
            .route("/", post(handle))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(Self {
            addr,
            state,
            _stop: tx,
        })
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The state (lock held while the guard lives).
    pub fn state(&self) -> MutexGuard<'_, MockState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}
