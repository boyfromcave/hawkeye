//! The `wyec-near` contract (`near/src/lib.rs`, NEAR plan §3) as Hawkeye drives it: typed view
//! calls at `finality: final` (or at a given block, for the scanner), and the relayer's
//! function-call transactions.
//!
//! The JSON shapes are the contract's: byte strings are hex without `0x` (`lock_id` and
//! `ycash_recipient` 32 bytes, guardian keys 64, signatures 65), amounts are NEP-141 `U128`
//! decimal strings, proposal ids and heights JSON numbers, `timestamp_ns` a `U64` string.
//!
//! **Sending.** Every call is a `TransactionV0` with one `FunctionCall` from the relayer account
//! ([`KeyFile`]), signed with its ed25519 key, sent with `send_tx` and returned once `FINAL` (so
//! the next view at `final` sees it). Calls are serialised: the nonce is the access key's nonce
//! at the final block, never below the last nonce this client used, plus one; a refused nonce
//! (`InvalidNonce`) is re-read and retried once. The envelope is rebuilt on every retry; what it
//! carries — the guardians' attestation signatures — comes from the caller (the engine's
//! sign-once records), never signed here.

use hawkeye_core::AccountId;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::near::{BridgeMessage, BurnRecord, Domain, GuardianKey, recover_guardian};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::admin::send_actions;
use crate::error::{Error, Result};
use crate::keys::KeyFile;
use crate::rpc::{BlockRef, NearRpc, ReceiptView};
use crate::tx::{Action, FunctionCall};

/// The default gas per call: 100 TGas (a mint with registration or a threshold mint of a few
/// signatures uses ~10–30 TGas, NEAR plan NQ-3).
pub const DEFAULT_GAS: u64 = 100 * crate::tx::TGAS;
/// The contract's `get_burns` page size (`MAX_BURNS_PER_PAGE`).
pub const BURNS_PAGE: u64 = 100;

/// What executing a lock's proposal would find (the contract's `ProposalStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ProposalStatus {
    /// No proposal.
    None,
    /// Inside the challenge window.
    Pending,
    /// Executable.
    Ready,
    /// The proposer left the guardian set.
    Void,
}

/// An optimistic proposal (`get_proposal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The proposal id (non-zero, increasing).
    pub id: u64,
    /// The proposing guardian's key.
    pub proposer: GuardianKey,
    /// The receiver.
    pub receiver_id: AccountId,
    /// zatoshi.
    pub amount: u128,
    /// Unix seconds from which it executes.
    pub eta: u64,
    /// Its status when read.
    pub status: ProposalStatus,
}

/// The contract's `config()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The network id bound into every digest.
    pub network_id: String,
    /// The contract's own account.
    pub contract_id: String,
    /// Guardian keys, in set order.
    pub guardians: Vec<GuardianKey>,
    /// Signatures for `mint` and admin acts.
    pub threshold: u8,
    /// Seconds between proposal and execution.
    pub challenge_window_sec: u64,
    /// zatoshi per window (0: no limit).
    pub mint_cap: u128,
    /// The rate-limit window.
    pub cap_window_sec: u64,
    /// The admin nonce.
    pub admin_nonce: u64,
    /// Paused.
    pub paused: bool,
    /// Proposals ever opened.
    pub proposal_count: u64,
    /// Burns ever recorded.
    pub burn_count: u64,
    /// The token's supply.
    pub total_supply: u128,
}

/// A transaction the relayer sent, final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOutcome {
    /// The transaction hash.
    pub tx: [u8; 32],
    /// The height of the block where the call executed.
    pub height: u64,
    /// The call's return value (JSON bytes).
    pub value: Vec<u8>,
    /// Gas burnt by the transaction and all its receipts.
    pub gas_burnt: u64,
}

/// A bridge event found by [`WyecNear::scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NearEvent {
    /// A burn record.
    Burn(BurnRecord),
    /// A mint (threshold `mint`, or `execute_mint` of a proposal).
    Minted {
        /// The lock.
        lock_id: Hash32,
        /// The receiver.
        receiver_id: AccountId,
        /// zatoshi.
        amount: u128,
    },
    /// A proposal opened.
    Proposed {
        /// The lock.
        lock_id: Hash32,
        /// The proposal id.
        proposal_id: u64,
        /// The guardian whose signature opened it.
        proposer: GuardianKey,
        /// The receiver.
        receiver_id: AccountId,
        /// zatoshi.
        amount: u128,
        /// Unix seconds from which it executes.
        eta: u64,
    },
    /// A proposal challenged (deleted, its proposer vetoed for the lock).
    Challenged {
        /// The lock.
        lock_id: Hash32,
        /// The proposal.
        proposal_id: u64,
        /// The guardian whose signature challenged it.
        challenger: GuardianKey,
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
        /// zatoshi per window.
        mint_cap: u128,
        /// Seconds.
        cap_window: u64,
    },
    /// Paused or unpaused.
    Paused {
        /// Paused now.
        paused: bool,
        /// Who submitted the act.
        by: String,
    },
}

/// An event and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearScanned {
    /// The block height the event took effect in (a burn: its record's `block_height`).
    pub height: u64,
    /// That block's hash.
    pub block_hash: [u8; 32],
    /// The receipt that made it — for a burn, `SHA256(borsh(BurnRecord))`, the `HKN1` memo's
    /// `data` (NEAR plan §2.4), which is what the ledger and the matcher key a burn by.
    pub id: [u8; 32],
    /// Position within the block (0, 1, …).
    pub index: u64,
    /// The event.
    pub event: NearEvent,
}

/// The events of a block range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutput {
    /// Events in chain order.
    pub events: Vec<NearScanned>,
    /// The hash of the range's last block (all zero if NEAR skipped that height).
    pub to_hash: [u8; 32],
}

// ------------------------------------------------------------------------------------- JSON

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Decode(format!("{what} {s:?} is not 32 bytes of hex")))
}

fn hex64(s: &str, what: &str) -> Result<[u8; 64]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Decode(format!("{what} {s:?} is not 64 bytes of hex")))
}

fn hex65(s: &str, what: &str) -> Result<[u8; 65]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Decode(format!("{what} {s:?} is not 65 bytes of hex")))
}

fn u128_of(v: &Value, what: &str) -> Result<u128> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
    .ok_or_else(|| Error::Decode(format!("{what} is not a U128: {v}")))
}

fn u64_of(v: &Value, what: &str) -> Result<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
    .ok_or_else(|| Error::Decode(format!("{what} is not a u64: {v}")))
}

fn get<'a>(v: &'a Value, k: &str) -> Result<&'a Value> {
    v.get(k)
        .ok_or_else(|| Error::Decode(format!("missing {k} in {v:.200}")))
}

fn str_of<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    get(v, k)?
        .as_str()
        .ok_or_else(|| Error::Decode(format!("{k} is not a string")))
}

fn account(s: &str) -> Result<AccountId> {
    AccountId::parse(s).map_err(|e| Error::Decode(format!("account {s:?}: {e}")))
}

fn parse_proposal(v: &Value) -> Result<Proposal> {
    Ok(Proposal {
        id: u64_of(get(v, "proposal_id")?, "proposal_id")?,
        proposer: hex64(str_of(v, "proposer")?, "proposer")?,
        receiver_id: account(str_of(v, "receiver_id")?)?,
        amount: u128_of(get(v, "amount")?, "amount")?,
        eta: u64_of(get(v, "eta_sec")?, "eta_sec")?,
        status: serde_json::from_value(get(v, "status")?.clone())
            .map_err(|e| Error::Decode(format!("status: {e}")))?,
    })
}

/// A `get_burns` row, checked: its `record_hash` must be the SHA-256 of the record's Borsh.
pub fn parse_burn(v: &Value) -> Result<BurnRecord> {
    let r = BurnRecord {
        nonce: u64_of(get(v, "nonce")?, "nonce")?,
        from: account(str_of(v, "from")?)?,
        amount: u128_of(get(v, "amount")?, "amount")?,
        ycash_recipient: hex32(str_of(v, "ycash_recipient")?, "ycash_recipient")?,
        block_height: u64_of(get(v, "block_height")?, "block_height")?,
        timestamp_ns: u64_of(get(v, "timestamp_ns")?, "timestamp_ns")?,
    };
    let want = hex32(str_of(v, "record_hash")?, "record_hash")?;
    if r.hash() != want {
        return Err(Error::Decode(format!(
            "burn {}: record_hash {} is not SHA256(borsh(record)) {}",
            r.nonce,
            hex::encode(want),
            hex::encode(r.hash())
        )));
    }
    Ok(r)
}

fn parse_config(v: &Value) -> Result<Config> {
    let guardians = get(v, "guardians")?
        .as_array()
        .ok_or_else(|| Error::Decode("guardians is not an array".into()))?
        .iter()
        .map(|g| hex64(g.as_str().unwrap_or(""), "guardian"))
        .collect::<Result<_>>()?;
    Ok(Config {
        network_id: str_of(v, "network_id")?.to_owned(),
        contract_id: str_of(v, "contract_id")?.to_owned(),
        guardians,
        threshold: u8::try_from(u64_of(get(v, "threshold")?, "threshold")?)
            .map_err(|_| Error::Decode("threshold above 255".into()))?,
        challenge_window_sec: u64_of(get(v, "challenge_window_sec")?, "challenge_window_sec")?,
        mint_cap: u128_of(get(v, "mint_cap")?, "mint_cap")?,
        cap_window_sec: u64_of(get(v, "cap_window_sec")?, "cap_window_sec")?,
        admin_nonce: u64_of(get(v, "admin_nonce")?, "admin_nonce")?,
        paused: get(v, "paused")?.as_bool().unwrap_or(false),
        proposal_count: u64_of(get(v, "proposal_count")?, "proposal_count")?,
        burn_count: u64_of(get(v, "burn_count")?, "burn_count")?,
        total_supply: u128_of(get(v, "total_supply")?, "total_supply")?,
    })
}

/// Order threshold signatures as `wyec-near` requires: by the recovered 64-byte key, strictly
/// ascending (NEAR plan N-12). A signature that does not recover is refused; a repeated signer
/// is dropped.
pub fn sort_signatures(digest: &Hash32, sigs: &[[u8; 65]]) -> Result<Vec<[u8; 65]>> {
    let mut keyed = Vec::with_capacity(sigs.len());
    for (i, s) in sigs.iter().enumerate() {
        let k = recover_guardian(digest, s)
            .map_err(|e| Error::Decode(format!("signature #{i}: {e}")))?;
        keyed.push((k, *s));
    }
    keyed.sort_by_key(|k| k.0);
    keyed.dedup_by(|a, b| a.0 == b.0);
    Ok(keyed.into_iter().map(|(_, s)| s).collect())
}

// ------------------------------------------------------------------------------------- client

struct Relayer {
    key: KeyFile,
    /// The last nonce this client used (sends hold the lock: one at a time).
    nonce: Mutex<Option<u64>>,
}

/// One `wyec-near` deployment over a NEAR RPC, with an optional relayer key for calls.
pub struct WyecNear {
    rpc: NearRpc,
    domain: Domain,
    relayer: Option<Relayer>,
    gas: u64,
}

impl std::fmt::Debug for WyecNear {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WyecNear")
            .field("rpc", &self.rpc.url())
            .field("domain", &self.domain)
            .field("relayer", &self.relayer.as_ref().map(|r| &r.key.account_id))
            .field("gas", &self.gas)
            .finish()
    }
}

impl WyecNear {
    /// The contract `domain.contract_id` on network `domain.network_id` at `rpc_url`; calls are
    /// sent by `relayer` (none: read-only) with `gas` each.
    pub fn new(rpc_url: &str, domain: Domain, relayer: Option<KeyFile>, gas: u64) -> Result<Self> {
        Ok(Self {
            rpc: NearRpc::new(rpc_url)?,
            domain,
            relayer: relayer.map(|key| Relayer {
                key,
                nonce: Mutex::new(None),
            }),
            gas,
        })
    }

    /// The deployment (digest domain).
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// The RPC client.
    pub fn rpc(&self) -> &NearRpc {
        &self.rpc
    }

    /// The relayer account, if calls can be sent.
    pub fn relayer_account(&self) -> Option<&AccountId> {
        self.relayer.as_ref().map(|r| &r.key.account_id)
    }

    fn contract(&self) -> &str {
        self.domain.contract_id.as_str()
    }

    /// A view call at `at`.
    pub async fn view_at(&self, at: BlockRef, method: &str, args: Value) -> Result<Value> {
        self.rpc.view(at, self.contract(), method, &args).await
    }

    /// A view call at the final block.
    pub async fn view(&self, method: &str, args: Value) -> Result<Value> {
        self.view_at(BlockRef::Final, method, args).await
    }

    /// `config()` at `at`.
    pub async fn config_at(&self, at: BlockRef) -> Result<Config> {
        parse_config(&self.view_at(at, "config", json!({})).await?)
    }

    /// `config()`.
    pub async fn config(&self) -> Result<Config> {
        self.config_at(BlockRef::Final).await
    }

    /// `get_guardians()`.
    pub async fn guardians(&self) -> Result<Vec<GuardianKey>> {
        self.view("get_guardians", json!({}))
            .await?
            .as_array()
            .ok_or_else(|| Error::Decode("get_guardians is not an array".into()))?
            .iter()
            .map(|g| hex64(g.as_str().unwrap_or(""), "guardian"))
            .collect()
    }

    /// `get_threshold()`.
    pub async fn threshold(&self) -> Result<u8> {
        let v = self.view("get_threshold", json!({})).await?;
        u8::try_from(u64_of(&v, "threshold")?).map_err(|_| Error::Decode("threshold".into()))
    }

    /// `is_consumed(lock_id)`.
    pub async fn is_consumed(&self, lock_id: &Hash32) -> Result<bool> {
        let v = self
            .view("is_consumed", json!({"lock_id": hex::encode(lock_id)}))
            .await?;
        v.as_bool()
            .ok_or_else(|| Error::Decode("is_consumed is not a bool".into()))
    }

    /// `get_proposal(lock_id)` at `at`.
    pub async fn proposal_at(&self, at: BlockRef, lock_id: &Hash32) -> Result<Option<Proposal>> {
        let v = self
            .view_at(at, "get_proposal", json!({"lock_id": hex::encode(lock_id)}))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        parse_proposal(&v).map(Some)
    }

    /// `get_proposal(lock_id)`.
    pub async fn proposal(&self, lock_id: &Hash32) -> Result<Option<Proposal>> {
        self.proposal_at(BlockRef::Final, lock_id).await
    }

    /// `proposal_status(lock_id)`.
    pub async fn proposal_status(&self, lock_id: &Hash32) -> Result<ProposalStatus> {
        let v = self
            .view("proposal_status", json!({"lock_id": hex::encode(lock_id)}))
            .await?;
        serde_json::from_value(v).map_err(|e| Error::Decode(format!("proposal_status: {e}")))
    }

    /// `is_vetoed(lock_id, guardian)`.
    pub async fn is_vetoed(&self, lock_id: &Hash32, guardian: &GuardianKey) -> Result<bool> {
        let v = self
            .view(
                "is_vetoed",
                json!({"lock_id": hex::encode(lock_id), "guardian": hex::encode(guardian)}),
            )
            .await?;
        v.as_bool()
            .ok_or_else(|| Error::Decode("is_vetoed is not a bool".into()))
    }

    /// `get_burn_count()` at `at`.
    pub async fn burn_count_at(&self, at: BlockRef) -> Result<u64> {
        u64_of(
            &self.view_at(at, "get_burn_count", json!({})).await?,
            "burn_count",
        )
    }

    /// Burn records `[from, to)` at `at`, paged by [`BURNS_PAGE`], each checked.
    pub async fn burns_at(&self, at: BlockRef, from: u64, to: u64) -> Result<Vec<BurnRecord>> {
        let mut out = vec![];
        let mut next = from;
        while next < to {
            let page = self
                .view_at(
                    at,
                    "get_burns",
                    json!({"from_nonce": next, "limit": (to - next).min(BURNS_PAGE)}),
                )
                .await?;
            let rows = page
                .as_array()
                .ok_or_else(|| Error::Decode("get_burns is not an array".into()))?;
            if rows.is_empty() {
                return Err(Error::Decode(format!(
                    "get_burns({next}) is empty below the count {to}"
                )));
            }
            for r in rows {
                let b = parse_burn(r)?;
                if b.nonce != next {
                    return Err(Error::Decode(format!(
                        "get_burns: nonce {} where {next} was expected",
                        b.nonce
                    )));
                }
                next += 1;
                out.push(b);
                if next == to {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// `burn_storage_deposit(account_id)`, yoctoNEAR.
    pub async fn burn_storage_deposit(&self, account_id: &AccountId) -> Result<u128> {
        u128_of(
            &self
                .view(
                    "burn_storage_deposit",
                    json!({"account_id": account_id.as_str()}),
                )
                .await?,
            "burn_storage_deposit",
        )
    }

    /// `mint_available()`.
    pub async fn mint_available(&self) -> Result<u128> {
        u128_of(
            &self.view("mint_available", json!({})).await?,
            "mint_available",
        )
    }

    /// `ft_total_supply()`.
    pub async fn total_supply(&self) -> Result<u128> {
        u128_of(
            &self.view("ft_total_supply", json!({})).await?,
            "ft_total_supply",
        )
    }

    /// `ft_balance_of(account_id)`.
    pub async fn balance_of(&self, account_id: &AccountId) -> Result<u128> {
        u128_of(
            &self
                .view("ft_balance_of", json!({"account_id": account_id.as_str()}))
                .await?,
            "ft_balance_of",
        )
    }

    /// `is_paused()`.
    pub async fn is_paused(&self) -> Result<bool> {
        self.view("is_paused", json!({}))
            .await?
            .as_bool()
            .ok_or_else(|| Error::Decode("is_paused is not a bool".into()))
    }

    /// The final block: (height, unix seconds).
    pub async fn final_head(&self) -> Result<(u64, u64)> {
        let b = self.rpc.block(BlockRef::Final).await?;
        Ok((b.height, b.timestamp_ns / 1_000_000_000))
    }

    // --------------------------------------------------------------------------------- calls

    /// Send `method(args)` with `deposit` yoctoNEAR from the relayer and wait until final.
    pub async fn call(&self, method: &str, args: Value, deposit: u128) -> Result<CallOutcome> {
        let r = self
            .relayer
            .as_ref()
            .ok_or_else(|| Error::Key("no relayer key: this client is read-only".into()))?;
        let mut last = r.nonce.lock().await;
        let o = send_actions(
            &self.rpc,
            &r.key,
            &mut last,
            &self.domain.contract_id,
            vec![Action::FunctionCall(FunctionCall {
                method_name: method.to_owned(),
                args: serde_json::to_vec(&args).expect("JSON"),
                gas: self.gas,
                deposit,
            })],
        )
        .await?;
        drop(last);
        let height = self
            .rpc
            .block(BlockRef::Hash(o.receipt_block))
            .await?
            .height;
        Ok(CallOutcome {
            tx: o.tx_hash,
            height,
            value: o.value,
            gas_burnt: o.gas_burnt,
        })
    }

    /// `mint(lock_id, amount, receiver_id, sigs)`: `sigs` as given (see [`sort_signatures`]).
    pub async fn mint(
        &self,
        lock_id: &Hash32,
        amount: u128,
        receiver_id: &AccountId,
        sigs: &[[u8; 65]],
    ) -> Result<CallOutcome> {
        self.call(
            "mint",
            json!({"lock_id": hex::encode(lock_id), "amount": amount.to_string(),
                   "receiver_id": receiver_id.as_str(),
                   "sigs": sigs.iter().map(hex::encode).collect::<Vec<_>>()}),
            0,
        )
        .await
    }

    /// `propose_mint(lock_id, amount, receiver_id, sig)` → the outcome and the proposal id.
    pub async fn propose_mint(
        &self,
        lock_id: &Hash32,
        amount: u128,
        receiver_id: &AccountId,
        sig: &[u8; 65],
    ) -> Result<(CallOutcome, u64)> {
        let o = self
            .call(
                "propose_mint",
                json!({"lock_id": hex::encode(lock_id), "amount": amount.to_string(),
                       "receiver_id": receiver_id.as_str(), "sig": hex::encode(sig)}),
                0,
            )
            .await?;
        let id = returned_u64(&o.value, "propose_mint")?;
        Ok((o, id))
    }

    /// `challenge_mint(lock_id, proposal_id, sig)`.
    pub async fn challenge_mint(
        &self,
        lock_id: &Hash32,
        proposal_id: u64,
        sig: &[u8; 65],
    ) -> Result<CallOutcome> {
        self.call(
            "challenge_mint",
            json!({"lock_id": hex::encode(lock_id), "proposal_id": proposal_id,
                   "sig": hex::encode(sig)}),
            0,
        )
        .await
    }

    /// `execute_mint(lock_id)`.
    pub async fn execute_mint(&self, lock_id: &Hash32) -> Result<CallOutcome> {
        self.call("execute_mint", json!({"lock_id": hex::encode(lock_id)}), 0)
            .await
    }

    /// `burn(amount, ycash_recipient)` from the relayer account, attaching the record's storage
    /// deposit (`burn_storage_deposit`) → the outcome and the burn nonce.
    pub async fn burn(&self, amount: u128, ycash_recipient: &Hash32) -> Result<(CallOutcome, u64)> {
        let who = self
            .relayer_account()
            .ok_or_else(|| Error::Key("no relayer key: this client is read-only".into()))?
            .clone();
        let deposit = self.burn_storage_deposit(&who).await?.max(1);
        let o = self
            .call(
                "burn",
                json!({"amount": amount.to_string(),
                       "ycash_recipient": hex::encode(ycash_recipient)}),
                deposit,
            )
            .await?;
        let nonce = returned_u64(&o.value, "burn")?;
        Ok((o, nonce))
    }

    // ------------------------------------------------------------------------------ scanning

    /// The guardian signatures a `mint` or `propose_mint` receipt (or the function call of a
    /// transaction whose first receipt has this id) carried; empty for any other receipt.
    pub async fn receipt_signatures(&self, receipt: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let r = match self.rpc.receipt(receipt).await {
            Ok(r) => r,
            Err(Error::Rpc { .. }) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut out = vec![];
        for c in &r.calls {
            let Ok(args) = serde_json::from_slice::<Value>(&c.args) else {
                continue;
            };
            match c.method_name.as_str() {
                "mint" => {
                    for s in args
                        .get("sigs")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(b) = s.as_str().and_then(|s| hex::decode(s).ok()) {
                            out.push(b);
                        }
                    }
                }
                "propose_mint" => {
                    if let Some(b) = args
                        .get("sig")
                        .and_then(Value::as_str)
                        .and_then(|s| hex::decode(s).ok())
                    {
                        out.push(b);
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// The bridge's events in blocks `[from, to]` (all final). A height the node has no block for
    /// is a height NEAR skipped, unless it lies below the node's earliest kept block (a pruned,
    /// non-archival node): that is an error, never a silent gap.
    ///
    /// NEAR's RPC has no log filter (N-8), so the scan reads, per height, the contract's state
    /// changes (`EXPERIMENTAL_changes`; a height NEAR skipped has none): every receipt that
    /// changed the contract's state succeeded, whichever account or contract sent it. Each such
    /// receipt's function calls (`EXPERIMENTAL_receipt`) are the events, completed from the
    /// contract's own views at that block: `get_proposal` after a `propose_mint` (id, eta) and
    /// before an `execute_mint` (receiver, amount), `get_burns` between the burn counts before
    /// and after a block with a `burn`. Proposers and challengers are the keys their signatures
    /// recover to under this deployment's digests, as the contract recovered them.
    pub async fn scan(&self, from: u64, to: u64) -> Result<ScanOutput> {
        let mut events = vec![];
        let mut to_hash = [0u8; 32];
        let mut earliest = None;
        for h in from..=to {
            let Some(ch) = self.rpc.data_changes(h, self.contract()).await? else {
                // a height NEAR skipped has no block; one the node pruned must not pass as one
                let e = match earliest {
                    Some(e) => e,
                    None => {
                        let e = self.rpc.earliest_block_height().await?;
                        earliest = Some(e);
                        e
                    }
                };
                if h < e {
                    return Err(Error::Rpc {
                        name: "PRUNED".into(),
                        cause: Some("UNKNOWN_BLOCK".into()),
                        message: format!(
                            "block {h} is below the node's earliest block {e}: the scan needs an \
                             archival NEAR RPC to catch up from here"
                        ),
                        data: None,
                    });
                }
                continue;
            };
            if h == to {
                to_hash = ch.block_hash;
            }
            let mut receipts: Vec<[u8; 32]> = vec![];
            for c in &ch.changes {
                if let Some(r) = c.receipt
                    && !receipts.contains(&r)
                {
                    receipts.push(r);
                }
            }
            let mut views = vec![];
            for r in &receipts {
                let v = self.rpc.receipt(r).await?;
                if v.receiver_id == self.contract() {
                    views.push(v);
                }
            }
            self.block_events(h, ch.block_hash, &views, &mut events)
                .await?;
        }
        Ok(ScanOutput { events, to_hash })
    }

    async fn block_events(
        &self,
        height: u64,
        block_hash: [u8; 32],
        receipts: &[ReceiptView],
        out: &mut Vec<NearScanned>,
    ) -> Result<()> {
        let at = BlockRef::Hash(block_hash);
        let mut index = 0u64;
        let mut push = |out: &mut Vec<NearScanned>, h: u64, id: [u8; 32], event: NearEvent| {
            out.push(NearScanned {
                height: h,
                block_hash,
                id,
                index,
                event,
            });
            index += 1;
        };
        let mut header = None;
        let mut burns_done = false;
        for r in receipts {
            for c in &r.calls {
                let args: Value = serde_json::from_slice(&c.args).unwrap_or(Value::Null);
                let lock = || -> Result<Hash32> { hex32(str_of(&args, "lock_id")?, "lock_id") };
                match c.method_name.as_str() {
                    "mint" => {
                        let ev = NearEvent::Minted {
                            lock_id: lock()?,
                            receiver_id: account(str_of(&args, "receiver_id")?)?,
                            amount: u128_of(get(&args, "amount")?, "amount")?,
                        };
                        push(out, height, r.id, ev);
                    }
                    "propose_mint" => {
                        let lock_id = lock()?;
                        let receiver_id = account(str_of(&args, "receiver_id")?)?;
                        let amount = u128_of(get(&args, "amount")?, "amount")?;
                        let sig = hex65(str_of(&args, "sig")?, "sig")?;
                        let digest = self.domain.digest(&BridgeMessage::Mint {
                            lock_id,
                            amount,
                            receiver_id: receiver_id.clone(),
                        });
                        let proposer = recover_guardian(&digest, &sig)
                            .map_err(|e| Error::Decode(format!("propose_mint sig: {e}")))?;
                        let (proposal_id, eta) = match self.proposal_at(at, &lock_id).await? {
                            Some(p) if p.proposer == proposer => (p.id, p.eta),
                            _ => {
                                // challenged within its own block: the challenge names its id
                                let id = receipts
                                    .iter()
                                    .flat_map(|r| &r.calls)
                                    .filter(|c| c.method_name == "challenge_mint")
                                    .filter_map(|c| serde_json::from_slice::<Value>(&c.args).ok())
                                    .find(|a| {
                                        a.get("lock_id").and_then(Value::as_str)
                                            == Some(&hex::encode(lock_id))
                                    })
                                    .and_then(|a| a.get("proposal_id").and_then(Value::as_u64));
                                let cfg = self.config_at(at).await?;
                                let hd = match header {
                                    Some(hd) => hd,
                                    None => {
                                        let hd = self.rpc.block(at).await?;
                                        header = Some(hd);
                                        hd
                                    }
                                };
                                (
                                    id.unwrap_or(cfg.proposal_count),
                                    hd.timestamp_ns / 1_000_000_000 + cfg.challenge_window_sec,
                                )
                            }
                        };
                        push(
                            out,
                            height,
                            r.id,
                            NearEvent::Proposed {
                                lock_id,
                                proposal_id,
                                proposer,
                                receiver_id,
                                amount,
                                eta,
                            },
                        );
                    }
                    "challenge_mint" => {
                        let lock_id = lock()?;
                        let proposal_id = u64_of(get(&args, "proposal_id")?, "proposal_id")?;
                        let sig = hex65(str_of(&args, "sig")?, "sig")?;
                        let digest = self.domain.digest(&BridgeMessage::Challenge {
                            lock_id,
                            proposal_id,
                        });
                        let challenger = recover_guardian(&digest, &sig)
                            .map_err(|e| Error::Decode(format!("challenge_mint sig: {e}")))?;
                        push(
                            out,
                            height,
                            r.id,
                            NearEvent::Challenged {
                                lock_id,
                                proposal_id,
                                challenger,
                            },
                        );
                    }
                    "execute_mint" => {
                        let lock_id = lock()?;
                        let hd = match header {
                            Some(hd) => hd,
                            None => {
                                let hd = self.rpc.block(at).await?;
                                header = Some(hd);
                                hd
                            }
                        };
                        let p = self
                            .proposal_at(BlockRef::Hash(hd.prev_hash), &lock_id)
                            .await?
                            .ok_or_else(|| {
                                Error::Decode(format!(
                                    "execute_mint of {} at {height}: no proposal before it",
                                    hex::encode(lock_id)
                                ))
                            })?;
                        push(
                            out,
                            height,
                            r.id,
                            NearEvent::Minted {
                                lock_id,
                                receiver_id: p.receiver_id,
                                amount: p.amount,
                            },
                        );
                    }
                    "burn" if !burns_done => {
                        burns_done = true;
                        let hd = match header {
                            Some(hd) => hd,
                            None => {
                                let hd = self.rpc.block(at).await?;
                                header = Some(hd);
                                hd
                            }
                        };
                        let before = self.burn_count_at(BlockRef::Hash(hd.prev_hash)).await?;
                        let after = self.burn_count_at(at).await?;
                        for b in self.burns_at(at, before, after).await? {
                            let id = b.hash();
                            let h = b.block_height;
                            push(out, h, id, NearEvent::Burn(b));
                        }
                    }
                    "set_guardians" => {
                        let count = get(&args, "guardians")?.as_array().map_or(0, Vec::len);
                        let threshold =
                            u8::try_from(u64_of(get(&args, "threshold")?, "threshold")?)
                                .unwrap_or(u8::MAX);
                        push(
                            out,
                            height,
                            r.id,
                            NearEvent::GuardiansChanged { count, threshold },
                        );
                    }
                    "set_paused" => {
                        let paused = get(&args, "paused")?.as_bool().unwrap_or(false);
                        push(
                            out,
                            height,
                            r.id,
                            NearEvent::Paused {
                                paused,
                                by: r.predecessor_id.clone(),
                            },
                        );
                    }
                    "set_mint_limit" => {
                        let ev = NearEvent::MintLimitChanged {
                            mint_cap: u128_of(get(&args, "mint_cap")?, "mint_cap")?,
                            cap_window: u64_of(get(&args, "cap_window_sec")?, "cap_window_sec")?,
                        };
                        push(out, height, r.id, ev);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

fn returned_u64(value: &[u8], method: &str) -> Result<u64> {
    serde_json::from_slice::<Value>(value)
        .ok()
        .and_then(|v| u64_of(&v, method).ok())
        .ok_or_else(|| {
            Error::Decode(format!(
                "{method} returned {:?}, not a u64",
                String::from_utf8_lossy(value)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hawkeye_core::SecretKey;

    #[test]
    fn burn_rows_are_hash_checked() {
        let r = BurnRecord {
            nonce: 3,
            from: AccountId::parse("alice.near").unwrap(),
            amount: 400_000_000,
            ycash_recipient: [1; 32],
            block_height: 77,
            timestamp_ns: 1_700_000_000_000_000_000,
        };
        let row = json!({"nonce": 3, "from": "alice.near", "amount": "400000000",
            "ycash_recipient": hex::encode([1u8; 32]), "block_height": 77,
            "timestamp_ns": "1700000000000000000", "record_hash": hex::encode(r.hash())});
        assert_eq!(parse_burn(&row).unwrap(), r);
        let mut bad = row.clone();
        bad["amount"] = json!("400000001");
        assert!(parse_burn(&bad).is_err());
    }

    #[test]
    fn proposals_and_config_parse() {
        let p = json!({"proposal_id": 2, "proposer": "ab".repeat(64), "receiver_id": "bob.near",
            "amount": "5", "eta_sec": 1000, "status": "Pending"});
        let p = parse_proposal(&p).unwrap();
        assert_eq!(
            (p.id, p.proposer, p.amount, p.eta, p.status),
            (2, [0xab; 64], 5, 1000, ProposalStatus::Pending)
        );
        let c = json!({"network_id": "sandbox", "contract_id": "wyec.near", "guardians": ["01".repeat(64)],
            "threshold": 1, "challenge_window_sec": 60, "mint_cap": "0", "cap_window_sec": 0,
            "admin_nonce": 0, "paused": false, "proposal_count": 4, "burn_count": 2,
            "total_supply": "340282366920938463463374607431768211455"});
        let c = parse_config(&c).unwrap();
        assert_eq!(c.total_supply, u128::MAX);
        assert_eq!(c.guardians, vec![[1; 64]]);
        assert_eq!(returned_u64(b"7", "x").unwrap(), 7);
        assert!(returned_u64(b"null", "x").is_err());
    }

    #[test]
    fn threshold_signatures_sort_by_recovered_key() {
        let keys: Vec<SecretKey> = (1..=3u8)
            .map(|i| SecretKey::from_bytes(&[i; 32]).unwrap())
            .collect();
        let d = [5u8; 32];
        let sigs: Vec<[u8; 65]> = keys
            .iter()
            .map(|k| hawkeye_core::near::sign_digest(k, &d).unwrap())
            .collect();
        let mut with_dup = sigs.clone();
        with_dup.push(sigs[0]);
        let sorted = sort_signatures(&d, &with_dup).unwrap();
        assert_eq!(sorted.len(), 3);
        let rec: Vec<GuardianKey> = sorted
            .iter()
            .map(|s| recover_guardian(&d, s).unwrap())
            .collect();
        assert!(rec.windows(2).all(|w| w[0] < w[1]));
        assert!(sort_signatures(&d, &[[0u8; 65]]).is_err());
    }
}
