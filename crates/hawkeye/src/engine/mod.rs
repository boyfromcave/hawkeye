//! The engine (plan §5): one loop, each [`Engine::tick`] idempotent and persisted through the
//! ledger.
//!
//! A tick, in order:
//!
//! 1. **set** — `set_getinfo`: live members (leader schedule, §5.2), this attestor's standing;
//! 2. **ycash** ([`ycash`]) — follow the active chain block by block (reorgs rewind the ledger,
//!    §5.4): `WYEC` vaults, new locks, intents created, cancelled and released;
//! 3. **eth** ([`mint`]) — finalized `BurnToYcash` / `Minted` events; every `Minted` must match a
//!    policy-OK lock (watcher, §5.3 step 2);
//! 4. **watch** ([`watch`]) — every intent of the set (blocks, `vault_list`, mempool) classified
//!    (§3.2); unmatched ones cancelled once (sign-once) and their signer put in a slash case;
//!    equivocations submitted;
//! 5. **locks / mint** ([`mint`]) — lock policy after `C_Y`, EIP-712 sign-once, leader submits;
//! 6. **burns** ([`burn`]) — leader assignment and takeover, rate limit, unlock with the `HKB1`
//!    memo, release after the delay;
//! 7. **slash** ([`slash`]) — the case owner builds `SET_REMOVE burn=1`, gathers votes from peers,
//!    sends it;
//! 8. **heartbeat**, rolls (alarm only, HK-6 TODO), status and alarms.
//!
//! Every action logs one structured line with an `event` field.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result, anyhow};
use hawkeye_core::bytes::{Hash32, txid_to_display};
use hawkeye_core::keys::sort_members;
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33, SecretKey};
use hawkeye_eth::EthClient;
use hawkeye_store::{
    BurnState, IntentState, LockState, Machine, SlashState, Store, StoreError, Tx, VaultState,
};
use hawkeye_ycash::YcashRpc;
use hawkeye_ycash::types::{IntentOutput, Member, MemberStatus, SetInfo};
use tracing::{info, warn};

use crate::attribution::Attributor;
use crate::config::Params;
use crate::peers::Peers;
use crate::status::{Alarm, Heights, Status, Supply};

pub mod burn;
pub mod mint;
pub mod slash;
pub mod watch;
pub mod ycash;

/// Everything the engine and the API share.
#[derive(Clone)]
pub struct Ctx {
    /// Configuration.
    pub params: Arc<Params>,
    /// The member key.
    pub key: SecretKey,
    /// Its compressed public key.
    pub me: PubKey33,
    /// This attestor's own ycashd.
    pub ycash: Arc<YcashRpc>,
    /// The bridge deployment (with the member key as sender).
    pub eth: EthClient,
    /// The ledger.
    pub store: Arc<Mutex<Store>>,
    /// Set-signature attribution.
    pub attributor: Arc<dyn Attributor>,
    /// The other attestors' APIs.
    pub peers: Peers,
    /// The latest status summary.
    pub status: Arc<RwLock<Status>>,
    /// `regtest` / `testnet` / `mainnet`.
    pub network_name: String,
}

impl Ctx {
    /// Run `f` in one ledger transaction.
    pub fn db<T>(&self, f: impl FnOnce(&Tx<'_>) -> Result<T, StoreError>) -> Result<T> {
        let mut s = self.store.lock().unwrap_or_else(|e| e.into_inner());
        Ok(s.tx(f)?)
    }

    /// The set id in RPC form.
    pub fn set_hash(&self) -> hawkeye_ycash::Hash256 {
        self.params.set_hash()
    }
}

/// Run an async call to completion from inside a synchronous closure (a sign-once ledger
/// transaction: the node's signature is recorded before it is used). Needs the multi-thread
/// runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// The result of one tick.
#[derive(Debug, Default, Clone)]
pub struct TickReport {
    /// Ycash tip at the start of the tick.
    pub tip: u32,
    /// Steps that failed (`step: error`); the other steps still ran.
    pub errors: Vec<String>,
}

/// A `Minted` (or `MintProposed`) event waiting for this attestor's Ycash view to catch up.
#[derive(Debug, Clone)]
pub(crate) struct PendingMint {
    pub lock_id: Hash32,
    pub to: hawkeye_core::EthAddress,
    pub amount: u64,
    pub tx_hash: Hash32,
    pub block: u64,
    pub since_tip: u32,
}

/// A set signature seen on Ycash (equivocation detection, §2.3 row 1).
#[derive(Debug, Clone)]
pub(crate) struct SeenSig {
    pub role: u8,
    pub sighash: Hash32,
    pub key: PubKey33,
    pub sig: [u8; 65],
}

/// In-memory working state (everything durable is in the ledger).
#[derive(Default)]
pub(crate) struct Memory {
    pub tip: u32,
    pub set: Option<SetInfo>,
    pub members: Vec<Member>,
    pub live: Vec<PubKey33>,
    pub vault_scripts: HashMap<CoreOutPoint, (Vec<u8>, u64)>,
    pub locked_value: u64,
    pub intent_rows: HashMap<CoreOutPoint, IntentOutput>,
    pub mempool_seen: HashSet<Hash32>,
    pub mempool_spent: HashSet<CoreOutPoint>,
    pub raw_txs: HashMap<Hash32, Vec<u8>>,
    pub sigs_seen: HashMap<CoreOutPoint, Vec<SeenSig>>,
    pub equivocations_sent: HashSet<(CoreOutPoint, PubKey33)>,
    pub pending_mints: Vec<PendingMint>,
    pub submitted: HashMap<Hash32, u32>,
    pub release_tried: HashMap<CoreOutPoint, u32>,
    pub case_hex: HashMap<i64, (String, bool)>,
    pub alarms: BTreeMap<String, Alarm>,
    pub eth_fresh: bool,
    pub eth_finalized: u64,
    pub guardian_check_due: bool,
    pub guardian_drift: bool,
    pub ticks: u64,
    pub last_heartbeat: Option<u32>,
    pub no_vault_logged: HashSet<u64>,
    pub own_logged: HashSet<CoreOutPoint>,
    pub wyec_supply: u128,
}

/// The engine.
pub struct Engine {
    pub(crate) ctx: Ctx,
    pub(crate) mem: Memory,
}

impl Engine {
    /// An engine over `ctx`.
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            mem: Memory {
                guardian_check_due: true,
                ..Memory::default()
            },
        }
    }

    /// The shared context.
    pub fn ctx(&self) -> &Ctx {
        &self.ctx
    }

    /// The raised alarms.
    pub fn alarms(&self) -> Vec<Alarm> {
        self.mem.alarms.values().cloned().collect()
    }

    /// One pass of the loop. Idempotent: running it twice on the same chains changes nothing.
    pub async fn tick(&mut self) -> TickReport {
        self.mem.ticks += 1;
        let mut report = TickReport::default();
        if let Err(e) = self.refresh_set().await {
            warn!(event = "tick_error", step = "set", error = %format!("{e:#}"));
            report.errors.push(format!("set: {e:#}"));
            self.publish_status(&report);
            return report;
        }
        report.tip = self.mem.tip;
        macro_rules! step {
            ($name:literal, $e:expr) => {
                if let Err(e) = $e.await {
                    warn!(event = "tick_error", step = $name, error = %format!("{e:#}"));
                    report.errors.push(format!("{}: {e:#}", $name));
                }
            };
        }
        step!("ycash", self.follow_ycash());
        step!("vaults", self.sync_vaults());
        step!("eth", self.scan_eth());
        step!("minted", self.check_pending_mints());
        step!("guardians", self.check_guardians());
        step!("watch", self.watch());
        step!("locks", self.evaluate_locks());
        step!("mint", self.mint());
        step!("burns", self.burns());
        step!("releases", self.releases());
        step!("slash", self.slash());
        step!("heartbeat", self.heartbeat());
        step!("rolls", self.rolls());
        step!("supply", self.supply());
        self.publish_status(&report);
        report
    }

    /// A read-only status (for `hawkeye status`): the set, the chains' heights and the supply,
    /// with the ledger's counts. Writes nothing.
    pub async fn snapshot(&mut self) -> Result<Status> {
        self.refresh_set().await?;
        self.mem.eth_finalized = self
            .ctx
            .eth
            .finalized_block_number()
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let rows = self
            .ctx
            .ycash
            .vault_list(Some(&hawkeye_ycash::types::VaultListFilter {
                tag: Some("WYEC".into()),
                setid: Some(self.ctx.set_hash()),
                kind: Some(hawkeye_ycash::types::TemplateKind::Vault),
                ..Default::default()
            }))
            .await?;
        self.mem.locked_value = rows
            .iter()
            .filter_map(|r| r.as_vault())
            .map(|v| u64::try_from(v.valuezat).unwrap_or(0))
            .sum();
        self.supply().await?;
        self.compute_status(&TickReport::default())
    }

    /// Raise (or refresh) an alarm; logs once when first raised.
    pub(crate) fn alarm(&mut self, name: &str, detail: String) {
        if !self.mem.alarms.contains_key(name) {
            warn!(event = "alarm", name, detail = %detail);
        }
        let since = self.mem.alarms.get(name).map_or(self.mem.tip, |a| a.since);
        self.mem.alarms.insert(
            name.to_owned(),
            Alarm {
                name: name.to_owned(),
                detail,
                since,
            },
        );
    }

    /// Clear an alarm.
    pub(crate) fn clear_alarm(&mut self, name: &str) {
        if self.mem.alarms.remove(name).is_some() {
            info!(event = "alarm_cleared", name);
        }
    }

    async fn refresh_set(&mut self) -> Result<()> {
        let tip = self.ctx.ycash.getblockcount().await?;
        let info = self
            .ctx
            .ycash
            .set_getinfo(&self.ctx.set_hash(), None)
            .await
            .context("set_getinfo")?;
        let mut live: Vec<PubKey33> = info
            .memberlist
            .iter()
            .filter(|m| m.current && m.live)
            .map(|m| m.key.0)
            .collect();
        sort_members(&mut live);
        self.mem.tip = tip;
        self.mem.members = info.memberlist.clone();
        self.mem.live = live;
        self.mem.set = Some(info);
        if !self.is_current_member() {
            self.alarm(
                "not-a-member",
                format!(
                    "member key {} is not a current member of the set",
                    hex::encode(self.ctx.me)
                ),
            );
        } else {
            self.clear_alarm("not-a-member");
        }
        Ok(())
    }

    /// Whether this attestor's key is a current member.
    pub(crate) fn is_current_member(&self) -> bool {
        self.mem
            .members
            .iter()
            .any(|m| m.key.0 == self.ctx.me && m.current)
    }

    /// Current members' keys (membership check of attributed signers).
    pub(crate) fn current_member_keys(&self) -> Vec<PubKey33> {
        self.mem
            .members
            .iter()
            .filter(|m| m.current)
            .map(|m| m.key.0)
            .collect()
    }

    async fn heartbeat(&mut self) -> Result<()> {
        let every = self.ctx.params.heartbeat_blocks;
        if every == 0 {
            return Ok(());
        }
        let Some(me) = self
            .mem
            .members
            .iter()
            .find(|m| m.key.0 == self.ctx.me && m.current)
        else {
            return Ok(());
        };
        let next = self.mem.tip + 1;
        let last = me.lastact.max(self.mem.last_heartbeat.unwrap_or(0));
        if next < last.saturating_add(every) {
            return Ok(());
        }
        let r = self
            .ctx
            .ycash
            .set_heartbeat(
                &self.ctx.set_hash(),
                Some(&hawkeye_ycash::PubKey(self.ctx.me)),
            )
            .await?;
        self.mem.last_heartbeat = Some(next);
        info!(event = "heartbeat", txid = %r.txid, height = next);
        Ok(())
    }

    /// HK-6: rolls are not implemented in this round. A vault within `ROLL_MARGIN` of its
    /// `ownerHeight` is moved to `ROLL_DUE` and raises the `roll-due` alarm.
    // TODO(HK-6): unlock ROLL_DUE vaults into a fresh V with a kind-2 memo (plan §3.1 item 2).
    async fn rolls(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let margin = self.ctx.params.roll_margin;
        let due = self.ctx.db(|t| {
            let mut due = vec![];
            for v in t.vaults_in_state(VaultState::Live)? {
                if v.owner_height <= tip.saturating_add(margin) {
                    t.transition_vault(
                        &v.outpoint,
                        VaultState::RollDue,
                        Some(tip),
                        Some("within ROLL_MARGIN"),
                    )?;
                    due.push(v);
                }
            }
            let all = t.vaults_in_state(VaultState::RollDue)?;
            Ok((due, all))
        })?;
        for v in &due.0 {
            warn!(event = "roll_due", vault = %v.outpoint, owner_height = v.owner_height, tip);
        }
        if due.1.is_empty() {
            self.clear_alarm("roll-due");
        } else {
            let list: Vec<String> = due
                .1
                .iter()
                .map(|v| format!("{} (ownerHeight {})", v.outpoint, v.owner_height))
                .collect();
            self.alarm(
                "roll-due",
                format!(
                    "vaults near ownerHeight, rolls not implemented (HK-6): {}",
                    list.join(", ")
                ),
            );
        }
        Ok(())
    }

    async fn supply(&mut self) -> Result<()> {
        let supply = self.ctx.eth.total_supply().await?;
        let supply = u128::try_from(supply).unwrap_or(u128::MAX);
        self.mem.wyec_supply = supply;
        let locked = self.mem.locked_value;
        if supply > u128::from(locked) {
            self.alarm(
                "supply",
                format!("wYEC totalSupply {supply} > locked WYEC vault value {locked}"),
            );
        } else {
            self.clear_alarm("supply");
        }
        Ok(())
    }

    fn publish_status(&self, report: &TickReport) {
        let s = self.compute_status(report).unwrap_or_else(|e| Status {
            last_errors: vec![format!("status: {e:#}")],
            ..Status::default()
        });
        *self.ctx.status.write().unwrap_or_else(|e| e.into_inner()) = s;
    }

    fn compute_status(&self, report: &TickReport) -> Result<Status> {
        let dep = self.ctx.params.deployment;
        let (counts, ycur, ecur) = self.ctx.db(|t| {
            let mut c: [BTreeMap<String, u64>; 5] = Default::default();
            for s in LockState::ALL {
                c[0].insert(s.to_string(), t.locks_in_state(*s)?.len() as u64);
            }
            for s in BurnState::ALL {
                c[1].insert(s.to_string(), t.burns_in_state(&dep, *s)?.len() as u64);
            }
            for s in IntentState::ALL {
                c[2].insert(s.to_string(), t.intents_in_state(*s)?.len() as u64);
            }
            for s in VaultState::ALL {
                c[3].insert(s.to_string(), t.vaults_in_state(*s)?.len() as u64);
            }
            for s in SlashState::ALL {
                c[4].insert(s.to_string(), t.slash_cases_in_state(*s)?.len() as u64);
            }
            Ok((
                c,
                t.cursor(hawkeye_store::Chain::Ycash)?,
                t.cursor(hawkeye_store::Chain::Ethereum)?,
            ))
        })?;
        let [locks, burns, intents, vaults, slash_cases] = counts;
        let ycursor = ycur.map_or(0, |c| c.height);
        let ecursor = ecur.map_or(0, |c| c.height);
        let tip = u64::from(self.mem.tip);
        let supply_alarm = self.mem.alarms.contains_key("supply");
        Ok(Status {
            version: env!("CARGO_PKG_VERSION").into(),
            network: self.ctx.network_name.clone(),
            set_id: txid_to_display(&self.ctx.params.set_id),
            member_key: hex::encode(self.ctx.me),
            eth_address: self.ctx.key.eth_address().to_checksum(),
            ycash: Heights {
                tip,
                cursor: ycursor,
                lag: tip.saturating_sub(ycursor),
            },
            ethereum: Heights {
                tip: self.mem.eth_finalized,
                cursor: ecursor,
                lag: self.mem.eth_finalized.saturating_sub(ecursor),
            },
            locks,
            burns,
            intents,
            vaults,
            slash_cases,
            live_members: self.mem.live.len() as u64,
            supply: Supply {
                wyec_total_supply: self.mem.wyec_supply,
                locked_vault_value: self.mem.locked_value,
                ok: !supply_alarm,
            },
            alarms: self.alarms(),
            ticks: self.mem.ticks,
            last_errors: report.errors.clone(),
        })
    }

    /// Re-read the guardian set when due (start, rotation events, every 60 ticks) and compare it
    /// with the current members' Ethereum addresses (plan §3.5, D-15).
    async fn check_guardians(&mut self) -> Result<()> {
        if !self.mem.guardian_check_due && !self.mem.ticks.is_multiple_of(60) {
            return Ok(());
        }
        self.mem.guardian_check_due = false;
        let mismatch = guardian_mismatch(&self.ctx, &self.mem.members).await?;
        match mismatch {
            None => {
                self.mem.guardian_drift = false;
                self.clear_alarm("guardian-drift");
            }
            Some(d) => {
                self.mem.guardian_drift = true;
                self.alarm("guardian-drift", d);
            }
        }
        Ok(())
    }

    /// Whether signing is paused by guardian drift (mainnet only; elsewhere an alarm).
    pub(crate) fn signing_paused(&self) -> bool {
        self.mem.guardian_drift && self.ctx.params.mainnet
    }

    /// Live members sorted (the leader order).
    pub(crate) fn live(&self) -> &[PubKey33] {
        &self.mem.live
    }

    /// The member list.
    pub(crate) fn member(&self, key: &PubKey33) -> Option<&Member> {
        self.mem.members.iter().find(|m| &m.key.0 == key)
    }

    /// Whether `key` was removed or ejected.
    pub(crate) fn is_removed(&self, key: &PubKey33) -> bool {
        self.member(key).is_some_and(|m| {
            matches!(m.status, MemberStatus::Removed | MemberStatus::Ejected) || !m.current
        })
    }
}

/// `None` if the contract's guardians equal the current members' Ethereum addresses, else a
/// description of the difference.
pub async fn guardian_mismatch(ctx: &Ctx, members: &[Member]) -> Result<Option<String>> {
    let guardians: HashSet<_> = ctx
        .eth
        .guardians()
        .await
        .map_err(|e| anyhow!("guardians: {e}"))?
        .into_iter()
        .collect();
    let mut expected = HashSet::new();
    for m in members.iter().filter(|m| m.current) {
        let a = hawkeye_core::eth::address_from_pubkey(&m.key.0)
            .map_err(|e| anyhow!("member key {}: {e}", m.key))?;
        expected.insert(crate::convert::addr(&a));
    }
    if guardians == expected {
        return Ok(None);
    }
    let missing: Vec<String> = expected
        .difference(&guardians)
        .map(|a| a.to_string())
        .collect();
    let extra: Vec<String> = guardians
        .difference(&expected)
        .map(|a| a.to_string())
        .collect();
    Ok(Some(format!(
        "guardian set differs from the set's current members: members not guardians [{}], guardians not members [{}]",
        missing.join(", "),
        extra.join(", ")
    )))
}
