//! The engine (plan §5): one loop, each [`Engine::tick`] idempotent and persisted through the
//! ledger.
//!
//! A tick, in order:
//!
//! 1. **set** — `set_getinfo`: live members (leader schedule, §5.2), this attestor's standing;
//! 2. **ycash** ([`ycash`]) — follow the active chain block by block (reorgs rewind the ledger,
//!    §5.4): the bridge's vaults (its configured tag, `WYEC` on Ethereum), new locks, intents
//!    created, cancelled and released;
//! 3. **eth** ([`mint`]) — the foreign chain's finalized burn / `Minted` / `MintProposed` events
//!    (through the [`ForeignChain`] adapter, NEAR plan §4 item 2); every
//!    `Minted` and every optimistic proposal must match a policy-OK lock (watcher, §5.3 step 2):
//!    a proposal that does not is challenged within the contract's window (sign-once), in every
//!    mint mode. Proposals and challenges are also read at the chain's head, ahead of finality
//!    (audit 05/H-2): the contract runs the window at `latest`, so a finalized-only watcher would
//!    see a proposal two epochs late and not at all while finality stalls. A finality stall
//!    raises `eth-finality-stall` and, on mainnet, pauses this attestor's own mint-side acts
//!    (never its challenges);
//! 4. **watch** ([`watch`]) — every intent of the set (blocks, `vault_list`, mempool) classified
//!    (§3.2); unmatched ones cancelled once (sign-once) and their signer put in a slash case;
//!    equivocations submitted;
//! 5. **locks / mint** ([`mint`]) — lock policy after `C_Y`, EIP-712 sign-once; the leader mints
//!    (threshold mode) or proposes and later executes (optimistic mode);
//! 6. **burns** ([`burn`]) — leader assignment and takeover, rate limit, unlock with the `HKB1`
//!    memo, release after the delay;
//! 7. **rolls** ([`roll`]) — vaults within `ROLL_MARGIN` of `ownerHeight` are unlocked by the
//!    roll leader into a fresh V with a kind-2 memo (HK-6), released after the delay;
//! 8. **slash** ([`slash`]) — the case owner builds `SET_REMOVE burn=1`, gathers votes from peers
//!    (each verifies the evidence against its own node and ledger), sends it;
//! 9. **heartbeat**, the supply check, status and alarms.
//!
//! What a restart must not lose is in the ledger (schema v2): deferred mint checks, slash votes
//! gathered and given, set signatures seen (equivocation detection).
//!
//! Every action logs one structured line with an `event` field.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use hawkeye_core::bytes::{Hash32, txid_to_display};
use hawkeye_core::keys::sort_members;
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33, SecretKey};
use hawkeye_store::{
    BurnState, IntentState, LockState, Machine, SlashState, Store, StoreError, Tx, VaultState,
};
use hawkeye_ycash::YcashRpc;
use hawkeye_ycash::types::{IntentOutput, Member, MemberStatus, SetInfo};
use tracing::{info, warn};

use crate::attribution::Attributor;
use crate::config::Params;
use crate::foreign::{ForeignChain, Guardian};
use crate::peers::Peers;
use crate::status::{Alarm, Heights, Status, Supply};

pub mod burn;
pub mod mint;
pub mod roll;
pub mod sign;
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
    /// The bridge deployment on the foreign chain (Ethereum: with the member key as sender).
    pub foreign: Arc<dyn ForeignChain>,
    /// The ledger.
    pub store: Arc<Mutex<Store>>,
    /// Set-signature attribution.
    pub attributor: Arc<dyn Attributor>,
    /// The other attestors' APIs.
    pub peers: Peers,
    /// The peer API's authentication state: settings, the set snapshot the engine publishes
    /// every tick, the replay cache (remedial report 05/H-1).
    pub auth: Arc<crate::peer_auth::AuthState>,
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

    /// This attestor's guardian on the foreign chain.
    pub fn guardian(&self) -> Result<Guardian> {
        self.foreign
            .guardian_of(&self.me)
            .map_err(|e| anyhow!("member key {}: {e}", hex::encode(self.me)))
    }
}

/// Run an async call to completion from inside a synchronous closure (a sign-once ledger
/// transaction: the node's signature is recorded before it is used). Needs the multi-thread
/// runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// The environment variable that arms a drill crash point (drill D-16).
pub const DRILL_CRASH_ENV: &str = "HAWKEYE_DRILL_CRASH_AT";

/// Whether crash point `point` is armed: `[devnet] drills = true`, not mainnet, and `armed` (the
/// value of [`DRILL_CRASH_ENV`]) names it.
pub fn drill_crash_armed(p: &Params, point: &str, armed: Option<&str>) -> bool {
    p.drills && !p.mainnet && armed == Some(point)
}

/// Drill D-16: abort the process at `point` when [`drill_crash_armed`] — a crash at the exact
/// moment a signature is recorded in the ledger and not yet used (`unlock_signed`: before the
/// unlock is broadcast; `mint_signed`: before the mint is submitted). `abort` runs no
/// destructor and flushes nothing, as `kill -9` would. Never armed on mainnet.
pub(crate) fn drill_crash_point(p: &Params, point: &str) {
    let armed = std::env::var(DRILL_CRASH_ENV).ok();
    if drill_crash_armed(p, point, armed.as_deref()) {
        warn!(
            event = "drill_crash",
            point, "aborting at an armed drill crash point"
        );
        std::process::abort();
    }
}

/// The result of one tick.
#[derive(Debug, Default, Clone)]
pub struct TickReport {
    /// Ycash tip at the start of the tick.
    pub tip: u32,
    /// Steps that failed (`step: error`); the other steps still ran.
    pub errors: Vec<String>,
}

/// In-memory working state (everything durable is in the ledger).
#[derive(Default)]
pub(crate) struct Memory {
    pub tip: u32,
    pub set: Option<SetInfo>,
    pub members: Vec<Member>,
    pub live: Vec<PubKey33>,
    /// The members a slash still reaches (D-Q-31): the current ones, and those that already
    /// left (`removed`, bond not frozen) whose bond is unspent — in its exit delay.
    pub slashable: Vec<PubKey33>,
    pub vault_scripts: HashMap<CoreOutPoint, (Vec<u8>, u64)>,
    pub locked_value: u64,
    pub intent_rows: HashMap<CoreOutPoint, IntentOutput>,
    pub mempool_seen: HashSet<Hash32>,
    pub mempool_spent: HashSet<CoreOutPoint>,
    pub raw_txs: HashMap<Hash32, Vec<u8>>,
    pub submitted: HashMap<Hash32, u32>,
    pub release_tried: HashMap<CoreOutPoint, u32>,
    pub roll_logged: HashSet<CoreOutPoint>,
    pub roll_value_pending: u64,
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
    /// The bridge's challenge window (read once).
    pub challenge_window: Option<u64>,
    /// Challenges known submitted or moot (their proposal is gone).
    pub challenges_done: mint::ProposalKeys,
    /// Own deliberate (drill) proposals already logged as left to the others.
    pub own_proposals_logged: mint::ProposalKeys,
    /// Once-only warnings about a lock's proposals (a mismatching one holding it, no eligible
    /// proposer, the rate limit).
    pub squat_logged: mint::ProposalKeys,
    /// The foreign chain's head at the last proposal scan (audit 05/H-2).
    pub eth_latest: u64,
    /// The last block the head-of-chain proposal scan covered (it re-reads
    /// [`mint::PROPOSAL_RESCAN_DEPTH`] blocks below it each tick).
    pub latest_scanned: u64,
    /// Proposals already handled by the head-of-chain scan: `(lockId, tx) → block`, pruned once
    /// the block is final.
    pub provisional_seen: HashMap<(Hash32, Hash32), u64>,
    /// Unfinalized fraudulent proposals already challenged: `(lockId, tx)`.
    pub provisional_challenged: HashSet<(Hash32, Hash32)>,
    /// The finality watch: the finalized height, since when it has not moved, and the head then.
    pub finality_watch: Option<FinalityWatch>,
    /// `finalized` has not moved for [`ETH_FINALITY_STALL_SECS`](hawkeye_eth::mode::ETH_FINALITY_STALL_SECS)
    /// while the head advanced.
    pub finality_stalled: bool,
    /// The bridge's `mintCap` was set to 0 (no limit) on mainnet.
    pub mint_cap_unbounded: bool,
    /// Added to the wall clock (tests drive the finality watch without waiting).
    pub clock_offset: Duration,
    /// Unacknowledged exposures (audit 05/L-5): lock ids, from the ledger every tick.
    pub exposures: Vec<Hash32>,
    /// `ROLL_DUE` vaults this member signed and cannot roll (W4-B-2).
    pub pinned_vaults: Vec<crate::status::PinnedVault>,
    /// Locks whose proposal this attestor withdrew (challenged) after the lock reorged.
    pub withdrawn: HashSet<Hash32>,
    /// Peers whose co-signatures failed the adoption checks, by URL: consecutive failures
    /// (two or more: asked last).
    pub peer_backoff: HashMap<String, u32>,
    /// Orphaned vaults reported to the peers: the tick of the last report (review H-2).
    pub orphan_reported: HashMap<CoreOutPoint, u64>,
    /// Pending burns' unmined intents seen out of the mempool, by txid: the tip first seen so
    /// (review M-3).
    pub evicted_since: HashMap<Hash32, u32>,
    /// Once-only warnings about a burn held by a live unlock this attestor will not re-send.
    pub held_logged: HashSet<u64>,
    /// The fee coins counted at the last capacity check.
    pub fee_coins: Option<u64>,
    /// The foreign-chain sender and its balance at the last gas check.
    pub sender: Option<(String, u128)>,
}

/// When the foreign chain's finalized height last moved (audit 05/H-2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct FinalityWatch {
    /// The finalized height.
    pub finalized: u64,
    /// When it was first seen at this value.
    pub since: Instant,
    /// The head when it was.
    pub latest_then: u64,
}

/// The engine.
pub struct Engine {
    pub(crate) ctx: Ctx,
    pub(crate) mem: Memory,
    /// The ledger's high-water-mark file (review L-2), raised after every tick.
    pub(crate) ledger_hwm: Option<std::path::PathBuf>,
}

impl Engine {
    /// An engine over `ctx`.
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            ledger_hwm: None,
            mem: Memory {
                guardian_check_due: true,
                ..Memory::default()
            },
        }
    }

    /// Keep the ledger's high-water mark at `path` (review L-2).
    pub fn with_ledger_hwm(mut self, path: std::path::PathBuf) -> Self {
        self.ledger_hwm = Some(path);
        self
    }

    /// The shared context.
    pub fn ctx(&self) -> &Ctx {
        &self.ctx
    }

    /// The raised alarms.
    pub fn alarms(&self) -> Vec<Alarm> {
        self.mem.alarms.values().cloned().collect()
    }

    /// Move this engine's clock forward by `by` (tests: the finality-stall watch without a
    /// twenty-minute wait). The ledger's own timestamps are unaffected.
    #[doc(hidden)]
    pub fn advance_clock(&mut self, by: Duration) {
        self.mem.clock_offset += by;
    }

    /// The engine's clock: the wall clock plus [`advance_clock`](Self::advance_clock)'s offset.
    pub(crate) fn instant(&self) -> Instant {
        Instant::now() + self.mem.clock_offset
    }

    /// Whether the finality watch reports a stall (audit 05/H-2).
    pub fn finality_stalled(&self) -> bool {
        self.mem.finality_stalled
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
        step!("eth-latest", self.scan_proposals_latest());
        step!("minted", self.check_pending_mints());
        step!("exposure", self.refresh_exposures());
        step!("guardians", self.check_guardians());
        step!("fees", self.check_fee_coins());
        step!("restored", self.check_sign_restored());
        step!("watch", self.watch());
        step!("locks", self.evaluate_locks());
        step!("mint", self.mint());
        step!("burns", self.burns());
        step!("orphans", self.orphans());
        step!("rolls", self.rolls());
        step!("releases", self.releases());
        step!("slash", self.slash());
        step!("heartbeat", self.heartbeat());
        step!("supply", self.supply());
        step!("gas", self.check_gas());
        if let Some(p) = &self.ledger_hwm
            && let Ok(n) = self.ctx.db(|t| t.ycash_signature_count())
            && let Err(e) = crate::restore::write_hwm(p, n)
        {
            warn!(event = "ledger_hwm_failed", error = %format!("{e:#}"));
        }
        match self.ledger_restored() {
            Ok(true) => {
                let why = self
                    .ctx
                    .db(|t| t.meta(burn::LEDGER_RESTORED))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                self.alarm(
                    "ledger-restored",
                    format!(
                        "{why}: fresh unlocks wait for every member's signed answer \
                         (`hawkeye acknowledge-ledger-restore` once safe)"
                    ),
                );
            }
            _ => self.clear_alarm("ledger-restored"),
        }
        self.publish_status(&report);
        report
    }

    /// A read-only status (for `hawkeye status`): the set, the chains' heights and the supply,
    /// with the ledger's counts. Writes nothing.
    pub async fn snapshot(&mut self) -> Result<Status> {
        self.refresh_set().await?;
        self.mem.eth_finalized = self
            .ctx
            .foreign
            .finalized_height()
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let rows = self
            .ctx
            .ycash
            .vault_list(Some(&hawkeye_ycash::types::VaultListFilter {
                tag: Some(self.ctx.params.tag_text()),
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
        self.check_gas().await?;
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

    /// A set signature the node wallet refused with `set-sign-restored` (07/F-5, `"wallet"` mode):
    /// the wallet carries the restore marker, so it signs no unlock or cancel until the operator
    /// imports the history and acknowledges (`hawkeye acknowledge-restore`). Paged: the bridge's
    /// cancels depend on it.
    pub(crate) fn note_sign_error(&mut self, e: &anyhow::Error) {
        if format!("{e:#}").contains("set-sign-restored") {
            self.alarm(
                "node-sign-restored",
                "the node wallet refuses to sign (set-sign-restored: restored from a seed or the \
                 member key imported); after checking no other copy of the key signed, run \
                 `hawkeye acknowledge-restore`"
                    .to_owned(),
            );
        }
    }

    /// Clear `node-sign-restored` once the wallet's restore marker is gone.
    async fn check_sign_restored(&mut self) -> Result<()> {
        if self.mem.alarms.contains_key("node-sign-restored")
            && !self.ctx.ycash.set_listsigned().await?.restored
        {
            self.clear_alarm("node-sign-restored");
        }
        Ok(())
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
        let slashable = slashable_members(&self.ctx, &info.memberlist).await;
        self.mem.slashable = slashable;
        self.mem.tip = tip;
        self.mem.members = info.memberlist.clone();
        self.mem.live = live;
        self.ctx.auth.publish(&info);
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

    /// Whether a peer's answer may be counted: signed by a current member, or unsigned when
    /// `[peers] require_auth = false` (regtest transition).
    pub(crate) fn responder_ok(&self, responder: Option<PubKey33>) -> bool {
        match responder {
            Some(k) => self.current_member_keys().contains(&k),
            None => !self.ctx.auth.config.require_auth,
        }
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

    /// The keys a slash still reaches (the `slashable` cache): fault attribution (a
    /// fraudulent intent's or mint's signer, an equivocation) looks here, not only at the
    /// current members, so a member cannot escape a fault by leaving (owner 2026-10-11).
    pub(crate) fn slashable_member_keys(&self) -> Vec<PubKey33> {
        self.mem.slashable.clone()
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
        let txid = match self.ctx.params.ycash_signing {
            crate::config::YcashSigning::Wallet => {
                self.ctx
                    .ycash
                    .set_heartbeat(
                        &self.ctx.set_hash(),
                        Some(&hawkeye_ycash::PubKey(self.ctx.me)),
                    )
                    .await?
                    .txid
            }
            crate::config::YcashSigning::SelfSigned => {
                // 05/M-1: built and funded by the wallet, the act signature made here
                let built = self
                    .ctx
                    .ycash
                    .set_buildact(&hawkeye_ycash::types::BuildAct::Heartbeat {
                        setid: self.ctx.set_hash(),
                        memberkey: hawkeye_ycash::PubKey(self.ctx.me),
                    })
                    .await?;
                let (signed, _, _) = sign::self_sign_act(&self.ctx.key, &built.hex.to_string())?;
                let h: hawkeye_ycash::HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
                self.ctx.ycash.set_sendact(&h).await?
            }
        };
        self.mem.last_heartbeat = Some(next);
        info!(event = "heartbeat", txid = %txid, height = next);
        Ok(())
    }

    async fn supply(&mut self) -> Result<()> {
        let supply = self.ctx.foreign.total_supply().await?;
        self.mem.wyec_supply = supply;
        // a roll in its window holds the vault's value in a matched roll intent (HK-6)
        let locked = self
            .mem
            .locked_value
            .saturating_add(self.mem.roll_value_pending);
        if supply > u128::from(locked) {
            self.alarm(
                "supply",
                format!(
                    "wYEC totalSupply {supply} > locked {} vault value {locked} (rolls in \
                     flight included)",
                    self.ctx.params.tag_text()
                ),
            );
        } else {
            self.clear_alarm("supply");
        }
        Ok(())
    }

    /// The gas account's balance (every 20 ticks; remedial report 05/M-1): `gas-low` below
    /// `[eth] min_sender_balance_wei`.
    async fn check_gas(&mut self) -> Result<()> {
        if self.mem.sender.is_some() && !self.mem.ticks.is_multiple_of(20) {
            return Ok(());
        }
        let Some((who, bal)) = self
            .ctx
            .foreign
            .sender_balance()
            .await
            .map_err(|e| anyhow!("{e}"))?
        else {
            return Ok(());
        };
        let floor = self.ctx.params.min_sender_balance_wei;
        if floor > 0 && bal < floor {
            self.alarm(
                "gas-low",
                format!("the sender {who} holds {bal} wei < {floor}: fund it"),
            );
        } else {
            self.clear_alarm("gas-low");
        }
        self.mem.sender = Some((who, bal));
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
        let (counts, over_cap, ycur, ecur) = self.ctx.db(|t| {
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
            let over_cap = t
                .burns_in_state(&dep, BurnState::WaitingCap)?
                .iter()
                .filter(|b| b.over_cap())
                .count() as u64;
            Ok((
                c,
                over_cap,
                t.cursor(hawkeye_store::Chain::Ycash)?,
                t.cursor(hawkeye_store::Chain::Foreign)?,
            ))
        })?;
        let [locks, burns, intents, vaults, slash_cases] = counts;
        let ycursor = ycur.map_or(0, |c| c.height);
        let ecursor = ecur.map_or(0, |c| c.height);
        let tip = u64::from(self.mem.tip);
        let supply_alarm = self.mem.alarms.contains_key("supply");
        let guardian = self.ctx.guardian()?.to_string();
        let foreign = Heights {
            tip: self.mem.eth_finalized,
            cursor: ecursor,
            lag: self.mem.eth_finalized.saturating_sub(ecursor),
        };
        let eth_finalized_age_secs = self.mem.finality_watch.map_or(0, |w| {
            self.instant().saturating_duration_since(w.since).as_secs()
        });
        Ok(Status {
            version: env!("CARGO_PKG_VERSION").into(),
            network: self.ctx.network_name.clone(),
            set_id: txid_to_display(&self.ctx.params.set_id),
            member_key: hex::encode(self.ctx.me),
            foreign_kind: self.ctx.params.bridge_kind.to_string(),
            eth_address: guardian.clone(),
            guardian,
            ycash: Heights {
                tip,
                cursor: ycursor,
                lag: tip.saturating_sub(ycursor),
            },
            ethereum: foreign.clone(),
            foreign,
            locks,
            burns,
            burns_over_cap: over_cap,
            intents,
            vaults,
            slash_cases,
            live_members: self.mem.live.len() as u64,
            supply: Supply {
                wyec_total_supply: self.mem.wyec_supply,
                locked_vault_value: self.mem.locked_value,
                ok: !supply_alarm,
            },
            fee_coins: self.mem.fee_coins,
            sender: self.mem.sender.as_ref().map(|s| s.0.clone()),
            sender_balance: self.mem.sender.as_ref().map(|s| s.1.to_string()),
            alarms: self.alarms(),
            ticks: self.mem.ticks,
            last_errors: report.errors.clone(),
            finality_stalled: self.mem.finality_stalled,
            exposure: self
                .mem
                .exposures
                .iter()
                .map(|id| format!("0x{}", hex::encode(id)))
                .collect(),
            eth_finalized_age_secs,
            pinned_vaults: self.mem.pinned_vaults.clone(),
        })
    }

    /// Re-read the guardian set when due (start, rotation events, every 60 ticks) and compare it
    /// with the current members' guardians (Ethereum: their addresses; plan §3.5, D-15); on
    /// mainnet also re-read whether the mint rate limit is unbounded.
    async fn check_guardians(&mut self) -> Result<()> {
        if !self.mem.guardian_check_due && !self.mem.ticks.is_multiple_of(60) {
            return Ok(());
        }
        self.mem.guardian_check_due = false;
        if self.ctx.params.mainnet {
            // the rate limit as the contract holds it now (audit 05/H-2): `mintAvailable()` is
            // the maximum exactly when `mintCap` is 0; read at start and every 60 ticks, so a
            // restart past the `MintLimitChanged` event keeps the pause
            let avail = self
                .ctx
                .foreign
                .mint_available()
                .await
                .map_err(|e| anyhow!("mint available: {e}"))?;
            self.mint_cap_changed(avail == u128::MAX);
        }
        self.check_live_floors().await?;
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

    /// The live parameter floors (audit 05/M-4), with the guardian check (start, every 60
    /// ticks): `heartbeat_blocks` against the set's current `livenesswindow` (a `SET_PARAMS` can
    /// shrink it) → `heartbeat-too-slow`, logged as an error on mainnet but never a pause (the
    /// heartbeats are the fix); vaults of the bridge's tag and set with another `delay` →
    /// `params-drift`.
    async fn check_live_floors(&mut self) -> Result<()> {
        if let Some(set) = &self.mem.set {
            match crate::floors::heartbeat_breach(&self.ctx.params, &set.set.params) {
                Some(r) => {
                    if self.ctx.params.mainnet {
                        tracing::error!(event = "heartbeat_too_slow", detail = %r);
                    }
                    self.alarm(
                        "heartbeat-too-slow",
                        format!("{r}: members would go DORMANT"),
                    );
                }
                None => self.clear_alarm("heartbeat-too-slow"),
            }
        }
        let (other, total) = crate::daemon::vault_delay_mismatch(&self.ctx).await?;
        if other > 0 {
            self.alarm(
                "params-drift",
                format!(
                    "{other} of {total} vaults carry a delay other than bridge.delay {}",
                    self.ctx.params.delay
                ),
            );
        } else {
            self.clear_alarm("params-drift");
        }
        Ok(())
    }

    /// Whether signing is paused by guardian drift (mainnet only; elsewhere an alarm).
    pub(crate) fn signing_paused(&self) -> bool {
        self.mem.guardian_drift && self.ctx.params.mainnet
    }

    /// Whether this attestor's own mint-side acts — `Mint` signatures, proposals, executions,
    /// threshold mints — are paused (mainnet only; elsewhere the alarms alone): guardian drift,
    /// a finality stall, or an unbounded `mintCap` (audit 05/H-2). Never consulted by
    /// challenges, cancels, heartbeats, releases or slash votes: those are the defence.
    pub(crate) fn mint_paused(&self) -> bool {
        self.signing_paused()
            || (self.ctx.params.mainnet
                && (self.mem.finality_stalled || self.mem.mint_cap_unbounded))
            || (self.exposure_pauses() && !self.mem.exposures.is_empty())
    }

    /// Whether an unacknowledged exposure pauses own mint-side acts here (audit 05/L-5): on
    /// mainnet and testnet; on regtest it is an alarm only.
    fn exposure_pauses(&self) -> bool {
        self.ctx.params.mainnet
            || self.ctx.params.network == hawkeye_core::address::Network::Testnet
    }

    /// The exposures from the ledger (audit 05/L-5): signed locks that left the active chain
    /// (`REORGED`) or were minted after they did (`MINTED_UNBACKED`), not acknowledged with
    /// `hawkeye exposure ack`. Raises or clears the `exposure` alarm; while any is unacknowledged
    /// this attestor's own `Mint` signatures, proposals, executions and threshold mints pause
    /// (off regtest). Challenges, cancels, heartbeats, releases and slash votes go on.
    pub(crate) async fn refresh_exposures(&mut self) -> Result<()> {
        let rows = self.ctx.db(|t| t.unacked_exposures())?;
        self.mem.exposures = rows.iter().map(|l| l.lock_id).collect();
        if rows.is_empty() {
            self.clear_alarm("exposure");
            return Ok(());
        }
        let list: Vec<String> = rows
            .iter()
            .map(|l| {
                format!(
                    "0x{} {} {} zat to {}",
                    hex::encode(l.lock_id),
                    l.state,
                    l.value_zat,
                    l.destination
                        .as_ref()
                        .map_or_else(|| "?".to_owned(), ToString::to_string)
                )
            })
            .collect();
        let paused = if self.exposure_pauses() {
            "; own mint-side acts paused until `hawkeye exposure ack <lockId>`"
        } else {
            ""
        };
        self.alarm(
            "exposure",
            format!(
                "signed locks left the active chain (unacknowledged): {}{paused}",
                list.join(", ")
            ),
        );
        Ok(())
    }

    /// Live members sorted (the leader order).
    pub(crate) fn live(&self) -> &[PubKey33] {
        &self.mem.live
    }

    /// The member list.
    pub(crate) fn member(&self, key: &PubKey33) -> Option<&Member> {
        self.mem.members.iter().find(|m| &m.key.0 == key)
    }
}

/// The members of `members` a slash still reaches (D-Q-31, the bond exit delay): every current
/// member, and every member that already left without a freeze (`removed`, `bondfrozen` false)
/// while its bond is unspent (`gettxout`, mempool included): its bond is in the exit delay, and
/// a cosigned `SET_REMOVE` with burn, or a `SET_EQUIVOCATION`, still freezes it. A `gettxout`
/// failure counts the member in (the node is the judge of the act).
pub async fn slashable_members(ctx: &Ctx, members: &[Member]) -> Vec<PubKey33> {
    let mut out = vec![];
    for m in members {
        if m.current {
            out.push(m.key.0);
            continue;
        }
        if m.status != MemberStatus::Removed || m.bondfrozen {
            continue;
        }
        match ctx
            .ycash
            .gettxout(&m.bondoutpoint.txid, m.bondoutpoint.vout, true)
            .await
        {
            Ok(None) => {}
            Ok(Some(_)) => out.push(m.key.0),
            Err(e) => {
                warn!(event = "bond_check_failed", member = %m.key, error = %e);
                out.push(m.key.0);
            }
        }
    }
    out
}

/// `None` if the contract's guardians equal the current members' guardians (Ethereum: their
/// addresses), else a description of the difference.
pub async fn guardian_mismatch(ctx: &Ctx, members: &[Member]) -> Result<Option<String>> {
    let guardians: HashSet<Guardian> = ctx
        .foreign
        .guardians()
        .await
        .map_err(|e| anyhow!("guardians: {e}"))?
        .into_iter()
        .collect();
    let mut expected = HashSet::new();
    for m in members.iter().filter(|m| m.current) {
        let a = ctx
            .foreign
            .guardian_of(&m.key.0)
            .map_err(|e| anyhow!("member key {}: {e}", m.key))?;
        expected.insert(a);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::sample_params;

    #[test]
    fn drill_crash_points_arm_only_on_a_drill_devnet() {
        let p = sample_params(true, false);
        assert!(drill_crash_armed(
            &p,
            "unlock_signed",
            Some("unlock_signed")
        ));
        assert!(!drill_crash_armed(&p, "unlock_signed", Some("mint_signed")));
        assert!(!drill_crash_armed(&p, "unlock_signed", None));
        // drills off, or mainnet: never armed, whatever the environment says
        let off = sample_params(false, false);
        assert!(!drill_crash_armed(
            &off,
            "unlock_signed",
            Some("unlock_signed")
        ));
        let main = sample_params(true, true);
        assert!(!drill_crash_armed(
            &main,
            "mint_signed",
            Some("mint_signed")
        ));
        // unarmed in the test environment: a crash point is a no-op
        drill_crash_point(&p, "a point nobody arms");
    }
}
