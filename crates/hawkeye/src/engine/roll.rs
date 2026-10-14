//! Rolls (plan §3.1 item 2, HK-6, memo §4.3 kind 2).
//!
//! A `WYEC` vault whose `ownerHeight − tip ≤ ROLL_MARGIN` is `ROLL_DUE`. Its roll leader —
//! [`mint_leader_for`] over the vault outpoint's `lockId`, with takeover every `TAKEOVER` blocks
//! counted from the moment it fell due — unlocks the **whole** vault (no re-lock remainder, which
//! would keep the old `ownerHeight`) into one intent whose recipient is a fresh V with the same
//! tag, sets, delay and owner (the post-quantum owner slot, byte for byte), `appHeight` 0 and `ownerHeight = tip + 1 + MIN_OWNER_AGE +
//! ROLL_MARGIN + ROLL_SLACK`, carrying the kind-2 memo (`ref` = the new `ownerHeight`, `data` =
//! SHA256 of the new V's scriptPubKey). Watchers verify it from the intent alone (the matcher's
//! `MatchedRoll`) and do not cancel it; an invalid roll is cancelled and slashable like any
//! unmatched intent. After the delay every attestor releases it with the rebuilt script
//! ([`Engine::releases`](super::Engine)).
//!
//! A roll spends rate-limit budget (S-3) like a burn: it waits for an epoch with room for the
//! whole vault, and a vault larger than any epoch's cap cannot be rolled (alarm). Locks this
//! ledger has not judged yet wait; locks refused by policy are never rolled (their owner's
//! recovery is theirs).

use anyhow::{Result, anyhow, ensure};
use hawkeye_core::leader::mint_leader_for;
use hawkeye_core::lock::lock_id;
use hawkeye_core::memo::{HawkeyeMemo, MemoKind, parse_memo_script_for};
use hawkeye_core::template::{OWNER_HEIGHT_MAX, VaultParams, parse_vault};
use hawkeye_store::{IntentState, LockState, SignDomain, VaultRecord, VaultState, YcashSignKey};
use hawkeye_ycash::tx::{Transaction, insert_op_return};
use hawkeye_ycash::types::Recipient;
use hawkeye_ycash::{Amount, ErrorReason, HexBytes};
use tracing::{debug, info, warn};

use super::Engine;
use super::sign::SetSigning;
use crate::convert::{op_core, op_rpc};
use hawkeye_core::setsig::Role;

/// Blocks added to the new `ownerHeight` beyond `MIN_OWNER_AGE + ROLL_MARGIN`.
pub const ROLL_SLACK: u32 = 10;

/// Whether vault `vault` is **orphaned** for burn `burn` in this ledger (review H-2): the burn was
/// paid by another vault's intent, mined at least `C_Y` deep, while `vault` (whose signed unlock
/// for the same burn some member holds) is still in the ledger as a live set vault. Returns the
/// paying intent.
pub(crate) fn orphan_of(
    t: &hawkeye_store::Tx<'_>,
    burn: &hawkeye_store::BurnKey,
    vault: &hawkeye_core::OutPoint,
    tip: u32,
    confirmations: u32,
) -> Result<Option<hawkeye_core::OutPoint>, hawkeye_store::StoreError> {
    use hawkeye_store::BurnState;
    let Some(b) = t.burn(burn)? else {
        return Ok(None);
    };
    if !matches!(b.state, BurnState::IntentConfirmed | BurnState::Released) {
        return Ok(None);
    }
    let Some(op) = b.intent else { return Ok(None) };
    let Some(i) = t.intent(&op)? else {
        return Ok(None);
    };
    let deep = i
        .confirmed_height
        .is_some_and(|h| (tip + 1).saturating_sub(h) >= confirmations);
    if !deep || i.origin_vault.is_none() || i.origin_vault == Some(*vault) {
        return Ok(None);
    }
    let live = t
        .vault(vault)?
        .is_some_and(|v| matches!(v.state, VaultState::Live | VaultState::RollDue));
    Ok(live.then_some(op))
}

/// The `meta` key prefix of the vaults a restored ledger's node wallet signed an unlock of with
/// no record here (review N-2): `restore_orphan/<txid:vout>`.
pub const RESTORE_ORPHAN_PREFIX: &str = "restore_orphan/";

/// The most vaults one restore report may say its event covers (a sanity bound, review R-1).
pub const MAX_RESTORE_REPORT: u32 = 64;
/// The rolling window of the per-reporter restore-report caps, Ycash blocks (~7 days).
pub const RESTORE_WINDOW: u32 = 4_032;
/// Corroborated restored reports accepted per reporter per window (this ledger saw the reporter
/// set-sign a spend of the vault), across all its restore events.
pub const RESTORE_CORROBORATED_CAP: usize = 64;
/// Uncorroborated restored reports accepted per reporter per window, across all its events.
pub const RESTORE_UNCORROBORATED_CAP: usize = 4;
/// `restore_report/<reporter>/<height:010>/<vault>` → `c` | `u`: the restored reports accepted
/// here, by the height they were accepted at (the rolling window).
pub const RESTORE_REPORT_PREFIX: &str = "restore_report/";
/// `restore_rolled/<vault>`: vaults a restored report marked to roll — never marked again.
pub const RESTORE_ROLLED_PREFIX: &str = "restore_rolled/";
/// `restore_lineage/<vault>`: a vault created by the release of the roll of a restore-rolled
/// vault (or of one of its successors) — never marked for a restored report either.
pub const RESTORE_LINEAGE_PREFIX: &str = "restore_lineage/";
/// `restore_flood/<reporter>` → the height of the last refusal for volume (alarm
/// `restore-report-flood`, cleared once the window passes).
pub const RESTORE_FLOOD_PREFIX: &str = "restore_flood/";

/// Whether `member` answered — signed — that its ledger is restored. Only the reporter is asked
/// (its URL learnt from its signed answers and cached), and its answer is cached per reporter for
/// [`crate::peer_auth::RESTORE_ANSWER_TTL`]: bounded by the member count, and a `true` lapses
/// once the reporter has acknowledged its restore. (A malicious member can lie here; the evidence
/// rule and the caps are what bound it.)
async fn reporter_says_restored(ctx: &super::Ctx, member: &hawkeye_core::PubKey33) -> bool {
    {
        let mut cache = ctx
            .auth
            .restore_answers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (_, at)| at.elapsed() < crate::peer_auth::RESTORE_ANSWER_TTL);
        if let Some((v, _)) = cache.get(member) {
            return *v;
        }
    }
    let known = ctx
        .auth
        .peer_url
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(member)
        .cloned();
    let urls: Vec<String> = match known {
        Some(u) => vec![u],
        None => ctx.peers.urls().to_vec(),
    };
    let mut answer = None;
    for peer in urls {
        if let Ok(a) = ctx.peers.burn_unlock(&peer, 0).await
            && let Some(who) = a.responder
        {
            ctx.auth
                .peer_url
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(who, peer.clone());
            if who == *member {
                answer = Some(a.body.restored);
                break;
            }
        }
    }
    let v = answer.unwrap_or(false);
    if answer.is_some() {
        ctx.auth
            .restore_answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(*member, (v, std::time::Instant::now()));
    }
    v
}

/// Whether `vault` descends, through the release of a roll, from a vault a restored report
/// marked (review R-1): the roll's intent has the marked vault as origin and its release creates
/// the successor. Records every successor found (`restore_lineage/`), generation by generation.
pub(crate) fn restore_lineage_contains(
    t: &hawkeye_store::Tx<'_>,
    vault: &hawkeye_core::OutPoint,
) -> Result<bool, hawkeye_store::StoreError> {
    let roots: Vec<String> = t
        .meta_prefix(RESTORE_ROLLED_PREFIX)?
        .into_iter()
        .map(|(k, _)| k[RESTORE_ROLLED_PREFIX.len()..].to_owned())
        .chain(
            t.meta_prefix(RESTORE_LINEAGE_PREFIX)?
                .into_iter()
                .map(|(k, _)| k[RESTORE_LINEAGE_PREFIX.len()..].to_owned()),
        )
        .collect();
    if roots.iter().any(|r| *r == vault.to_string()) {
        return Ok(true);
    }
    let mut frontier: Vec<hawkeye_core::OutPoint> = roots
        .iter()
        .filter_map(|r| super::slash::parse_outpoint(r).ok())
        .collect();
    let mut found = false;
    let mut seen = std::collections::HashSet::new();
    while let Some(x) = frontier.pop() {
        if !seen.insert(x) {
            continue;
        }
        let mut released = vec![];
        for st in [IntentState::Released, IntentState::Matched] {
            for i in t.intents_in_state(st)? {
                if i.origin_vault == Some(x)
                    && i.classification.as_deref() == Some("matched-roll")
                    && let Some(r) = i.released_txid
                {
                    released.push(r);
                }
            }
        }
        for r in released {
            for v in t
                .vaults_in_state(VaultState::Live)?
                .into_iter()
                .chain(t.vaults_in_state(VaultState::RollDue)?)
            {
                if v.outpoint.txid == r {
                    let key = format!("{RESTORE_LINEAGE_PREFIX}{}", v.outpoint);
                    if t.meta(&key)?.is_none() {
                        t.set_meta(&key, &x.to_string())?;
                    }
                    found |= v.outpoint == *vault;
                    frontier.push(v.outpoint);
                }
            }
        }
    }
    Ok(found)
}

/// `POST /vaults/orphaned` with `restored` (review N-2; R-1 as decided 2026-10-13): acted on only
/// with **evidence** — this ledger saw the reporter set-sign a spend of the vault — within
/// [`RESTORE_CORROBORATED_CAP`] per reporter per [`RESTORE_WINDOW`] blocks; without evidence
/// only [`RESTORE_UNCORROBORATED_CAP`] per reporter per window, counted across all its events
/// (a fresh event id resets nothing). Never for a vault a restored report already marked, nor any
/// successor of one (the vault its roll's release created, and so on). The reporter must also
/// say, signed, that it is restored (asked once per event). Refusals for volume are recorded and
/// alarmed (`restore-report-flood`).
async fn verify_restore_report(
    ctx: &super::Ctx,
    requester: hawkeye_core::PubKey33,
    vault: &hawkeye_core::OutPoint,
    req: &crate::peers::OrphanRequest,
) -> Result<crate::peers::OrphanResponse> {
    let rep = hex::encode(requester);
    let tip = ctx.ycash.getblockcount().await?;
    let flood = |why: String| -> anyhow::Error {
        let _ = ctx.db(|t| t.set_meta(&format!("{RESTORE_FLOOD_PREFIX}{rep}"), &tip.to_string()));
        warn!(event = "restore_report_flood", reporter = %rep, reason = %why);
        anyhow!("{why}")
    };
    ensure!(
        !req.event.is_empty()
            && req.event.len() <= 64
            && req.event.bytes().all(|b| b.is_ascii_hexdigit()),
        "a restore report names its restore event (hex)"
    );
    if req.count == 0 || req.count > MAX_RESTORE_REPORT {
        return Err(flood(format!(
            "a restore event reports {} vaults: 1..={MAX_RESTORE_REPORT}",
            req.count
        )));
    }
    let (already, corroborated, window) = ctx.db(|t| {
        let already = t
            .meta(&format!("{RESTORE_ROLLED_PREFIX}{vault}"))?
            .is_some()
            || restore_lineage_contains(t, vault)?;
        let corroborated = t.seen_set_sig_by(&ctx.params.set_id, vault, &requester)?;
        let from = tip.saturating_sub(RESTORE_WINDOW);
        let window: Vec<(String, String)> = t
            .meta_prefix(&format!("{RESTORE_REPORT_PREFIX}{rep}/"))?
            .into_iter()
            .filter(|(k, _)| {
                k.split('/')
                    .nth(2)
                    .and_then(|h| h.parse::<u32>().ok())
                    .is_some_and(|h| h > from)
            })
            .collect();
        Ok((already, corroborated, window))
    })?;
    ensure!(
        !already,
        "vault {vault} was already rolled for a restored report (or descends from such a roll)"
    );
    let kind = if corroborated { "c" } else { "u" };
    let used = window.iter().filter(|(_, v)| v == kind).count();
    let cap = if corroborated {
        RESTORE_CORROBORATED_CAP
    } else {
        RESTORE_UNCORROBORATED_CAP
    };
    if used >= cap {
        return Err(flood(format!(
            "{rep} already made {used} {} restored reports in the last {RESTORE_WINDOW} blocks \
             (cap {cap})",
            if corroborated {
                "corroborated"
            } else {
                "uncorroborated"
            }
        )));
    }
    // only now (a reporter over its cap triggers no outbound request): does it say it is restored?
    ensure!(
        reporter_says_restored(ctx, &requester).await,
        "the reporter's own signed /burns/unlock answer does not show its ledger restored"
    );
    let op = op_rpc(vault);
    ensure!(
        ctx.ycash.gettxout(&op.txid, op.vout, true).await?.is_some(),
        "vault {vault} is spent"
    );
    let marked = ctx.db(|t| {
        t.set_meta(
            &format!("{RESTORE_REPORT_PREFIX}{rep}/{tip:010}/{vault}"),
            kind,
        )?;
        let m = mark_orphan(t, vault, 0, tip)?;
        t.set_meta(&format!("{RESTORE_ROLLED_PREFIX}{vault}"), &rep)?;
        Ok(m)
    })?;
    warn!(event = "orphan_marked_restored", vault = %vault, reporter = %rep,
          restore_event = %req.event, corroborated, marked);
    Ok(crate::peers::OrphanResponse { marked })
}

/// Mark an orphaned vault `ROLL_DUE` (from `LIVE`): its roll leader — never a member that signed
/// it — rolls it now, which spends it, so the orphaned signed unlock dies (review H-2).
pub(crate) fn mark_orphan(
    t: &hawkeye_store::Tx<'_>,
    vault: &hawkeye_core::OutPoint,
    nonce: u64,
    tip: u32,
) -> Result<bool, hawkeye_store::StoreError> {
    mark_due(
        t,
        vault,
        tip,
        &format!("orphaned signed unlock of burn {nonce}: rolled so it can never confirm"),
    )
}

/// Mark a vault `ROLL_DUE` because a signed unlock of it can no longer confirm (W4-B-2, W4-B-5).
pub(crate) fn mark_unconfirmable(
    t: &hawkeye_store::Tx<'_>,
    vault: &hawkeye_core::OutPoint,
    nonce: u64,
    tip: u32,
    why: &str,
) -> Result<bool, hawkeye_store::StoreError> {
    let kind = if why.contains("old branch") {
        "old branch"
    } else {
        "departed signer"
    };
    mark_due(
        t,
        vault,
        tip,
        &format!(
            "unconfirmable signed unlock of burn {nonce} ({kind}): rolled so it can never confirm"
        ),
    )
}

fn mark_due(
    t: &hawkeye_store::Tx<'_>,
    vault: &hawkeye_core::OutPoint,
    tip: u32,
    detail: &str,
) -> Result<bool, hawkeye_store::StoreError> {
    if t.vault(vault)?.is_some_and(|v| v.state == VaultState::Live) {
        t.transition_vault(vault, VaultState::RollDue, Some(tip), Some(detail))?;
        return Ok(true);
    }
    Ok(false)
}

/// The height a roll's takeover counts from: when the vault fell due by `ROLL_MARGIN` (or was
/// created, if born due) — or, earlier, when it was marked `ROLL_DUE` for another reason (an
/// orphaned signed unlock, review H-2: the vault is rolled so the old bytes die).
pub fn roll_due_from(owner_height: u32, margin: u32, created: u32, marked: Option<u32>) -> u32 {
    let natural = owner_height.saturating_sub(margin).max(created);
    marked.map_or(natural, |m| natural.min(m))
}

/// The new `ownerHeight` a roll at `tip` writes.
pub fn rolled_owner_height(tip: u32, min_owner_age: u32, roll_margin: u32) -> u32 {
    tip.saturating_add(1)
        .saturating_add(min_owner_age)
        .saturating_add(roll_margin)
        .saturating_add(ROLL_SLACK)
}

impl Engine {
    /// The sign-once key of a vault's unlock.
    fn unlock_key(&self, vault: &hawkeye_core::OutPoint) -> YcashSignKey {
        YcashSignKey {
            domain: SignDomain::YcashUnlock,
            set_id: self.ctx.params.set_id,
            prevout: *vault,
        }
    }

    /// One rolls pass: mark due vaults, re-send rolls in flight, post the rolls this attestor
    /// leads, raise the alarms.
    pub(crate) async fn rolls(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let p = self.ctx.params.clone();
        let margin = p.roll_margin;
        let newly_due = self.ctx.db(|t| {
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
            Ok(due)
        })?;
        for v in &newly_due {
            warn!(event = "roll_due", vault = %v.outpoint, owner_height = v.owner_height, tip);
        }
        // the value a matched roll intent holds while it waits for its release (supply check)
        self.mem.roll_value_pending = self.ctx.db(|t| {
            Ok(t.intents_in_state(IntentState::Matched)?
                .iter()
                .filter(|i| i.classification.as_deref() == Some("matched-roll"))
                .map(|i| i.value_zat)
                .sum())
        })?;
        let due_now = self.ctx.db(|t| t.vaults_in_state(VaultState::RollDue))?;
        self.note_pinned(&due_now).await?;
        if self.is_current_member() && !self.signing_paused() {
            self.resend_rolls().await?;
            self.post_rolls().await?;
        }
        let due = self.ctx.db(|t| t.vaults_in_state(VaultState::RollDue))?;
        let overdue: Vec<String> = due
            .iter()
            .filter(|v| v.owner_height <= tip.saturating_add(margin / 2))
            .map(|v| format!("{} (ownerHeight {})", v.outpoint, v.owner_height))
            .collect();
        if overdue.is_empty() {
            self.clear_alarm("roll-overdue");
        } else {
            self.alarm(
                "roll-overdue",
                format!(
                    "vaults past half their ROLL_MARGIN without a roll (HK-6): {}",
                    overdue.join(", ")
                ),
            );
        }
        Ok(())
    }

    /// Orphaned signed unlocks this attestor holds (review H-2): a burn paid by another vault
    /// while the vault of the unlock it signed for it is unspent. Those bytes stay revivable
    /// (01/V-2) — a second payment of the burn — until the vault is spent, which this attestor
    /// can never do itself (sign-once per vault). So it marks the vault `ROLL_DUE` and tells the
    /// other members (`POST /vaults/orphaned`, every 20 ticks), whose roll leader rolls it.
    pub(crate) async fn orphans(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        // review R-1: a reporter refused for volume, within the window (older refusals expire);
        // and the lineage of restore-rolled vaults, followed as their rolls are released
        let floods = self.ctx.db(|t| {
            for (k, v) in t.meta_prefix(RESTORE_FLOOD_PREFIX)? {
                if v.parse::<u32>()
                    .map_or(true, |h| tip.saturating_sub(h) > RESTORE_WINDOW)
                {
                    t.delete_meta_prefix(&k)?;
                }
            }
            // reports older than the window no longer count: drop them (review nit)
            let from = tip.saturating_sub(RESTORE_WINDOW);
            for (k, _) in t.meta_prefix(RESTORE_REPORT_PREFIX)? {
                if k.split('/')
                    .nth(2)
                    .and_then(|h| h.parse::<u32>().ok())
                    .is_none_or(|h| h <= from)
                {
                    t.delete_meta_prefix(&k)?;
                }
            }
            let _ = restore_lineage_contains(t, &hawkeye_core::OutPoint::new([0; 32], 0))?;
            t.meta_prefix(RESTORE_FLOOD_PREFIX)
        })?;
        if floods.is_empty() {
            self.clear_alarm("restore-report-flood");
        } else {
            self.alarm(
                "restore-report-flood",
                format!(
                    "restored-ledger orphan reports refused for volume from {}",
                    floods
                        .iter()
                        .map(|(k, _)| &k[RESTORE_FLOOD_PREFIX.len()..])
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        // review R-3: observed unlocks of a burn released C_Y deep are no longer needed
        let observed = self.ctx.db(|t| t.meta_prefix("observed_unlock/"))?;
        let mut done = std::collections::BTreeSet::new();
        for (k, _) in observed {
            let Some(burn) = k
                .strip_prefix("observed_unlock/")
                .and_then(|r| r.rsplit_once('/'))
                .map(|(b, _)| b.to_owned())
            else {
                continue;
            };
            let Some(nonce) = burn.rsplit(':').next().and_then(|n| n.parse::<u64>().ok()) else {
                continue;
            };
            let key = hawkeye_store::BurnKey::new(p.deployment, nonce);
            if key.to_string() != burn || done.contains(&nonce) {
                continue;
            }
            let released_deep = self.ctx.db(|t| {
                let Some(b) = t.burn(&key)? else {
                    return Ok(false);
                };
                if b.state != hawkeye_store::BurnState::Released {
                    return Ok(false);
                }
                let h = match b.intent {
                    Some(op) => t.intent(&op)?.and_then(|i| i.released_height),
                    None => None,
                };
                Ok(h.is_some_and(|h| (tip + 1).saturating_sub(h) >= p.confirmations))
            })?;
            if released_deep {
                done.insert(nonce);
                let n = self
                    .ctx
                    .db(|t| t.delete_meta_prefix(&super::ycash::observed_unlock_prefix(&key)))?;
                debug!(event = "observed_unlock_pruned", nonce, records = n);
            }
        }
        self.retire_unconfirmable().await?;
        let rows = self.ctx.db(|t| t.live_unlock_rows(&p.set_id))?;
        for r in rows {
            let Some(paid_by) = self
                .ctx
                .db(|t| orphan_of(t, &r.key, &r.prevout, tip, p.confirmations))?
            else {
                continue;
            };
            let op = op_rpc(&r.prevout);
            if self
                .ctx
                .ycash
                .gettxout(&op.txid, op.vout, true)
                .await?
                .is_none()
            {
                continue;
            }
            if self
                .ctx
                .db(|t| mark_orphan(t, &r.prevout, r.key.nonce, tip))?
            {
                warn!(event = "unlock_orphaned", nonce = r.key.nonce, vault = %r.prevout,
                      paid_by = %paid_by, "the burn was paid by another vault: rolling this one");
            }
            let last = self.mem.orphan_reported.get(&r.prevout).copied();
            if last.is_some_and(|t| self.mem.ticks < t + 20) {
                continue;
            }
            self.mem.orphan_reported.insert(r.prevout, self.mem.ticks);
            let req = crate::peers::OrphanRequest {
                nonce: r.key.nonce,
                vault: r.prevout.to_string(),
                restored: false,
                count: 0,
                event: String::new(),
            };
            for peer in self.ctx.peers.urls().to_vec() {
                match self.ctx.peers.orphaned(&peer, &req).await {
                    Ok(a) => info!(event = "orphan_reported", peer = %peer, vault = %r.prevout,
                                   marked = a.body.marked),
                    Err(e) => info!(event = "orphan_report_failed", peer = %peer, error = %e),
                }
            }
        }
        // review N-2: vaults the node wallet signed an unlock of that a restored ledger has no
        // record of (restore::check_restore): rolled, whatever burn those bytes pay, until spent
        let restore_orphans = self.ctx.db(|t| t.meta_prefix(RESTORE_ORPHAN_PREFIX))?;
        let restore_count = u32::try_from(restore_orphans.len()).unwrap_or(u32::MAX);
        let restore_event = hex::encode(
            &hawkeye_core::bytes::sha256(
                self.ctx
                    .db(|t| t.meta(super::burn::LEDGER_RESTORED))?
                    .unwrap_or_default()
                    .as_bytes(),
            )[..16],
        );
        for (k, _) in restore_orphans {
            let Ok(vault) = super::slash::parse_outpoint(&k[RESTORE_ORPHAN_PREFIX.len()..]) else {
                continue;
            };
            let op = op_rpc(&vault);
            if self
                .ctx
                .ycash
                .gettxout(&op.txid, op.vout, true)
                .await?
                .is_none()
            {
                continue;
            }
            self.ctx.db(|t| mark_orphan(t, &vault, 0, tip))?;
            let last = self.mem.orphan_reported.get(&vault).copied();
            if last.is_some_and(|t| self.mem.ticks < t + 20) {
                continue;
            }
            self.mem.orphan_reported.insert(vault, self.mem.ticks);
            let req = crate::peers::OrphanRequest {
                nonce: 0,
                vault: vault.to_string(),
                restored: true,
                count: restore_count,
                event: restore_event.clone(),
            };
            for peer in self.ctx.peers.urls().to_vec() {
                let _ = self.ctx.peers.orphaned(&peer, &req).await;
            }
        }
        Ok(())
    }

    /// Rolls this attestor signed whose unlock is neither mined nor in the mempool: re-send the
    /// stored bytes (sign-once: never rebuilt, never re-signed).
    async fn resend_rolls(&mut self) -> Result<()> {
        let rolling = self.ctx.db(|t| t.vaults_in_state(VaultState::Rolling))?;
        for v in rolling {
            if self.mem.mempool_spent.contains(&v.outpoint) {
                continue;
            }
            let legacy = format!("legacy_roll/{}", v.outpoint);
            if let Some(hex) = self.ctx.db(|t| t.meta(&legacy))? {
                self.send_roll(&v, &hex).await?;
                continue;
            }
            let key = self.unlock_key(&v.outpoint);
            let Some(rec) = self.ctx.db(|t| t.ycash_signature(&key))? else {
                continue;
            };
            let hex = match self.complete_unlock(&rec.signed_hex).await? {
                Some(h) => h,
                None => continue,
            };
            self.send_roll(&v, &hex).await?;
        }
        Ok(())
    }

    async fn post_rolls(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let p = self.ctx.params.clone();
        let due = self.ctx.db(|t| t.vaults_in_state(VaultState::RollDue))?;
        let mut available = self
            .mem
            .set
            .as_ref()
            .and_then(|s| s.set.unlockavailable)
            .map(|a| u64::try_from(a.zat()).unwrap_or(0));
        let mut blocked = vec![];
        for v in due {
            let lock = self.ctx.db(|t| t.lock_by_outpoint(&v.outpoint))?;
            match lock.map(|l| l.state) {
                Some(LockState::Seen | LockState::Confirmed) => continue, // judged first
                Some(LockState::PolicyRejected | LockState::Reorged) => {
                    if self.mem.roll_logged.insert(v.outpoint) {
                        info!(event = "roll_never", vault = %v.outpoint,
                              reason = "a lock refused by policy (or reorged) is its owner's to recover");
                    }
                    continue;
                }
                _ => {}
            }
            if self.mem.mempool_spent.contains(&v.outpoint)
                || self.our_unlock_signature(&v.outpoint).await?
            {
                continue; // being spent, or this member signed another spend of it
            }
            // takeover counts from the moment it fell due (or was created, if born due)
            let marked = self.ctx.db(|t| t.vault_due_height(&v.outpoint))?;
            let due_from = roll_due_from(v.owner_height, p.roll_margin, v.created_height, marked);
            let since = tip.saturating_sub(due_from);
            let Some(leader) =
                mint_leader_for(&lock_id(&v.outpoint), self.live(), since, p.takeover)
            else {
                continue;
            };
            if *leader != self.ctx.me {
                continue;
            }
            if let Some(av) = available {
                if v.value_zat > av {
                    blocked.push(format!(
                        "{} ({} zat > {av} available)",
                        v.outpoint, v.value_zat
                    ));
                    continue;
                }
                available = Some(av - v.value_zat);
            }
            if let Err(e) = self.post_roll(&v).await {
                warn!(event = "roll_failed", vault = %v.outpoint, error = %format!("{e:#}"));
                self.note_sign_error(&e);
            }
        }
        if blocked.is_empty() {
            self.clear_alarm("roll-waiting-cap");
        } else {
            self.alarm(
                "roll-waiting-cap",
                format!(
                    "rolls wait for rate-limit room (S-3): {}",
                    blocked.join(", ")
                ),
            );
        }
        Ok(())
    }

    /// vault_buildunlock (the whole vault to the new V) → kind-2 memo → set_signunlock
    /// (sign-once) → `ROLLING` → vault_send.
    async fn post_roll(&mut self, v: &VaultRecord) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let (spk, value) = self
            .vault_coin(&v.outpoint)
            .await?
            .ok_or_else(|| anyhow!("vault script unknown"))?;
        let spent = parse_vault(&spk).map_err(|e| anyhow!("vault script: {e}"))?;
        let owner_height = rolled_owner_height(tip, p.min_owner_age, p.roll_margin);
        ensure!(owner_height <= OWNER_HEIGHT_MAX, "ownerHeight out of range");
        let new = VaultParams {
            owner_height,
            app_height: 0,
            ..spent
        };
        ensure!(
            spent.app_height == 0,
            "the vault has an APP branch: not a bridge vault"
        );
        let new_spk = new.script().map_err(|e| anyhow!("new vault: {e}"))?;
        let memo = HawkeyeMemo::roll_for(p.bridge_kind, p.deployment, &new)
            .map_err(|e| anyhow!("memo: {e}"))?;
        let key = self.unlock_key(&v.outpoint);
        let unsigned_here = self.ctx.db(|t| t.ycash_signature(&key))?.is_none();
        let built = super::sign::build_unlock(
            &self.ctx.ycash,
            &op_rpc(&v.outpoint),
            &[Recipient::script(
                new_spk,
                Amount::from_zat(i64::try_from(value)?),
            )],
            unsigned_here,
        )
        .await?;
        let with_memo = insert_op_return(&built.hex.to_string(), &memo.encode())
            .map_err(|e| anyhow!("memo: {e}"))?;
        // no change output: whoever ever funds these bytes pays the fee only (H-1)
        let with_memo =
            super::sign::fund_exactly(&self.ctx.ycash, &with_memo, &v.outpoint, value).await?;
        let signer = SetSigning::prepare(&self.ctx, &with_memo, Role::Unlock, v.outpoint).await?;
        let legacy_key = format!("legacy_adoption/{}", v.outpoint);
        if self.ctx.db(|t| t.meta(&legacy_key))?.is_some() {
            let stored = format!("legacy_roll/{}", v.outpoint);
            if let Some(hex) = self.ctx.db(|t| t.meta(&stored))? {
                return self.send_roll(v, &hex).await;
            }
            let signed = signer.sign(&with_memo).map_err(|e| anyhow!(e))?;
            self.ctx.db(|t| {
                t.set_meta(&stored, &signed.hex)?;
                t.transition_vault(
                    &v.outpoint,
                    VaultState::Rolling,
                    Some(tip),
                    Some(&format!("roll to ownerHeight {owner_height}")),
                )?;
                Ok(())
            })?;
            warn!(event = "roll_signed", vault = %v.outpoint, value,
                  old_owner_height = v.owner_height, new_owner_height = owner_height,
                  "legacy adoption record: the roll is signed once into the ledger metadata");
            return self.send_roll(v, &signed.hex).await;
        }
        let branch = signer.branch_id();
        let signed_height = tip;
        let rec = self.ctx.db(|t| {
            // a roll pays no burn: per vault only
            let rec = t.sign_once_unlock_at(
                &key,
                None,
                &with_memo,
                Some(branch),
                Some(signed_height),
                |h| {
                    let o = signer.sign(h)?;
                    Ok::<_, String>((o.hex, o.sighash))
                },
            )?;
            t.transition_vault(
                &v.outpoint,
                VaultState::Rolling,
                Some(tip),
                Some(&format!("roll to ownerHeight {owner_height}")),
            )?;
            Ok(rec)
        })?;
        warn!(event = "roll_signed", vault = %v.outpoint, value, old_owner_height = v.owner_height,
              new_owner_height = owner_height);
        let Some(hex) = self.complete_unlock(&rec.signed_hex).await? else {
            return Ok(());
        };
        self.send_roll(v, &hex).await
    }

    /// This member signed a spend of `vault` (a `ycash-unlock` record that recovers to this
    /// key). A record with none of this member's signatures is a pre-fix adoption: it does not
    /// block the roll (W4-B-2).
    async fn our_unlock_signature(&mut self, vault: &hawkeye_core::OutPoint) -> Result<bool> {
        let key = self.unlock_key(vault);
        let Some(rec) = self.ctx.db(|t| t.ycash_signature(&key))? else {
            return Ok(false);
        };
        let legacy = format!("legacy_adoption/{vault}");
        if self.ctx.db(|t| t.meta(&legacy))?.is_some() {
            return Ok(false);
        }
        let Ok(tx) = Transaction::decode_hex(&rec.signed_hex) else {
            return Ok(true);
        };
        let Some(coin) = self.vault_coin(vault).await? else {
            return Ok(true);
        };
        match self.attribute_under(&tx, vault, &coin, rec.branch_id).await {
            Ok(a) if a.signers.iter().any(|s| s.pubkey == self.ctx.me) => Ok(true),
            Ok(_) => {
                self.ctx.db(|t| t.set_meta(&legacy, "1"))?;
                self.alarm(
                    "legacy_adoption_row",
                    format!(
                        "vault {vault}: the stored unlock has no signature of this member \
                         (an adoption recorded before W4-B-2); it does not block a roll"
                    ),
                );
                Ok(false)
            }
            Err(_) => Ok(true),
        }
    }

    /// `ROLL_DUE` vaults this member signed and so cannot roll (W4-B-2 §4.7).
    async fn note_pinned(&mut self, due: &[VaultRecord]) -> Result<()> {
        let tip = self.mem.tip;
        let margin = self.ctx.params.roll_margin;
        let set = self.ctx.params.set_id;
        let mut pinned = vec![];
        let mut pages = vec![];
        for v in due {
            if !self.our_unlock_signature(&v.outpoint).await? {
                continue;
            }
            let burn = self.ctx.db(|t| {
                Ok(t.unlock_burns_of_vault(&set, &v.outpoint)?
                    .into_iter()
                    .find(|r| r.origin != hawkeye_store::UnlockOrigin::Drill)
                    .map(|r| r.key.nonce.to_string())
                    .unwrap_or_else(|| "unknown".into()))
            })?;
            let left = v.owner_height.saturating_sub(tip);
            if left <= margin / 2 && !self.mem.mempool_spent.contains(&v.outpoint) {
                pages.push(format!(
                    "vault {} (owner height {}, {left} blocks left) cannot be rolled by this \
                     member (it signed burn {burn}'s unlock of it); check that another member \
                     rolls it",
                    v.outpoint, v.owner_height
                ));
            }
            pinned.push(crate::status::PinnedVault {
                vault: v.outpoint.to_string(),
                burn,
                owner_height: v.owner_height,
                blocks_left: left,
            });
        }
        self.mem.pinned_vaults = pinned;
        if pages.is_empty() {
            self.clear_alarm("vault-pinned");
        } else {
            self.alarm("vault-pinned", pages.join("; "));
        }
        Ok(())
    }

    async fn send_roll(&mut self, v: &VaultRecord, signed: &str) -> Result<()> {
        let p = self.ctx.params.clone();
        let tx = Transaction::decode_hex(signed).map_err(|e| anyhow!("{e}"))?;
        let is_roll = tx.outputs.iter().any(|o| {
            matches!(parse_memo_script_for(p.bridge_kind, &o.script_pubkey), Ok(Some(m))
                if m.kind == MemoKind::Roll && m.is_for(p.bridge_kind, &p.deployment))
        });
        if !is_roll {
            return Ok(()); // the vault's stored unlock pays a burn: burns() owns it
        }
        let hex: HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
        let txid = match super::sign::send_set_signed(&self.ctx.ycash, &hex, &v.outpoint).await {
            Ok(t) => t,
            Err(e) if e.rpc().is_some_and(|r| r.is_already_known()) => return Ok(()),
            Err(e) if matches!(e.reason(), Some(ErrorReason::Rejected { ref reason, .. }) if reason.contains("vault-rate")) =>
            {
                if self.mem.roll_logged.insert(v.outpoint) {
                    info!(event = "roll_waiting_cap", vault = %v.outpoint, reason = "bad-txns-vault-rate");
                }
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        warn!(event = "roll_sent", vault = %v.outpoint, txid = %txid, value = v.value_zat);
        let raw = self.ctx.ycash.getrawtransaction(&txid).await?;
        let tx = Transaction::decode(raw.as_slice()).map_err(|e| anyhow!("{e}"))?;
        if let Some(obs) = self.prepare_unlock(&tx, raw.as_slice(), None).await? {
            let tip = self.mem.tip;
            let members = self.current_member_keys();
            self.mem.mempool_seen.insert(obs.txid);
            for i in &tx.inputs {
                self.mem.mempool_spent.insert(op_core(&i.prevout));
            }
            self.note_signatures(&obs).await;
            self.ctx
                .db(|t| super::ycash::apply_unlock(t, &p, &obs, tip, tip, None, &members))?;
        }
        Ok(())
    }
}

/// `POST /vaults/orphaned` (authenticated): mark a vault orphaned here only if this ledger itself
/// shows the burn paid by another vault `C_Y` deep while the vault is live (review H-2).
pub async fn verify_orphan(
    ctx: &super::Ctx,
    requester: Option<hawkeye_core::PubKey33>,
    req: &crate::peers::OrphanRequest,
) -> Result<crate::peers::OrphanResponse> {
    let requester = requester.ok_or_else(|| anyhow!("member-signed requests only"))?;
    let vault = super::slash::parse_outpoint(&req.vault)?;
    if req.restored {
        return verify_restore_report(ctx, requester, &vault, req).await;
    }
    let k = hawkeye_store::BurnKey::new(ctx.params.deployment, req.nonce);
    let tip = ctx.ycash.getblockcount().await?;
    let conf = ctx.params.confirmations;
    let paid_by = ctx
        .db(|t| orphan_of(t, &k, &vault, tip, conf))?
        .ok_or_else(|| {
            anyhow!(
                "vault {vault} is not orphaned here: burn {} is not paid by another vault C_Y \
                 deep, or the vault is not live",
                req.nonce
            )
        })?;
    let op = op_rpc(&vault);
    ensure!(
        ctx.ycash.gettxout(&op.txid, op.vout, true).await?.is_some(),
        "vault {vault} is spent"
    );
    let marked = ctx.db(|t| mark_orphan(t, &vault, req.nonce, tip))?;
    info!(event = "orphan_marked", vault = %vault, nonce = req.nonce, paid_by = %paid_by,
          requester = %hex::encode(requester), marked);
    Ok(crate::peers::OrphanResponse { marked })
}
