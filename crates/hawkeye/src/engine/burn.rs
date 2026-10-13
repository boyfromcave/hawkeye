//! The burn side (plan §1.3, §5.2, §5.5): leader assignment and takeover, the rate limit, the
//! unlock with its `HKB1` memo (sign-once), and the release after the delay.

use anyhow::{Result, anyhow};
use hawkeye_core::address::encode_address;
use hawkeye_core::leader::leader_for;
use hawkeye_core::memo::{HawkeyeMemo, parse_memo_script_for};
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::template::{TemplateKind, parse_selector, parse_vault};
use hawkeye_store::{
    BurnRecord, BurnState, IntentState, OVER_CAP_EPOCH, SignDomain, VaultRecord, VaultState,
    YcashSignKey,
};
use hawkeye_ycash::tx::{Transaction, insert_op_return};
use hawkeye_ycash::types::{Recipient, Set};
use hawkeye_ycash::{Amount, ErrorReason, HexBytes};
use tracing::{debug, info, warn};

use super::{Engine, block_on};
use crate::convert::{op_core, op_rpc};

impl Engine {
    /// Assign, take over, wait for the cap, and (as leader) post the unlock of every finalized
    /// burn, FIFO by nonce. A burn larger than the set's whole per-window cap (audit 05/M-2) is
    /// parked out of the FIFO on every attestor's ledger with alarm `burn-over-cap`, so later
    /// nonces are served; it is released when the set's cap rises to its amount.
    pub(crate) async fn burns(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let dep = p.deployment;
        let tip = self.mem.tip;
        let epoch = self.mem.set.as_ref().map_or(0, |s| s.set.epoch);
        let epoch_u = u64::try_from(epoch).unwrap_or(0);
        // `None`: the set is unknown (nothing is judged over cap, nothing over cap is released);
        // `Some(None)`: no rate limit; `Some(Some(cap))`: the full-window cap
        let full = self.mem.set.as_ref().map(|s| full_window_cap(&s.set));
        let over = |amount: u64| matches!(full, Some(Some(cap)) if amount > cap);
        let live = self.live().to_vec();
        self.ctx.db(|t| {
            for b in t.burns_in_state(&dep, BurnState::WaitingCap)? {
                if b.over_cap() {
                    // over cap: released only by a cap change, never by an epoch turn
                    if full.is_some() && !over(b.amount) {
                        t.transition_burn(
                            &b.key,
                            BurnState::Finalized,
                            Some(tip.into()),
                            Some("cap raised: within the set's full-window cap"),
                        )?;
                        info!(event = "burn_over_cap_released", nonce = b.key.nonce,
                              amount = b.amount, cap = ?full.flatten());
                    }
                } else if b.waiting_epoch != Some(epoch_u) {
                    // the epoch turned: waiting burns are up again
                    t.transition_burn(
                        &b.key,
                        BurnState::Finalized,
                        Some(tip.into()),
                        Some("new epoch"),
                    )?;
                    info!(event = "burn_cap_released", nonce = b.key.nonce, epoch);
                }
            }
            for s in [BurnState::Finalized, BurnState::Assigned] {
                for b in t.burns_in_state(&dep, s)? {
                    if over(b.amount) {
                        t.burn_wait_cap(&b.key, OVER_CAP_EPOCH, Some(tip))?;
                        warn!(event = "burn_over_cap", nonce = b.key.nonce, amount = b.amount,
                              cap = ?full.flatten(), "parked out of the FIFO until the set's cap rises");
                    }
                }
            }
            for b in t.burns_in_state(&dep, BurnState::Finalized)? {
                if let Some(l) = leader_for(b.key.nonce, &live, 0, p.takeover) {
                    t.assign_burn(&b.key, l, tip)?;
                    info!(event = "burn_assigned", nonce = b.key.nonce, leader = %hex::encode(l),
                          mine = *l == self.ctx.me);
                }
            }
            for b in t.burns_in_state(&dep, BurnState::Assigned)? {
                let (Some(h), Some(cur)) = (b.assigned_height, b.leader) else {
                    continue;
                };
                if p.takeover == 0 || tip < h + p.takeover || live.is_empty() {
                    continue;
                }
                let next = match live.iter().position(|k| *k == cur) {
                    Some(i) => live[(i + 1) % live.len()],
                    None => *leader_for(b.key.nonce, &live, 0, p.takeover).expect("live"),
                };
                t.assign_burn(&b.key, &next, tip)?;
                warn!(event = "burn_takeover", nonce = b.key.nonce, from = %hex::encode(cur),
                      to = %hex::encode(next), mine = next == self.ctx.me);
            }
            Ok(())
        })?;
        self.over_cap_alarm()?;
        if !self.is_current_member() {
            return Ok(());
        }
        let assigned: Vec<BurnRecord> = self
            .ctx
            .db(|t| t.burns_in_state(&dep, BurnState::Assigned))?
            .into_iter()
            .filter(|b| b.leader == Some(self.ctx.me))
            .collect();
        let available = self
            .mem
            .set
            .as_ref()
            .and_then(|s| s.set.unlockavailable)
            .map(|a| u64::try_from(a.zat()).unwrap_or(0));
        let amounts: Vec<u64> = assigned.iter().map(|b| b.amount).collect();
        let plan = cap_plan(&amounts, available, full.flatten());
        for (b, step) in assigned.iter().zip(plan) {
            match step {
                CapStep::Post => {
                    if let Err(e) = self.post_unlock(b).await {
                        warn!(event = "unlock_failed", nonce = b.key.nonce, error = %format!("{e:#}"));
                    }
                }
                CapStep::OverCap => {
                    // parked above already; kept for a cap read between the two steps
                    self.ctx
                        .db(|t| t.burn_wait_cap(&b.key, OVER_CAP_EPOCH, Some(tip)))?;
                }
                CapStep::WaitEpoch => {
                    self.ctx
                        .db(|t| t.burn_wait_cap(&b.key, epoch_u, Some(tip)))?;
                    info!(
                        event = "burn_waiting_cap",
                        nonce = b.key.nonce,
                        amount = b.amount,
                        available = ?available,
                        epoch
                    );
                }
                CapStep::Behind => {} // FIFO: later burns wait behind it
            }
        }
        Ok(())
    }

    /// Raise `burn-over-cap` while any burn of this deployment is parked over cap; clear it once
    /// none is.
    fn over_cap_alarm(&mut self) -> Result<()> {
        let dep = self.ctx.params.deployment;
        let parked: Vec<BurnRecord> = self
            .ctx
            .db(|t| t.burns_in_state(&dep, BurnState::WaitingCap))?
            .into_iter()
            .filter(BurnRecord::over_cap)
            .collect();
        if parked.is_empty() {
            self.clear_alarm("burn-over-cap");
            return Ok(());
        }
        let (bps, basis, cap) = self.mem.set.as_ref().map_or((0, 0, None), |s| {
            (
                s.set.params.ratelimitbps,
                cap_basis(&s.set),
                full_window_cap(&s.set),
            )
        });
        let list: Vec<String> = parked
            .iter()
            .map(|b| format!("{} ({} zat)", b.key.nonce, b.amount))
            .collect();
        self.alarm(
            "burn-over-cap",
            format!(
                "burn(s) {} exceed the set's full-window cap {} zat (ratelimitbps {bps}, basis \
                 {basis} zat); they wait for a governance change (SET_PARAMS raising \
                 ratelimitbps) while later burns are served",
                list.join(", "),
                cap.map_or_else(|| "none".to_owned(), |c| c.to_string()),
            ),
        );
        Ok(())
    }

    /// The signed unlock for burn `nonce` this attestor already holds, on a vault still live.
    fn signed_unlock_for(&self, nonce: u64, vaults: &[VaultRecord]) -> Result<Option<String>> {
        let set = self.ctx.params.set_id;
        for v in vaults {
            let key = YcashSignKey {
                domain: SignDomain::YcashUnlock,
                set_id: set,
                prevout: v.outpoint,
            };
            let Some(rec) = self.ctx.db(|t| t.ycash_signature(&key))? else {
                continue;
            };
            let Ok(tx) = Transaction::decode_hex(&rec.signed_hex) else {
                continue;
            };
            let p = &self.ctx.params;
            let names = tx.outputs.iter().any(|o| {
                matches!(parse_memo_script_for(p.bridge_kind, &o.script_pubkey), Ok(Some(m))
                    if m.reference == nonce && m.is_for(p.bridge_kind, &p.deployment))
            });
            if names {
                return Ok(Some(rec.signed_hex));
            }
        }
        Ok(None)
    }

    /// vault_buildunlock → memo → set_signunlock (sign-once) → vault_send, then observe it.
    async fn post_unlock(&mut self, b: &BurnRecord) -> Result<()> {
        let p = self.ctx.params.clone();
        let nonce = b.key.nonce;
        let recipient =
            YcashRecipient::from_bytes(&b.recipient).map_err(|e| anyhow!("recipient: {e}"))?;
        let vaults: Vec<VaultRecord> = self.ctx.db(|t| {
            let mut v = t.vaults_in_state(VaultState::Live)?;
            v.extend(t.vaults_in_state(VaultState::RollDue)?);
            v.sort_by_key(|x| x.owner_height);
            Ok(v)
        })?;
        let signed = match self.signed_unlock_for(nonce, &vaults)? {
            Some(h) => {
                info!(event = "unlock_resend", nonce);
                match self.complete_unlock(&h).await? {
                    Some(h) => h,
                    None => return Ok(()),
                }
            }
            None => {
                let mut chosen = None;
                for v in &vaults {
                    if v.value_zat < b.amount || self.mem.mempool_spent.contains(&v.outpoint) {
                        continue;
                    }
                    let key = YcashSignKey {
                        domain: SignDomain::YcashUnlock,
                        set_id: p.set_id,
                        prevout: v.outpoint,
                    };
                    if self.ctx.db(|t| t.ycash_signature(&key))?.is_some() {
                        continue; // signed for another spend: busy until it is spent
                    }
                    chosen = Some((v.clone(), key));
                    break;
                }
                let Some((vault, key)) = chosen else {
                    if self.mem.no_vault_logged.insert(nonce) {
                        warn!(event = "unlock_no_vault", nonce, amount = b.amount);
                    }
                    return Ok(());
                };
                let built = self
                    .ctx
                    .ycash
                    .vault_buildunlock(
                        &op_rpc(&vault.outpoint),
                        &[Recipient::script(
                            recipient.script(),
                            Amount::from_zat(i64::try_from(b.amount)?),
                        )],
                    )
                    .await?;
                let memo =
                    HawkeyeMemo::burn_release_for(p.bridge_kind, p.deployment, nonce, b.tx_hash);
                let with_memo = insert_op_return(&built.hex.to_string(), &memo.encode())
                    .map_err(|e| anyhow!("memo: {e}"))?;
                let ycash = self.ctx.ycash.clone();
                let complete = std::cell::Cell::new(true);
                let rec = self.ctx.db(|t| {
                    t.sign_once_ycash(&key, &with_memo, |h| {
                        let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
                        let r = block_on(ycash.set_signunlock(&hex)).map_err(|e| e.to_string())?;
                        complete.set(r.complete);
                        Ok::<_, String>((r.hex.to_string(), r.sighash.0))
                    })
                })?;
                info!(event = "unlock_signed", nonce, vault = %vault.outpoint, amount = b.amount,
                      recipient = %encode_address(&recipient, p.network), complete = complete.get());
                super::drill_crash_point(&p, "unlock_signed");
                match self.complete_unlock(&rec.signed_hex).await? {
                    Some(h) => h,
                    None => return Ok(()),
                }
            }
        };
        let hex: HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
        let txid = match self.ctx.ycash.vault_send(&hex).await {
            Ok(t) => t,
            Err(e) if e.rpc().is_some_and(|r| r.is_already_known()) => {
                // already broadcast; the watcher observes it from the mempool or a block
                info!(event = "unlock_already_known", nonce);
                return Ok(());
            }
            Err(e) if matches!(e.reason(), Some(ErrorReason::Rejected { ref reason, .. }) if reason.contains("vault-rate")) =>
            {
                let epoch = self.mem.set.as_ref().map_or(0, |s| s.set.epoch);
                // over the cap even for an empty epoch: out of the FIFO (05/M-2)
                let over = self
                    .mem
                    .set
                    .as_ref()
                    .and_then(|s| full_window_cap(&s.set))
                    .is_some_and(|cap| b.amount > cap);
                let wait = if over {
                    OVER_CAP_EPOCH
                } else {
                    u64::try_from(epoch).unwrap_or(0)
                };
                self.ctx
                    .db(|t| t.burn_wait_cap(&b.key, wait, Some(self.mem.tip)))?;
                info!(
                    event = "burn_waiting_cap",
                    nonce,
                    reason = "bad-txns-vault-rate",
                    over_cap = over
                );
                if over {
                    self.over_cap_alarm()?;
                }
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        info!(event = "unlock_sent", nonce, txid = %txid, amount = b.amount,
              recipient = %encode_address(&recipient, p.network));
        // vault_send signs the fee inputs: observe the transaction as broadcast
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

    /// Release every matched intent that has matured — burns to their recipient, rolls into
    /// their new V rebuilt from the memo (U-15: anyone may; every attestor does, idempotently).
    pub(crate) async fn releases(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let delay = u32::from(self.ctx.params.delay);
        let matched = self.ctx.db(|t| t.intents_in_state(IntentState::Matched))?;
        for i in matched {
            let Some(c) = i.confirmed_height else {
                continue;
            };
            if tip + 1 < c + delay {
                continue;
            }
            if self.mem.release_tried.get(&i.outpoint) == Some(&tip) {
                continue;
            }
            self.mem.release_tried.insert(i.outpoint, tip);
            let (script, what) = if i.classification.as_deref() == Some("matched-roll") {
                match self.roll_target(&i).await {
                    Ok(s) => (s, "roll".to_owned()),
                    Err(e) => {
                        debug!(event = "release_skipped", intent = %i.outpoint, error = %format!("{e:#}"));
                        continue;
                    }
                }
            } else {
                let Some(k) = i.matched_burn else { continue };
                let Some(b) = self.ctx.db(|t| t.burn(&k))? else {
                    continue;
                };
                let Ok(r) = YcashRecipient::from_bytes(&b.recipient) else {
                    continue;
                };
                (
                    r.script(),
                    format!(
                        "burn {} to {}",
                        k.nonce,
                        encode_address(&r, self.ctx.params.network)
                    ),
                )
            };
            match self
                .ctx
                .ycash
                .vault_release(&op_rpc(&i.outpoint), Some(&hex::encode(&script)))
                .await
            {
                Ok(txid) => info!(event = "release_sent", intent = %i.outpoint, what = %what,
                                  txid = %txid, amount = i.value_zat),
                Err(e) => debug!(event = "release_skipped", intent = %i.outpoint, error = %e),
            }
        }
        Ok(())
    }

    /// The new V a roll intent pays: the spent V rebuilt with the memo's `ownerHeight`, checked
    /// against the intent's `recipientHash`.
    async fn roll_target(&mut self, i: &hawkeye_store::IntentRecord) -> Result<Vec<u8>> {
        let memo = HawkeyeMemo::decode_for(
            self.ctx.params.bridge_kind,
            i.memo.as_deref().ok_or_else(|| anyhow!("no memo"))?,
        )
        .map_err(|e| anyhow!("memo: {e}"))?;
        anyhow::ensure!(
            memo.is_for(self.ctx.params.bridge_kind, &self.ctx.params.deployment),
            "the roll memo names another deployment"
        );
        let origin = i
            .origin_vault
            .ok_or_else(|| anyhow!("origin vault unknown"))?;
        let (spk, _) = self
            .vault_coin(&origin)
            .await?
            .ok_or_else(|| anyhow!("origin vault script unknown"))?;
        let spent = parse_vault(&spk).map_err(|e| anyhow!("origin vault: {e}"))?;
        let new = memo
            .rolled_vault(&spent)
            .map_err(|e| anyhow!("roll memo: {e}"))?;
        let script = new.script().map_err(|e| anyhow!("{e}"))?;
        anyhow::ensure!(
            hawkeye_core::bytes::sha256(&script) == i.recipient_hash,
            "the rebuilt V is not the intent's recipient"
        );
        Ok(script)
    }

    /// An unlock this attestor signed, with at least `unlockThreshold` set signatures: as is when
    /// its own node's signatures suffice (the §2 row: 1), else with the peers' signatures
    /// gathered over `POST /unlock/sign` (each peer re-verifies the burn ↔ memo match, or the roll,
    /// against its own ledger, and signs on its own node). `None` while still short.
    pub(crate) async fn complete_unlock(&mut self, signed: &str) -> Result<Option<String>> {
        let need = self
            .mem
            .set
            .as_ref()
            .map_or(1, |s| s.set.params.unlockthreshold) as usize;
        let mut hex = signed.to_owned();
        let mut have = unlock_signatures(&hex)?;
        if have >= need {
            return Ok(Some(hex));
        }
        for peer in self.ctx.peers.urls().to_vec() {
            match self
                .ctx
                .peers
                .unlock_sign(&peer, &crate::peers::UnlockSignRequest { hex: hex.clone() })
                .await
            {
                Ok(r) => {
                    let n = unlock_signatures(&r.hex)?;
                    if n > have {
                        info!(event = "unlock_signature_received", peer = %peer, signatures = n,
                              required = need);
                        hex = r.hex;
                        have = n;
                    }
                    if have >= need {
                        return Ok(Some(hex));
                    }
                }
                Err(e) => info!(event = "unlock_signature_refused", peer = %peer, error = %e),
            }
        }
        warn!(
            event = "unlock_incomplete",
            signatures = have,
            required = need,
            "unlockThreshold not reached: no further peer signed"
        );
        Ok(None)
    }
}

/// The node's `RateCap(basis, bps)` (`ycash-dd/src/vault/state.cpp`), bit for bit: the most an
/// epoch with basis `basis` zat lets the set unlock.
pub fn rate_cap(basis: u64, bps: u32) -> u64 {
    let bps = u64::from(bps);
    (basis / 10_000) * bps + ((basis % 10_000) * bps) / 10_000
}

/// The basis a fresh epoch would have: the larger of the current epoch's `epochbasis` and the
/// set's `lockedvalue` (the next epoch's basis, U-20), so a burn that fits either is not judged
/// over cap.
pub fn cap_basis(set: &Set) -> u64 {
    let z = |a: hawkeye_ycash::Amount| u64::try_from(a.zat()).unwrap_or(0);
    z(set.epochbasis).max(z(set.lockedvalue))
}

/// The set's full-window cap in zat (`None`: `ratelimitbps == 0`, no limit). A burn above it
/// fits no epoch under the current parameters: it is **over cap** (audit 05/M-2).
pub fn full_window_cap(set: &Set) -> Option<u64> {
    (set.params.ratelimitbps != 0).then(|| rate_cap(cap_basis(set), set.params.ratelimitbps))
}

/// What the leader does with one of its assigned burns (plan §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapStep {
    /// Within the epoch's remainder: unlock it.
    Post,
    /// Above the full-window cap: parked out of the FIFO (05/M-2); later burns go on.
    OverCap,
    /// Fits a full window but not this epoch's remainder: `WAITING_CAP` for the next epoch.
    WaitEpoch,
    /// Behind a `WaitEpoch` burn: left `ASSIGNED` (FIFO by nonce, never splitting, HK-8).
    Behind,
}

/// The leader's FIFO walk over its burns' `amounts` (nonce order) given the epoch's remaining
/// `available` and the `full` window cap (`None`: unlimited). An over-cap burn is skipped and
/// never blocks; the first burn that does not fit the remainder blocks every later one.
pub fn cap_plan(amounts: &[u64], available: Option<u64>, full: Option<u64>) -> Vec<CapStep> {
    let mut left = available;
    let mut blocked = false;
    amounts
        .iter()
        .map(|&a| {
            if full.is_some_and(|f| a > f) {
                return CapStep::OverCap;
            }
            if blocked {
                return CapStep::Behind;
            }
            if let Some(av) = left {
                if a > av {
                    blocked = true;
                    return CapStep::WaitEpoch;
                }
                left = Some(av - a);
            }
            CapStep::Post
        })
        .collect()
}

/// The number of set signatures on the UNLOCK (selector 1) input of an unlock transaction.
pub fn unlock_signatures(hex: &str) -> Result<usize> {
    let tx = Transaction::decode_hex(hex).map_err(|e| anyhow!("{e}"))?;
    Ok(tx
        .inputs
        .iter()
        .filter_map(|i| parse_selector(TemplateKind::Vault, &i.script_sig).ok())
        .find(|s| s.selector == 1)
        .map_or(0, |s| s.args.len()))
}

/// `POST /unlock/sign` (`unlockThreshold > 1`): co-sign a peer's unlock only if, on this
/// attestor's own node and ledger, it spends one vault of the bridge's tag (`WYEC`) of the set into exactly one intent
/// that matches an unconsumed finalized burn through its memo, or is a valid roll of a vault due
/// here; then `set_signunlock` on this node through the sign-once record (one spend per vault,
/// ever).
pub async fn verify_and_sign_unlock(
    ctx: &super::Ctx,
    req: &crate::peers::UnlockSignRequest,
) -> Result<crate::peers::UnlockSignResponse> {
    use hawkeye_core::matcher::Classification;
    let p = &ctx.params;
    let tx = Transaction::decode_hex(&req.hex).map_err(|e| anyhow!("unlock: {e}"))?;
    // the vault input, from this node
    let mut vault = None;
    for (idx, input) in tx.inputs.iter().enumerate() {
        // unsigned, or carrying UNLOCK signatures already
        if !input.script_sig.is_empty()
            && parse_selector(TemplateKind::Vault, &input.script_sig)
                .map(|s| s.selector)
                .ok()
                != Some(1)
        {
            continue;
        }
        let Ok(raw) = ctx.ycash.getrawtransaction(&input.prevout.txid).await else {
            continue;
        };
        let prev = Transaction::decode(raw.as_slice()).map_err(|e| anyhow!("{e}"))?;
        let Some(o) = prev.outputs.get(input.prevout.vout as usize) else {
            continue;
        };
        if let Ok(v) = parse_vault(&o.script_pubkey)
            && v.tag == p.tag()
            && v.set_id == p.set_id
        {
            vault = Some((idx, op_core(&input.prevout), v));
            break;
        }
    }
    let (_, origin, vp) = vault.ok_or_else(|| {
        anyhow!(
            "the transaction unlocks no {} vault of this set",
            p.tag_text()
        )
    })?;
    // its intents (one, HK-8)
    let mut intents = vec![];
    for (n, o) in tx.outputs.iter().enumerate() {
        let ip = match hawkeye_core::template::parse_intent(&o.script_pubkey) {
            Ok(ip) => ip,
            Err(_) => match ctx
                .ycash
                .vault_decodescript(&HexBytes(o.script_pubkey.clone()))
                .await
            {
                Ok(hawkeye_ycash::types::DecodedScript::Intent(f)) => {
                    crate::convert::intent_params(&f)?
                }
                _ => continue,
            },
        };
        intents.push((n, ip, u64::try_from(o.value).unwrap_or(0)));
    }
    let [(_, ip, value)] = intents.as_slice() else {
        anyhow::bail!(
            "the unlock creates {} intents, not one (HK-8)",
            intents.len()
        );
    };
    let tip = ctx.ycash.getblockcount().await?;
    let outs = crate::convert::outputs(&tx);
    let c = ctx.db(|t| {
        Ok(super::ycash::classify(
            t,
            p,
            &super::ycash::IntentFacts {
                txid: tx.txid().0,
                first_seen: tip,
                intent: ip,
                value: *value,
                outputs: &outs,
                spent_vault: Some(&vp),
                origin: Some(&origin),
            },
        ))
    })?;
    let matched = match c {
        Classification::MatchedBurn { nonce } => format!("burn {nonce}"),
        Classification::MatchedRoll { .. } => {
            anyhow::ensure!(
                vp.owner_height <= tip.saturating_add(p.roll_margin),
                "a roll of a vault not yet within ROLL_MARGIN here (ownerHeight {}, tip {tip})",
                vp.owner_height
            );
            "roll".to_owned()
        }
        other => anyhow::bail!(
            "the intent does not match here: {}",
            hawkeye_store::classification_code(&other)
        ),
    };
    let key = YcashSignKey {
        domain: SignDomain::YcashUnlock,
        set_id: p.set_id,
        prevout: origin,
    };
    let ycash = ctx.ycash.clone();
    let complete = std::cell::Cell::new(None);
    let rec = ctx.db(|t| {
        t.sign_once_ycash(&key, &req.hex, |h| {
            let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
            let r = block_on(ycash.set_signunlock(&hex)).map_err(|e| e.to_string())?;
            complete.set(Some(r.complete));
            Ok::<_, String>((r.hex.to_string(), r.sighash.0))
        })
    })?;
    info!(event = "unlock_cosigned", vault = %origin, matched = %matched);
    let need = ctx
        .ycash
        .set_getinfo(&ctx.set_hash(), None)
        .await
        .map(|s| s.set.params.unlockthreshold as usize)
        .unwrap_or(1);
    Ok(crate::peers::UnlockSignResponse {
        complete: complete
            .get()
            .unwrap_or(unlock_signatures(&rec.signed_hex)? >= need),
        hex: rec.signed_hex,
        matched,
    })
}

#[cfg(test)]
mod tests {
    use super::{CapStep::*, cap_plan, rate_cap};

    #[test]
    fn rate_cap_is_the_nodes() {
        // RateCap(basis, bps) = (basis / 10000) * bps + ((basis % 10000) * bps) / 10000
        assert_eq!(rate_cap(1_000_000_000, 5_000), 500_000_000);
        assert_eq!(rate_cap(9_999, 9_999), 9_998);
        assert_eq!(rate_cap(12_345, 1), 1);
        assert_eq!(rate_cap(0, 10_000), 0);
        assert_eq!(rate_cap(u64::MAX / 2, 10_000), u64::MAX / 2);
    }

    /// 05/M-2: cap 5, burns 8, 1, 1 — the over-cap burn is skipped, the others go.
    #[test]
    fn an_over_cap_burn_does_not_block_later_ones() {
        assert_eq!(
            cap_plan(&[8, 1, 1], Some(5), Some(5)),
            [OverCap, Post, Post]
        );
        assert_eq!(
            cap_plan(&[1, 8, 4, 1], Some(5), Some(5)),
            [Post, OverCap, Post, WaitEpoch]
        );
        // no rate limit: everything goes, nothing is over cap
        assert_eq!(cap_plan(&[8, 1], None, None), [Post, Post]);
    }

    /// FIFO for burns that fit a full window is the old behaviour: cap 5, burns 4, 3, 1 — 4 goes,
    /// 3 waits for the next epoch, 1 waits behind it (never served out of order).
    #[test]
    fn fifo_is_kept_for_burns_that_fit() {
        assert_eq!(
            cap_plan(&[4, 3, 1], Some(5), Some(5)),
            [Post, WaitEpoch, Behind]
        );
        assert_eq!(cap_plan(&[3, 1], Some(5), Some(5)), [Post, Post]);
        assert_eq!(cap_plan(&[5, 5], Some(5), Some(5)), [Post, WaitEpoch]);
        // the cap unknown (pre-fix shape): the remainder alone decides
        assert_eq!(
            cap_plan(&[4, 3, 1], Some(5), None),
            [Post, WaitEpoch, Behind]
        );
    }
}
