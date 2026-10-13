//! The burn side (plan §1.3, §5.2, §5.5): leader assignment and takeover, the rate limit, the
//! unlock with its `HKB1` memo (sign-once), and the release after the delay.

use anyhow::{Result, anyhow};
use hawkeye_core::address::encode_address;
use hawkeye_core::leader::{leader_for, mint_leader_for};
use hawkeye_core::lock::lock_id;
use hawkeye_core::memo::HawkeyeMemo;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::setsig::Role;
use hawkeye_core::template::{TemplateKind, parse_selector, parse_vault};
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33};
use hawkeye_store::{
    BurnKey, BurnRecord, BurnState, IntentState, OVER_CAP_EPOCH, SignDomain, UnlockBurn,
    UnlockBurnRecord, UnlockOrigin, VaultRecord, VaultState, YcashSignKey,
};
use hawkeye_ycash::tx::{Transaction, insert_op_return};
use hawkeye_ycash::types::{Recipient, Set};
use hawkeye_ycash::{Amount, ErrorReason, HexBytes};
use tracing::{debug, info, warn};

use super::Engine;
use super::sign::{Adoption, SetSigning};
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

    /// Judge the live unlock that pays a burn here (remedial report 05/H-1 §4.4, finding
    /// 05/N-1): re-sent only if this attestor signed it **as the burn's leader** and every fee
    /// input still unspent is this wallet's; dead only when it can no longer confirm — the vault
    /// spent by another transaction at least `C_Y` deep, or, for a row this attestor did not
    /// sign as leader, a fee input spent so deep while the vault is unspent.
    ///
    /// A leader's unlock whose fee input is gone is **not** dead (audit 01/V-2): the set
    /// signatures are over `SIGHASH_ALL|SIGHASH_ANYONECANPAY`, so anyone holding the signed
    /// bytes can re-fund it (`vault_refee`) and it would still pay the burn. Signing another
    /// vault for the burn would then risk a double payment; it is re-sent instead, and
    /// [`super::sign::send_set_signed`] re-funds it.
    async fn judge_live_unlock(
        &mut self,
        row: &UnlockBurnRecord,
        signed_hex: &str,
    ) -> Result<LiveUnlock> {
        let tip = self.mem.tip;
        let cy = self.ctx.params.confirmations;
        let tx = Transaction::decode_hex(signed_hex).map_err(|e| anyhow!("stored unlock: {e}"))?;
        let vault = row.prevout;
        let ycash = self.ctx.ycash.clone();
        let rpc = |op: &CoreOutPoint| op_rpc(op);
        // the vault: unspent, spent by this unlock (it is out), or by another transaction
        if ycash
            .gettxout(&rpc(&vault).txid, vault.vout, true)
            .await?
            .is_none()
        {
            if ycash.getrawtransaction(&tx.txid()).await.is_ok() {
                return Ok(LiveUnlock::Out);
            }
            if ycash
                .gettxout(&rpc(&vault).txid, vault.vout, false)
                .await?
                .is_some()
            {
                return Ok(LiveUnlock::Hold(format!(
                    "vault {vault} is spent in the mempool by another transaction"
                )));
            }
            let since = *self.mem.conflict_seen.entry(vault).or_insert(tip);
            let depth = tip + 1 - since.min(tip + 1);
            if depth >= cy {
                return Ok(LiveUnlock::Dead(format!(
                    "vault {vault} spent by another transaction, at least {depth} blocks deep (seen spent since height {since})"
                )));
            }
            return Ok(LiveUnlock::Hold(format!(
                "vault {vault} spent by another transaction {depth} < C_Y {cy} blocks deep"
            )));
        }
        let mut foreign = vec![];
        let mut lost = vec![];
        for i in &tx.inputs {
            let op = op_core(&i.prevout);
            if op == vault {
                continue;
            }
            match ycash
                .gettxout(&i.prevout.txid, i.prevout.vout, true)
                .await?
            {
                Some(info) => {
                    let mine = match info
                        .script_pub_key
                        .addresses
                        .as_ref()
                        .and_then(|a| a.first())
                    {
                        Some(a) => ycash
                            .validateaddress(a)
                            .await
                            .is_ok_and(|v| v.ismine == Some(true)),
                        None => false,
                    };
                    if !mine {
                        foreign.push(op.to_string());
                    }
                }
                None if row.origin == UnlockOrigin::Leader => {
                    // re-fundable (01/V-2): resent below, `send_set_signed` re-funds it
                    lost.push(op.to_string());
                }
                None => {
                    if ycash
                        .gettxout(&i.prevout.txid, i.prevout.vout, false)
                        .await?
                        .is_some()
                    {
                        return Ok(LiveUnlock::Hold(format!(
                            "fee input {op} is spent in the mempool by another transaction"
                        )));
                    }
                    let since = *self.mem.conflict_seen.entry(op).or_insert(tip);
                    let depth = tip + 1 - since.min(tip + 1);
                    if depth >= cy {
                        return Ok(LiveUnlock::Dead(format!(
                            "fee input {op} spent at least {depth} blocks deep (seen spent since height {since}) while vault {vault} is unspent"
                        )));
                    }
                    return Ok(LiveUnlock::Hold(format!(
                        "fee input {op} spent {depth} < C_Y {cy} blocks deep"
                    )));
                }
            }
        }
        if row.origin != UnlockOrigin::Leader {
            return Ok(LiveUnlock::Hold(format!(
                "a {} unlock of vault {vault} pays this burn here; it is never re-sent",
                row.origin
            )));
        }
        if !foreign.is_empty() {
            return Ok(LiveUnlock::Hold(format!(
                "the unlock of vault {vault} has fee inputs this wallet does not hold: {}",
                foreign.join(", ")
            )));
        }
        if !lost.is_empty() {
            info!(event = "unlock_refund_due", vault = %vault, lost = %lost.join(", "),
                  "fee input(s) gone: the leader's unlock is re-sent re-funded (01/V-2)");
        }
        Ok(LiveUnlock::Resend(signed_hex.to_owned()))
    }

    /// vault_buildunlock → memo → set_signunlock (sign-once, per vault **and** per burn) →
    /// vault_send, then observe it. A burn that already has a live unlock here is re-sent (if
    /// it is this attestor's own as leader), held, or marked dead ([`LiveUnlock`]).
    async fn post_unlock(&mut self, b: &BurnRecord) -> Result<()> {
        let p = self.ctx.params.clone();
        let nonce = b.key.nonce;
        let recipient =
            YcashRecipient::from_bytes(&b.recipient).map_err(|e| anyhow!("recipient: {e}"))?;
        let (signed, template) = match self.ctx.db(|t| t.live_unlock_for_burn(&p.set_id, &b.key))? {
            Some(row) => {
                let key = self.unlock_key_of(&row.prevout);
                let rec = self.ctx.db(|t| t.ycash_signature(&key))?.ok_or_else(|| {
                    anyhow!(
                        "burn {nonce}: the live unlock of {} has no record",
                        row.prevout
                    )
                })?;
                match self.judge_live_unlock(&row, &rec.signed_hex).await? {
                    LiveUnlock::Out => return Ok(()),
                    LiveUnlock::Hold(why) => {
                        if self.mem.held_logged.insert(nonce) {
                            warn!(event = "unlock_held", nonce, vault = %row.prevout,
                                  origin = %row.origin, reason = %why);
                        }
                        self.alarm(
                            "unlock-held",
                            format!("burn {nonce}: {why} (takeover moves the burn on)"),
                        );
                        return Ok(());
                    }
                    LiveUnlock::Dead(why) => {
                        let tip = self.mem.tip;
                        self.ctx.db(|t| {
                            t.mark_unlock_dead(&p.set_id, &b.key, &row.prevout, &why, tip)
                        })?;
                        warn!(event = "unlock_dead", nonce, vault = %row.prevout,
                              origin = %row.origin, reason = %why,
                              "the signed unlock can no longer confirm; another vault may be signed");
                        self.mem.held_logged.remove(&nonce);
                        self.alarm(
                            "unlock-dead",
                            format!(
                                "burn {nonce}: unlock of vault {} is dead: {why}",
                                row.prevout
                            ),
                        );
                        return Ok(());
                    }
                    LiveUnlock::Resend(h) => {
                        info!(event = "unlock_resend", nonce);
                        match self.complete_unlock(&h).await? {
                            Some(h) => (h, row.prevout),
                            None => return Ok(()),
                        }
                    }
                }
            }
            None => {
                let vaults: Vec<VaultRecord> = self.ctx.db(|t| {
                    let mut v = t.vaults_in_state(VaultState::Live)?;
                    v.extend(t.vaults_in_state(VaultState::RollDue)?);
                    v.sort_by_key(|x| x.owner_height);
                    Ok(v)
                })?;
                let mut chosen = None;
                for v in &vaults {
                    if v.value_zat < b.amount || self.mem.mempool_spent.contains(&v.outpoint) {
                        continue;
                    }
                    let key = self.unlock_key_of(&v.outpoint);
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
                // no record of this vault here (checked above): a stale node build may go
                let built = super::sign::build_unlock(
                    &self.ctx.ycash,
                    &op_rpc(&vault.outpoint),
                    &[Recipient::script(
                        recipient.script(),
                        Amount::from_zat(i64::try_from(b.amount)?),
                    )],
                    true,
                )
                .await?;
                let memo =
                    HawkeyeMemo::burn_release_for(p.bridge_kind, p.deployment, nonce, b.tx_hash);
                let with_memo = insert_op_return(&built.hex.to_string(), &memo.encode())
                    .map_err(|e| anyhow!("memo: {e}"))?;
                let signer =
                    SetSigning::prepare(&self.ctx, &with_memo, Role::Unlock, vault.outpoint)
                        .await?;
                let complete = std::cell::Cell::new(true);
                let burn = UnlockBurn {
                    key: b.key,
                    origin: UnlockOrigin::Leader,
                    allow_double: false,
                };
                let rec = self.ctx.db(|t| {
                    t.sign_once_unlock(&key, Some(&burn), &with_memo, |h| {
                        let o = signer.sign(h)?;
                        complete.set(o.complete);
                        Ok::<_, String>((o.hex, o.sighash))
                    })
                })?;
                info!(event = "unlock_signed", nonce, vault = %vault.outpoint, amount = b.amount,
                      recipient = %encode_address(&recipient, p.network), complete = complete.get());
                super::drill_crash_point(&p, "unlock_signed");
                match self.complete_unlock(&rec.signed_hex).await? {
                    Some(h) => (h, vault.outpoint),
                    None => return Ok(()),
                }
            }
        };
        let hex: HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
        let txid = match super::sign::send_set_signed(&self.ctx.ycash, &hex, &template).await {
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

    /// The sign-once key of a vault's unlock.
    pub(crate) fn unlock_key_of(&self, vault: &CoreOutPoint) -> YcashSignKey {
        YcashSignKey {
            domain: SignDomain::YcashUnlock,
            set_id: self.ctx.params.set_id,
            prevout: *vault,
        }
    }

    /// An unlock this attestor signed, with at least `unlockThreshold` set signatures: as is when
    /// its own node's signatures suffice (the §2 row: 1 — no peer is ever asked), else with the
    /// peers' signatures gathered over `POST /unlock/sign` (each peer re-verifies the burn ↔ memo
    /// match, or the roll, against its own ledger, and that the requester leads it). A peer's
    /// answer is adopted only if it is our transaction with more valid signatures of distinct
    /// current members ([`Adoption`], finding 05/L-1); a peer that fails twice in a row is asked
    /// last. `None` while still short.
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
        debug_assert!(need > 1, "at unlockThreshold 1 no peer is ever asked");
        let ours = Transaction::decode_hex(signed).map_err(|e| anyhow!("{e}"))?;
        let Some((idx, vault)) = ours.inputs.iter().enumerate().find_map(|(i, x)| {
            (parse_selector(TemplateKind::Vault, &x.script_sig).is_ok_and(|s| s.selector == 1))
                .then(|| (i, op_core(&x.prevout)))
        }) else {
            anyhow::bail!("the unlock carries no UNLOCK signature of ours");
        };
        let (spk, value) = match self.vault_coin(&vault).await? {
            Some(c) => c,
            None => {
                let o = self
                    .ctx
                    .ycash
                    .gettxout(&op_rpc(&vault).txid, vault.vout, true)
                    .await?
                    .ok_or_else(|| anyhow!("vault {vault} is spent"))?;
                (
                    o.script_pub_key.hex.0,
                    u64::try_from(o.value.zat()).unwrap_or(0),
                )
            }
        };
        let members = self.current_member_keys();
        let mut peers = self.ctx.peers.urls().to_vec();
        peers.sort_by_key(|u| u32::from(self.mem.peer_backoff.get(u).copied().unwrap_or(0) >= 2));
        let mut current = ours.clone();
        for peer in peers {
            match self
                .ctx
                .peers
                .unlock_sign(&peer, &crate::peers::UnlockSignRequest { hex: hex.clone() })
                .await
            {
                Ok(r) => {
                    let check = if self.responder_ok(r.responder) {
                        Adoption {
                            ours: &current,
                            idx,
                            role: Role::Unlock,
                            need,
                            coin: (&spk, value),
                            members: &members,
                        }
                        .check(&self.ctx, &r.body.hex)
                    } else {
                        Err(anyhow!("the answer is not signed by a current member"))
                    };
                    match check {
                        Ok(signers) => {
                            self.mem.peer_backoff.remove(&peer);
                            info!(event = "unlock_signature_received", peer = %peer,
                                  signatures = signers.len(), required = need);
                            hex = r.body.hex;
                            current = Transaction::decode_hex(&hex).map_err(|e| anyhow!("{e}"))?;
                            have = signers.len();
                        }
                        Err(e) => {
                            *self.mem.peer_backoff.entry(peer.clone()).or_default() += 1;
                            warn!(event = "unlock_signature_rejected", peer = %peer,
                                  error = %format!("{e:#}"));
                        }
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

/// What a burn's live unlock here allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveUnlock {
    /// This attestor's own unlock as leader, sendable: re-send these bytes.
    Resend(String),
    /// Not re-sent and not dead (yet): wait, alarm; takeover moves the burn on.
    Hold(String),
    /// It can no longer confirm: mark it dead (one more vault may then be signed).
    Dead(String),
    /// It is broadcast or mined: the watcher follows it.
    Out,
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

/// The set as the engine last saw it, else from the node.
pub(crate) async fn set_snapshot(ctx: &super::Ctx) -> Result<hawkeye_ycash::types::SetInfo> {
    if let Some(s) = ctx
        .auth
        .set
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return Ok(s);
    }
    Ok(ctx.ycash.set_getinfo(&ctx.set_hash(), None).await?)
}

/// `POST /unlock/sign` (`unlockThreshold > 1` only): co-sign a peer's unlock only if
///
/// - the set's `unlockThreshold` is above 1 — at 1 (HK-1, the mainnet shape) the leader
///   completes its own unlocks and the endpoint is inert;
/// - the request is member-signed ([`crate::peer_auth`]) and its requester **leads** what the
///   unlock pays here: the burn's leader in this ledger (takeover already applied), or the
///   vault's roll leader;
/// - on this attestor's own node and ledger it spends one **unspent** vault of the bridge's
///   tag of the set (`gettxout`) into exactly one intent that matches an unconsumed finalized
///   burn through its memo, or is a valid roll of a vault due here;
///
/// then signs on this node through the sign-once record — one spend per vault and one live
/// vault per burn, ever (schema v6).
pub async fn verify_and_sign_unlock(
    ctx: &super::Ctx,
    requester: Option<PubKey33>,
    req: &crate::peers::UnlockSignRequest,
) -> Result<crate::peers::UnlockSignResponse> {
    use hawkeye_core::matcher::Classification;
    let p = &ctx.params;
    let set = set_snapshot(ctx).await?;
    let need = set.set.params.unlockthreshold;
    anyhow::ensure!(
        need > 1,
        "unlock co-signing is disabled: the set's unlockThreshold is 1 (HK-1); the leader \
         completes its own unlocks"
    );
    let requester = requester.ok_or_else(|| {
        anyhow!("unauthenticated request: unlock co-signing answers member-signed requests only")
    })?;
    let tx = Transaction::decode_hex(&req.hex).map_err(|e| anyhow!("unlock: {e}"))?;
    // the vault input: unspent on this node (N-3)
    let mut vault = None;
    for input in &tx.inputs {
        // unsigned, or carrying UNLOCK signatures already
        if !input.script_sig.is_empty()
            && parse_selector(TemplateKind::Vault, &input.script_sig)
                .map(|s| s.selector)
                .ok()
                != Some(1)
        {
            continue;
        }
        let Ok(Some(o)) = ctx
            .ycash
            .gettxout(&input.prevout.txid, input.prevout.vout, true)
            .await
        else {
            continue;
        };
        if let Ok(v) = parse_vault(&o.script_pub_key.hex.0)
            && v.tag == p.tag()
            && v.set_id == p.set_id
        {
            vault = Some((op_core(&input.prevout), v));
            break;
        }
    }
    let (origin, vp) = vault.ok_or_else(|| {
        anyhow!(
            "the transaction unlocks no unspent {} vault of this set",
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
    let (matched, burn) = match c {
        Classification::MatchedBurn { nonce } => {
            let k = BurnKey::new(p.deployment, nonce);
            let b = ctx
                .db(|t| t.burn(&k))?
                .ok_or_else(|| anyhow!("burn {nonce} is not in this ledger"))?;
            anyhow::ensure!(
                b.leader == Some(requester),
                "the requester {} is not the burn's leader here (leader = {})",
                hex::encode(requester),
                b.leader.map_or("none".into(), hex::encode)
            );
            (
                format!("burn {nonce}"),
                Some(UnlockBurn {
                    key: k,
                    origin: UnlockOrigin::Cosign,
                    allow_double: false,
                }),
            )
        }
        Classification::MatchedRoll { .. } => {
            anyhow::ensure!(
                vp.owner_height <= tip.saturating_add(p.roll_margin),
                "a roll of a vault not yet within ROLL_MARGIN here (ownerHeight {}, tip {tip})",
                vp.owner_height
            );
            let mut live: Vec<PubKey33> = set
                .memberlist
                .iter()
                .filter(|m| m.current && m.live)
                .map(|m| m.key.0)
                .collect();
            hawkeye_core::keys::sort_members(&mut live);
            let created = ctx
                .db(|t| t.vault(&origin))?
                .map_or(0, |v| v.created_height);
            let due_from = vp.owner_height.saturating_sub(p.roll_margin).max(created);
            let since = tip.saturating_sub(due_from);
            let leader = mint_leader_for(&lock_id(&origin), &live, since, p.takeover);
            anyhow::ensure!(
                leader == Some(&requester),
                "the requester {} is not the vault's roll leader here (leader = {})",
                hex::encode(requester),
                leader.map_or("none".into(), hex::encode)
            );
            ("roll".to_owned(), None)
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
    let signer = SetSigning::prepare(ctx, &req.hex, Role::Unlock, origin).await?;
    let complete = std::cell::Cell::new(None);
    let rec = ctx.db(|t| {
        t.sign_once_unlock(&key, burn.as_ref(), &req.hex, |h| {
            let o = signer.sign(h)?;
            complete.set(Some(o.complete));
            Ok::<_, String>((o.hex, o.sighash))
        })
    })?;
    info!(event = "unlock_cosigned", vault = %origin, matched = %matched,
          requester = %hex::encode(requester));
    Ok(crate::peers::UnlockSignResponse {
        complete: complete
            .get()
            .unwrap_or(unlock_signatures(&rec.signed_hex)? >= need as usize),
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
