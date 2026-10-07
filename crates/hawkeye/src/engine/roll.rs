//! Rolls (plan §3.1 item 2, HK-6, memo §4.3 kind 2).
//!
//! A `WYEC` vault whose `ownerHeight − tip ≤ ROLL_MARGIN` is `ROLL_DUE`. Its roll leader —
//! [`mint_leader_for`] over the vault outpoint's `lockId`, with takeover every `TAKEOVER` blocks
//! counted from the moment it fell due — unlocks the **whole** vault (no re-lock remainder, which
//! would keep the old `ownerHeight`) into one intent whose recipient is a fresh V with the same
//! tag, sets, delay and owner key, `appHeight` 0 and `ownerHeight = tip + 1 + MIN_OWNER_AGE +
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
use hawkeye_core::memo::{HawkeyeMemo, MemoKind, parse_memo_script};
use hawkeye_core::template::{OWNER_HEIGHT_MAX, VaultParams, parse_vault};
use hawkeye_store::{IntentState, LockState, SignDomain, VaultRecord, VaultState, YcashSignKey};
use hawkeye_ycash::tx::{Transaction, insert_op_return};
use hawkeye_ycash::types::Recipient;
use hawkeye_ycash::{Amount, ErrorReason, HexBytes};
use tracing::{info, warn};

use super::{Engine, block_on};
use crate::convert::{op_core, op_rpc};

/// Blocks added to the new `ownerHeight` beyond `MIN_OWNER_AGE + ROLL_MARGIN`.
pub const ROLL_SLACK: u32 = 10;

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

    /// Rolls this attestor signed whose unlock is neither mined nor in the mempool: re-send the
    /// stored bytes (sign-once: never rebuilt, never re-signed).
    async fn resend_rolls(&mut self) -> Result<()> {
        let rolling = self.ctx.db(|t| t.vaults_in_state(VaultState::Rolling))?;
        for v in rolling {
            if self.mem.mempool_spent.contains(&v.outpoint) {
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
                || self
                    .ctx
                    .db(|t| t.ycash_signature(&self.unlock_key(&v.outpoint)))?
                    .is_some()
            {
                continue; // being spent, or signed for another spend
            }
            // takeover counts from the moment it fell due (or was created, if born due)
            let due_from = v
                .owner_height
                .saturating_sub(p.roll_margin)
                .max(v.created_height);
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
        let memo = HawkeyeMemo::roll(p.deployment, &new).map_err(|e| anyhow!("memo: {e}"))?;
        let built = self
            .ctx
            .ycash
            .vault_buildunlock(
                &op_rpc(&v.outpoint),
                &[Recipient::script(
                    new_spk,
                    Amount::from_zat(i64::try_from(value)?),
                )],
            )
            .await?;
        let with_memo = insert_op_return(&built.hex.to_string(), &memo.encode())
            .map_err(|e| anyhow!("memo: {e}"))?;
        let key = self.unlock_key(&v.outpoint);
        let ycash = self.ctx.ycash.clone();
        let rec = self.ctx.db(|t| {
            let rec = t.sign_once_ycash(&key, &with_memo, |h| {
                let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
                let r = block_on(ycash.set_signunlock(&hex)).map_err(|e| e.to_string())?;
                Ok::<_, String>((r.hex.to_string(), r.sighash.0))
            })?;
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

    async fn send_roll(&mut self, v: &VaultRecord, signed: &str) -> Result<()> {
        let p = self.ctx.params.clone();
        let tx = Transaction::decode_hex(signed).map_err(|e| anyhow!("{e}"))?;
        let is_roll = tx.outputs.iter().any(|o| {
            matches!(parse_memo_script(&o.script_pubkey), Ok(Some(m))
                if m.kind == MemoKind::Roll && m.deployment == p.deployment)
        });
        if !is_roll {
            return Ok(()); // the vault's stored unlock pays a burn: burns() owns it
        }
        let hex: HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
        let txid = match self.ctx.ycash.vault_send(&hex).await {
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
