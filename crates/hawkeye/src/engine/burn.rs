//! The burn side (plan §1.3, §5.2, §5.5): leader assignment and takeover, the rate limit, the
//! unlock with its `HKB1` memo (sign-once), and the release after the delay.

use anyhow::{Result, anyhow};
use hawkeye_core::address::encode_address;
use hawkeye_core::leader::leader_for;
use hawkeye_core::memo::{HawkeyeMemo, parse_memo_script};
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_store::{
    BurnRecord, BurnState, IntentState, SignDomain, VaultRecord, VaultState, YcashSignKey,
};
use hawkeye_ycash::tx::{Transaction, insert_op_return};
use hawkeye_ycash::types::Recipient;
use hawkeye_ycash::{Amount, ErrorReason, HexBytes};
use tracing::{debug, info, warn};

use super::{Engine, block_on};
use crate::convert::{op_core, op_rpc};

impl Engine {
    /// Assign, take over, wait for the cap, and (as leader) post the unlock of every finalized
    /// burn, FIFO by nonce.
    pub(crate) async fn burns(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let dep = p.deployment;
        let tip = self.mem.tip;
        let epoch = self.mem.set.as_ref().map_or(0, |s| s.set.epoch);
        let epoch_u = u64::try_from(epoch).unwrap_or(0);
        let live = self.live().to_vec();
        // the epoch turned: waiting burns are up again
        self.ctx.db(|t| {
            for b in t.burns_in_state(&dep, BurnState::WaitingCap)? {
                if b.waiting_epoch != Some(epoch_u) {
                    t.transition_burn(
                        &b.key,
                        BurnState::Finalized,
                        Some(tip.into()),
                        Some("new epoch"),
                    )?;
                    info!(event = "burn_cap_released", nonce = b.key.nonce, epoch);
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
        if !self.is_current_member() {
            return Ok(());
        }
        let assigned = self
            .ctx
            .db(|t| t.burns_in_state(&dep, BurnState::Assigned))?;
        let mut available = self
            .mem
            .set
            .as_ref()
            .and_then(|s| s.set.unlockavailable)
            .map(|a| u64::try_from(a.zat()).unwrap_or(0));
        for b in assigned {
            if b.leader != Some(self.ctx.me) {
                continue;
            }
            if let Some(av) = available {
                if b.amount > av {
                    self.ctx
                        .db(|t| t.burn_wait_cap(&b.key, epoch_u, Some(tip)))?;
                    info!(
                        event = "burn_waiting_cap",
                        nonce = b.key.nonce,
                        amount = b.amount,
                        available = av,
                        epoch
                    );
                    break; // FIFO: later burns wait behind it
                }
                available = Some(av - b.amount);
            }
            if let Err(e) = self.post_unlock(&b).await {
                warn!(event = "unlock_failed", nonce = b.key.nonce, error = %format!("{e:#}"));
            }
        }
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
            let names = tx.outputs.iter().any(|o| {
                matches!(parse_memo_script(&o.script_pubkey), Ok(Some(m))
                    if m.reference == nonce && m.deployment == self.ctx.params.deployment)
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
            YcashRecipient::from_bytes32(&b.recipient).map_err(|e| anyhow!("recipient: {e}"))?;
        let vaults: Vec<VaultRecord> = self.ctx.db(|t| {
            let mut v = t.vaults_in_state(VaultState::Live)?;
            v.extend(t.vaults_in_state(VaultState::RollDue)?);
            v.sort_by_key(|x| x.owner_height);
            Ok(v)
        })?;
        let signed = match self.signed_unlock_for(nonce, &vaults)? {
            Some(h) => {
                info!(event = "unlock_resend", nonce);
                h
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
                let memo = HawkeyeMemo::burn_release(p.deployment, nonce, b.tx_hash);
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
                if !complete.get() {
                    warn!(
                        event = "unlock_incomplete",
                        nonce,
                        "unlockThreshold > 1: the set needs more signatures than this node holds"
                    );
                    return Ok(());
                }
                rec.signed_hex
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
                self.ctx.db(|t| {
                    t.burn_wait_cap(
                        &b.key,
                        u64::try_from(epoch).unwrap_or(0),
                        Some(self.mem.tip),
                    )
                })?;
                info!(
                    event = "burn_waiting_cap",
                    nonce,
                    reason = "bad-txns-vault-rate"
                );
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

    /// Release every matched burn intent that has matured (U-15: anyone may; every attestor
    /// does, idempotently).
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
            let Some(k) = i.matched_burn else { continue };
            let Some(b) = self.ctx.db(|t| t.burn(&k))? else {
                continue;
            };
            let Ok(r) = YcashRecipient::from_bytes32(&b.recipient) else {
                continue;
            };
            let script = hex::encode(r.script());
            match self
                .ctx
                .ycash
                .vault_release(&op_rpc(&i.outpoint), Some(&script))
                .await
            {
                Ok(txid) => info!(event = "release_sent", intent = %i.outpoint, nonce = k.nonce,
                                  txid = %txid, amount = i.value_zat,
                                  recipient = %encode_address(&r, self.ctx.params.network)),
                Err(e) => debug!(event = "release_skipped", intent = %i.outpoint, error = %e),
            }
        }
        Ok(())
    }
}
