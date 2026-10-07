//! The watcher (plan §3.2, §5.3 step 1): every `WYEC` intent of the set — in blocks (the
//! follower), in `vault_list`, in the mempool — is classified; an unmatched one is cancelled
//! within its window (one cancel per intent, sign-once, never re-funded) and its signer faces a
//! slash case unless it is a benign race.

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use hawkeye_core::IntentParams;
use hawkeye_core::OutPoint as CoreOutPoint;
use hawkeye_core::bytes::txid_to_display;
use hawkeye_core::matcher::{Classification, ObservedIntent, classify_intent};
use hawkeye_core::policy::TxOut as CoreTxOut;
use hawkeye_core::script::op_return_script;
use hawkeye_core::template::TAG_WYEC;
use hawkeye_store::{
    FaultKind, IntentRecord, IntentState, NewSlashCase, SignDomain, YcashSignKey,
    classification_code,
};
use hawkeye_ycash::HexBytes;
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{TemplateKind as RpcKind, VaultListFilter};
use tracing::{info, warn};

use super::ycash::{link_burn, match_context};
use super::{Engine, block_on};
use crate::convert::{op_core, op_rpc};

impl Engine {
    /// One watcher pass.
    pub(crate) async fn watch(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let members = self.current_member_keys();
        // a. confirmed, unspent intents of the set
        let rows = self
            .ctx
            .ycash
            .vault_list(Some(&VaultListFilter {
                tag: Some("WYEC".into()),
                setid: Some(self.ctx.set_hash()),
                kind: Some(RpcKind::Intent),
                ..VaultListFilter::default()
            }))
            .await?;
        self.mem.intent_rows = rows
            .into_iter()
            .filter_map(|r| r.as_intent().cloned())
            .map(|r| (op_core(&r.outpoint), r))
            .collect();
        let rows: Vec<_> = self.mem.intent_rows.values().cloned().collect();
        for r in rows {
            let op = op_core(&r.outpoint);
            if self.ctx.db(|t| t.intent(&op))?.is_some() {
                continue;
            }
            let bh = self.ctx.ycash.getblockhash(r.height).await?;
            let info = self
                .ctx
                .ycash
                .getrawtransaction_verbose(&r.txid, Some(&bh))
                .await?;
            let raw = info.hex.ok_or_else(|| anyhow!("no hex"))?;
            let tx = Transaction::decode(raw.as_slice()).map_err(|e| anyhow!("{e}"))?;
            if let Some(obs) = self
                .prepare_unlock(&tx, raw.as_slice(), Some(r.origin.as_slice()))
                .await?
            {
                self.note_signatures(&obs).await;
                self.ctx.db(|t| {
                    super::ycash::apply_unlock(t, &p, &obs, tip, r.height, Some(r.height), &members)
                })?;
            }
        }
        // b. the mempool
        let mempool = self.ctx.ycash.getrawmempool().await?;
        let current: HashSet<_> = mempool.iter().map(|t| t.0).collect();
        self.mem.mempool_seen.retain(|t| current.contains(t));
        self.mem.mempool_spent.clear();
        for txid in &mempool {
            let raw = match self.ctx.ycash.getrawtransaction(txid).await {
                Ok(r) => r,
                Err(_) => continue, // left the mempool meanwhile
            };
            let Ok(tx) = Transaction::decode(raw.as_slice()) else {
                continue;
            };
            for i in &tx.inputs {
                self.mem.mempool_spent.insert(op_core(&i.prevout));
            }
            if !self.mem.mempool_seen.insert(txid.0) {
                continue;
            }
            if let Some(obs) = self.prepare_unlock(&tx, raw.as_slice(), None).await? {
                self.note_signatures(&obs).await;
                self.ctx
                    .db(|t| super::ycash::apply_unlock(t, &p, &obs, tip, tip, None, &members))?;
            }
        }
        // c. re-classify (consumption changes as intents are mined) and link burns
        self.reclassify()?;
        // d. act on unmatched intents
        let unmatched = self
            .ctx
            .db(|t| t.intents_in_state(IntentState::Unmatched))?;
        for i in unmatched {
            if let Err(e) = self.handle_unmatched(&i).await {
                warn!(event = "cancel_failed", intent = %i.outpoint, error = %format!("{e:#}"));
            }
        }
        // e. our cancels not yet mined: re-broadcast the stored bytes (never rebuilt)
        let sent = self
            .ctx
            .db(|t| t.intents_in_state(IntentState::CancelSent))?;
        for i in sent {
            let key = cancel_key(p.set_id, &i.outpoint);
            if let Some(rec) = self.ctx.db(|t| t.ycash_signature(&key))?
                && let Ok(h) = rec.signed_hex.parse::<HexBytes>()
            {
                let _ = self.ctx.ycash.vault_send(&h).await;
            }
            if i.confirmed_height.is_some() && !self.mem.intent_rows.contains_key(&i.outpoint) {
                continue;
            }
            if let Some(r) = self.mem.intent_rows.get(&i.outpoint)
                && !r.cancellable
            {
                self.ctx.db(|t| {
                    t.transition_intent(
                        &i.outpoint,
                        IntentState::MaturedUnmatched,
                        Some(tip),
                        Some("window missed"),
                    )
                })?;
                self.alarm(
                    "matured-unmatched",
                    format!(
                        "unmatched intent {} matured before its cancel confirmed",
                        i.outpoint
                    ),
                );
            }
        }
        Ok(())
    }

    /// Re-run the matcher over the open intents with the ledger's current burns.
    fn reclassify(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let mctx = match_context(&p, tip);
        self.ctx.db(|t| {
            let mut open = t.intents_in_state(IntentState::Matched)?;
            open.extend(t.intents_in_state(IntentState::Unmatched)?);
            open.extend(t.intents_in_state(IntentState::Observed)?);
            for i in open {
                if i.classification.as_deref() == Some("matched-roll") {
                    continue;
                }
                let ip = IntentParams {
                    tag: TAG_WYEC,
                    recipient_hash: i.recipient_hash,
                    vault_hash: i.vault_hash,
                    delay: p.delay,
                    cancel_set_id: p.set_id,
                    set_id: p.set_id,
                    owner_key: [2; 33],
                };
                let outs: Vec<CoreTxOut> = i
                    .memo
                    .iter()
                    .map(|m| CoreTxOut {
                        value: 0,
                        script_pubkey: op_return_script(m),
                    })
                    .collect();
                let c = classify_intent(
                    &mctx,
                    &ObservedIntent {
                        txid: i.outpoint.txid,
                        first_seen: i.first_seen_height,
                        intent: &ip,
                        value: i.value_zat,
                        outputs: &outs,
                        spent_vault: None,
                    },
                    |n| t.matcher_burn(&p.deployment, n).ok().flatten(),
                );
                if c == Classification::Foreign {
                    continue;
                }
                let code = classification_code(&c);
                if i.classification.as_deref() != Some(code.as_str()) {
                    t.classify_intent(&i.outpoint, &p.deployment, &c, Some(tip))?;
                    info!(event = "intent_classified", intent = %i.outpoint, classification = %code,
                          previous = ?i.classification);
                }
                if let Classification::MatchedBurn { nonce } = c {
                    link_burn(t, &p, nonce, &i.outpoint, i.confirmed_height.is_some(), tip)?;
                }
            }
            Ok(())
        })
    }

    async fn handle_unmatched(&mut self, i: &IntentRecord) -> Result<()> {
        let code = i.classification.clone().unwrap_or_default();
        if code == "unmatched:unknown-burn" && !self.mem.eth_fresh {
            return Ok(()); // this attestor's Ethereum view may lag the burn's finality
        }
        let tip = self.mem.tip;
        let cancellable = match self.mem.intent_rows.get(&i.outpoint) {
            Some(r) => r.cancellable,
            None if i.confirmed_height.is_none() => true, // mempool
            None => return Ok(()),                        // spent meanwhile
        };
        if !cancellable {
            self.ctx.db(|t| {
                t.transition_intent(
                    &i.outpoint,
                    IntentState::MaturedUnmatched,
                    Some(tip),
                    Some(&code),
                )
            })?;
            self.alarm(
                "matured-unmatched",
                format!(
                    "unmatched intent {} ({code}) is past its cancel window",
                    i.outpoint
                ),
            );
            return Ok(());
        }
        let own = i.signer_key == Some(self.ctx.me) && self.signed_here(i)?;
        if own {
            // this attestor's own deliberate unlock (a drill, or its own fault): the other
            // attestors judge it; cancelling it here would hide the fault from them
            if self.mem.own_logged.insert(i.outpoint) {
                warn!(event = "own_unmatched_intent", intent = %i.outpoint, reason = %code,
                      "signed by this attestor; left to the other watchers");
            }
            return Ok(());
        }
        if self.mem.mempool_spent.contains(&i.outpoint) {
            tracing::debug!(event = "intent_cancel_pending", intent = %i.outpoint,
                  "a spend of the intent (another attestor's cancel) is in the mempool");
        } else if let Some(txid) = self.cancel(&i.outpoint).await? {
            self.ctx
                .db(|t| t.intent_cancel_sent(&i.outpoint, &txid, Some(tip)))?;
            warn!(event = "intent_cancel_sent", intent = %i.outpoint, reason = %code,
                  cancel_txid = %txid_to_display(&txid), signer = ?i.signer_key.map(hex::encode));
        }
        let benign = code == "unmatched:consumed-burn:benign-race";
        if benign {
            info!(event = "benign_race", intent = %i.outpoint);
            return Ok(());
        }
        let Some(target) = i.signer_key else {
            warn!(event = "slash_unattributed", intent = %i.outpoint, reason = %code);
            return Ok(());
        };
        if target == self.ctx.me {
            warn!(event = "own_intent_cancelled", intent = %i.outpoint, reason = %code);
            return Ok(());
        }
        let raw = match self.mem.raw_txs.get(&i.outpoint.txid) {
            Some(r) => hex::encode(r),
            None => String::new(),
        };
        let evidence = serde_json::json!({
            "fault": "FRAUDULENT_INTENT",
            "set_id": txid_to_display(&self.ctx.params.set_id),
            "target": hex::encode(target),
            "subject": hex::encode(i.outpoint.txid),
            "intent": i.outpoint.to_string(),
            "unlock_txid": txid_to_display(&i.outpoint.txid),
            "unlock_hex": raw,
            "vault": i.origin_vault.map(|v| v.to_string()),
            "value": i.value_zat,
            "classification": code,
            "memo": i.memo.as_ref().map(hex::encode),
            "first_seen_height": i.first_seen_height,
        });
        let (case, new) = self.ctx.db(|t| {
            t.open_slash_case(&NewSlashCase {
                target_key: target,
                fault: FaultKind::FraudulentIntent,
                subject: i.outpoint.txid.to_vec(),
                evidence_json: evidence.to_string(),
                opened_height: Some(tip),
            })
        })?;
        if new {
            warn!(event = "slash_case_opened", case = case.id, fault = "FRAUDULENT_INTENT",
                  target = %hex::encode(target), intent = %i.outpoint, reason = %code);
        }
        Ok(())
    }

    /// Whether this attestor's ledger holds the unlock signature of the intent's vault, i.e. it
    /// signed this unlock itself.
    fn signed_here(&self, i: &IntentRecord) -> Result<bool> {
        let Some(vault) = i.origin_vault else {
            return Ok(false);
        };
        let key = YcashSignKey {
            domain: SignDomain::YcashUnlock,
            set_id: self.ctx.params.set_id,
            prevout: vault,
        };
        Ok(self.ctx.db(|t| t.ycash_signature(&key))?.is_some())
    }

    /// Cancel an intent once: the stored signed cancel if there is one, else
    /// vault_buildcancel → set_signcancel (sign-once) → vault_send. `None`: it was already
    /// broadcast (the txid is then learnt when it is mined).
    pub(crate) async fn cancel(
        &mut self,
        op: &CoreOutPoint,
    ) -> Result<Option<hawkeye_core::bytes::Hash32>> {
        let key = cancel_key(self.ctx.params.set_id, op);
        let signed = match self.ctx.db(|t| t.ycash_signature(&key))? {
            Some(rec) => rec.signed_hex,
            None => {
                let built = self.ctx.ycash.vault_buildcancel(&op_rpc(op)).await?;
                let ycash = self.ctx.ycash.clone();
                let rec = self.ctx.db(|t| {
                    t.sign_once_ycash(&key, &built.hex.to_string(), |h| {
                        let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
                        let r = block_on(ycash.set_signcancel(&hex)).map_err(|e| e.to_string())?;
                        Ok::<_, String>((r.hex.to_string(), r.sighash.0))
                    })
                })?;
                rec.signed_hex
            }
        };
        let hex: HexBytes = signed.parse().map_err(|e| anyhow!("{e}"))?;
        match self.ctx.ycash.vault_send(&hex).await {
            Ok(t) => Ok(Some(t.0)),
            Err(e) if e.rpc().is_some_and(|r| r.is_already_known()) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// The sign-once key of a cancel.
pub fn cancel_key(set_id: [u8; 32], op: &CoreOutPoint) -> YcashSignKey {
    YcashSignKey {
        domain: SignDomain::YcashCancel,
        set_id,
        prevout: *op,
    }
}
