//! The watcher (plan §3.2, §5.3 step 1): every intent of the set under the bridge's tag (`WYEC`) — in blocks (the
//! follower), in `vault_list`, in the mempool — is classified; an unmatched one is cancelled
//! within its window (one cancel per intent, sign-once, never re-funded) and its signer faces a
//! slash case unless it is a benign race.

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use hawkeye_core::IntentParams;
use hawkeye_core::OutPoint as CoreOutPoint;
use hawkeye_core::bytes::txid_to_display;
use hawkeye_core::leader::mint_leader_for;
use hawkeye_core::lock::lock_id;
use hawkeye_core::matcher::Classification;
use hawkeye_core::memo::{HawkeyeMemo, MemoKind};
use hawkeye_core::policy::TxOut as CoreTxOut;
use hawkeye_core::script::op_return_script;
use hawkeye_core::setsig::Role;
use hawkeye_store::{
    BurnKey, BurnState, FaultKind, IntentRecord, IntentState, NewSlashCase, SignDomain,
    YcashSignKey, classification_code,
};
use hawkeye_ycash::HexBytes;
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{TemplateKind as RpcKind, VaultListFilter};
use tracing::{info, warn};

use super::Engine;
use super::sign::{Adoption, SetSigning, input_index, role_args};
use super::ycash::{IntentFacts, classify, link_burn};
use crate::convert::{op_core, op_rpc};
use crate::peers::{CancelSignRequest, CancelSignResponse};

impl Engine {
    /// One watcher pass.
    pub(crate) async fn watch(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let members = self.slashable_member_keys();
        // a. confirmed, unspent intents of the set
        let rows = self
            .ctx
            .ycash
            .vault_list(Some(&VaultListFilter {
                tag: Some(p.tag_text()),
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
            for a in self.cancel_attributions(&tx, raw.as_slice()).await {
                self.note_attribution(&a, &txid.0).await;
            }
            if let Some(obs) = self.prepare_unlock(&tx, raw.as_slice(), None).await? {
                self.note_signatures(&obs).await;
                self.ctx
                    .db(|t| super::ycash::apply_unlock(t, &p, &obs, tip, tip, None, &members))?;
            }
        }
        // c. re-classify (consumption changes as intents are mined) and link burns
        self.reclassify()?;
        self.evict_pending_intents()?;
        // d. act on unmatched intents
        let mut unmatched = self
            .ctx
            .db(|t| t.intents_in_state(IntentState::Unmatched))?;
        // nearest cancel deadline first (finding 05/N-2): a confirmed intent's window closes at
        // confirmed + delay; a mempool intent's has not started
        let delay = u32::from(p.delay);
        unmatched.sort_by_key(|i| i.confirmed_height.unwrap_or(tip + 1).saturating_add(delay));
        for i in unmatched {
            if let Err(e) = self.handle_unmatched(&i).await {
                warn!(event = "cancel_failed", intent = %i.outpoint, error = %format!("{e:#}"));
                self.note_sign_error(&e);
            }
        }
        // e. our cancels not yet mined: re-broadcast the stored bytes (never rebuilt)
        let sent = self
            .ctx
            .db(|t| t.intents_in_state(IntentState::CancelSent))?;
        for i in sent {
            let key = cancel_key(p.set_id, &i.outpoint);
            if self.ctx.db(|t| t.ycash_signature(&key))?.is_some()
                && !self.mem.mempool_spent.contains(&i.outpoint)
            {
                let _ = self.cancel(&i.outpoint).await;
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

    /// Re-run the matcher over the open intents with the ledger's current burns. Rolls are
    /// judged once, when first observed with the V they spend (§4.3), and not re-run here.
    ///
    /// An intent released while its burn was still unknown here (`MATURED_UNMATCHED` as
    /// `unmatched:unknown-burn`, with its release recorded) is re-run too: a restart after the
    /// intent was posted and released by a takeover leader follows those Ycash blocks before it
    /// scans the burn on Ethereum. If it now matches, the release is adopted (intent and burn
    /// `RELEASED`), so the burn is never assigned and posted a second time (drill D-7).
    fn reclassify(&mut self) -> Result<()> {
        let in_mempool = self.mem.mempool_seen.clone();
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        self.ctx.db(|t| {
            let mut open = t.intents_in_state(IntentState::Matched)?;
            open.extend(t.intents_in_state(IntentState::Unmatched)?);
            open.extend(t.intents_in_state(IntentState::Observed)?);
            open.extend(
                t.intents_in_state(IntentState::MaturedUnmatched)?
                    .into_iter()
                    .filter(|i| {
                        i.released_txid.is_some()
                            && i.classification.as_deref() == Some("unmatched:unknown-burn")
                    }),
            );
            for i in open {
                if i.classification.as_deref() == Some("matched-roll")
                    || i.memo.as_deref().is_some_and(|m| {
                        HawkeyeMemo::decode_for(p.bridge_kind, m)
                            .is_ok_and(|m| m.kind == MemoKind::Roll)
                    })
                {
                    continue;
                }
                let ip = IntentParams {
                    tag: p.tag(),
                    recipient_hash: i.recipient_hash,
                    vault_hash: i.vault_hash,
                    delay: p.delay,
                    cancel_set_id: p.set_id,
                    set_id: p.set_id,
                    // a placeholder: classification never reads the owner
                    owner: hawkeye_core::PqKeyId {
                        scheme: hawkeye_core::pq::SCHEME_SLH_DSA_SHA2_128S,
                        hash: [0; 32],
                    },
                };
                let outs: Vec<CoreTxOut> = i
                    .memo
                    .iter()
                    .map(|m| CoreTxOut {
                        value: 0,
                        script_pubkey: op_return_script(m),
                    })
                    .collect();
                let c = classify(
                    t,
                    &p,
                    &IntentFacts {
                        txid: i.outpoint.txid,
                        first_seen: i.first_seen_height,
                        intent: &ip,
                        value: i.value_zat,
                        outputs: &outs,
                        spent_vault: None,
                        origin: i.origin_vault.as_ref(),
                        signer: i.signer_key,
                    },
                );
                if c == Classification::Foreign {
                    continue;
                }
                if i.state == IntentState::MaturedUnmatched {
                    if let Classification::MatchedBurn { nonce } = c {
                        adopt_release(t, &p, &i, nonce, tip)?;
                    }
                    continue;
                }
                let code = classification_code(&c);
                if i.classification.as_deref() != Some(code.as_str()) {
                    t.classify_intent(&i.outpoint, &p.deployment, &c, Some(tip))?;
                    info!(event = "intent_classified", intent = %i.outpoint, classification = %code,
                          previous = ?i.classification);
                }
                // an unmined intent that left the mempool is not re-linked (review M-3): its
                // burn goes back to its leader, who re-sends the signed unlock
                let live = i.confirmed_height.is_some() || in_mempool.contains(&i.outpoint.txid);
                if let Classification::MatchedBurn { nonce } = c
                    && live
                {
                    link_burn(t, &p, nonce, &i.outpoint, i.confirmed_height.is_some(), tip)?;
                }
            }
            Ok(())
        })
    }

    async fn handle_unmatched(&mut self, i: &IntentRecord) -> Result<()> {
        let code = i.classification.clone().unwrap_or_default();
        if code == "unmatched:unknown-burn" && !self.mem.eth_fresh {
            return Ok(()); // this attestor's foreign-chain view may lag the burn's finality
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
        let need = self
            .mem
            .set
            .as_ref()
            .map_or(1, |s| s.set.params.cancelthreshold);
        let leads = need <= 1 || self.cancel_leader(&i.outpoint, i.signer_key) == Some(self.ctx.me);
        if self.mem.mempool_spent.contains(&i.outpoint) {
            tracing::debug!(event = "intent_cancel_pending", intent = %i.outpoint,
                  "a spend of the intent (another attestor's cancel) is in the mempool");
        } else if !leads {
            tracing::debug!(event = "intent_cancel_left_to_leader", intent = %i.outpoint,
                  leader = ?self.cancel_leader(&i.outpoint, i.signer_key).map(hex::encode),
                  "cancelThreshold > 1: the intent's cancel leader builds, the others co-sign");
        } else {
            match self.cancel(&i.outpoint).await {
                Ok(CancelOutcome::Sent(txid)) => {
                    self.ctx
                        .db(|t| t.intent_cancel_sent(&i.outpoint, &txid, Some(tip)))?;
                    warn!(event = "intent_cancel_sent", intent = %i.outpoint, reason = %code,
                          cancel_txid = %txid_to_display(&txid),
                          signer = ?i.signer_key.map(hex::encode));
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(event = "cancel_failed", intent = %i.outpoint, error = %format!("{e:#}"));
                    self.note_sign_error(&e);
                }
            }
        }
        if code == "unmatched:consumed-burn:scheduled" {
            info!(event = "scheduled_duplicate", intent = %i.outpoint,
                  "a correct duplicate by a recorded leader of the burn is cancelled, never slashed");
            return Ok(());
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

    /// Review M-3: a burn whose intent is neither mined nor in the mempool for
    /// `max(TAKEOVER, C_Y)` blocks (the unlock was evicted, or never relayed) goes back to
    /// `FINALIZED`, so it is assigned again and its leader re-sends — or a takeover leader
    /// adopts — the signed unlock. Without it the burn would wait in `INTENT_PENDING` forever.
    fn evict_pending_intents(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let after = p.takeover.max(p.confirmations).max(1);
        let pending = self
            .ctx
            .db(|t| t.burns_in_state(&p.deployment, BurnState::IntentPending))?;
        let mut still = HashSet::new();
        for b in pending {
            let Some(op) = b.intent else { continue };
            let Some(i) = self.ctx.db(|t| t.intent(&op))? else {
                continue;
            };
            if i.confirmed_height.is_some() || self.mem.mempool_seen.contains(&op.txid) {
                self.mem.evicted_since.remove(&op.txid);
                continue;
            }
            still.insert(op.txid);
            let since = *self.mem.evicted_since.entry(op.txid).or_insert(tip);
            if tip.saturating_sub(since) >= after {
                self.ctx.db(|t| t.burn_intent_evicted(&b.key, tip))?;
                self.mem.evicted_since.remove(&op.txid);
                warn!(event = "burn_intent_evicted", nonce = b.key.nonce, intent = %op,
                      blocks = tip - since,
                      "the unlock left the mempool unmined: the burn is assigned again");
            }
        }
        self.mem.evicted_since.retain(|t, _| still.contains(t));
        Ok(())
    }

    /// The member that builds an intent's cancel when `cancelThreshold > 1` (the others
    /// co-sign over `POST /cancel/sign`): the mint schedule over the intent outpoint's id, live
    /// members other than the intent's signer. Two members building two cancels of one intent would each refuse the
    /// other's (sign-once), so exactly one builds.
    pub(crate) fn cancel_leader(
        &self,
        op: &CoreOutPoint,
        signer: Option<hawkeye_core::PubKey33>,
    ) -> Option<hawkeye_core::PubKey33> {
        // never the intent's own signer: it leaves its own intent to the others
        let live: Vec<_> = self
            .live()
            .iter()
            .filter(|k| Some(**k) != signer)
            .copied()
            .collect();
        mint_leader_for(&lock_id(op), &live, 0, 0).copied()
    }

    /// Cancel an intent once: the stored signed cancel if there is one, else
    /// vault_buildcancel → set_signcancel (sign-once) → [`Engine::complete_cancel`] (the peers'
    /// co-signatures when `cancelThreshold > 1`) → vault_send.
    pub(crate) async fn cancel(&mut self, op: &CoreOutPoint) -> Result<CancelOutcome> {
        let key = cancel_key(self.ctx.params.set_id, op);
        let signed = match self.ctx.db(|t| t.ycash_signature(&key))? {
            Some(rec) => rec.signed_hex,
            None => {
                let built = match self.ctx.ycash.vault_buildcancel(&op_rpc(op)).await {
                    Ok(b) => b,
                    Err(e)
                        if e.rpc().is_some_and(|r| {
                            r.code == hawkeye_ycash::error::codes::WALLET_INSUFFICIENT_FUNDS
                        }) =>
                    {
                        warn!(event = "cancel_unfunded", intent = %op, error = %e);
                        self.alarm(
                            "fee-coins-exhausted",
                            format!(
                                "no confirmed fee coin to fund the cancel of {op}: run `hawkeye \
                                 split-coins`"
                            ),
                        );
                        return Err(e.into());
                    }
                    Err(e) => return Err(e.into()),
                };
                // no change output: whoever ever re-funds these bytes pays the fee only (H-1)
                let (_, intent_value) = self
                    .intent_coin_of(op)
                    .await?
                    .ok_or_else(|| anyhow!("intent {op} unknown"))?;
                let built_hex = super::sign::fund_exactly(
                    &self.ctx.ycash,
                    &built.hex.to_string(),
                    op,
                    intent_value,
                )
                .await?;
                let signer = SetSigning::prepare(&self.ctx, &built_hex, Role::Cancel, *op).await?;
                let rec = self.ctx.db(|t| {
                    t.sign_once_ycash(&key, &built_hex, |h| {
                        let o = signer.sign(h)?;
                        Ok::<_, String>((o.hex, o.sighash))
                    })
                })?;
                rec.signed_hex
            }
        };
        let Some(complete) = self.complete_cancel(op, &signed).await? else {
            return Ok(CancelOutcome::Incomplete);
        };
        let hex: HexBytes = complete.parse().map_err(|e| anyhow!("{e}"))?;
        // a lost fee input is re-funded (01/V-2): the cancel must confirm before the delay ends
        match super::sign::send_set_signed(&self.ctx.ycash, &hex, op).await {
            Ok(t) => Ok(CancelOutcome::Sent(t.0)),
            Err(e) if e.rpc().is_some_and(|r| r.is_already_known()) => {
                Ok(CancelOutcome::AlreadyKnown)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// A cancel with at least `cancelThreshold` signatures: as is at threshold 1 (the §2 row),
    /// else with the peers' co-signatures gathered over `POST /cancel/sign` and checked like
    /// unlock co-signatures ([`Adoption`]). `None` while still short.
    pub(crate) async fn complete_cancel(
        &mut self,
        op: &CoreOutPoint,
        signed: &str,
    ) -> Result<Option<String>> {
        let need = self
            .mem
            .set
            .as_ref()
            .map_or(1, |s| s.set.params.cancelthreshold) as usize;
        let ours = Transaction::decode_hex(signed).map_err(|e| anyhow!("{e}"))?;
        let idx = input_index(&ours, op).ok_or_else(|| anyhow!("the cancel spends no {op}"))?;
        let mut have = role_args(&ours, idx, Role::Cancel)?.len();
        if have >= need {
            return Ok(Some(signed.to_owned()));
        }
        let (spk, value) = self
            .intent_coin_of(op)
            .await?
            .ok_or_else(|| anyhow!("intent {op} unknown"))?;
        let members = self.current_member_keys();
        let mut current = ours;
        let mut hex = signed.to_owned();
        let mut peers = self.ctx.peers.urls().to_vec();
        peers.sort_by_key(|u| u32::from(self.mem.peer_backoff.get(u).copied().unwrap_or(0) >= 2));
        for peer in peers {
            let req = CancelSignRequest {
                hex: hex.clone(),
                intent: op.to_string(),
            };
            match self.ctx.peers.cancel_sign(&peer, &req).await {
                Ok(r) => {
                    let check = if self.responder_ok(r.responder) {
                        Adoption {
                            ours: &current,
                            idx,
                            role: Role::Cancel,
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
                            info!(event = "cancel_signature_received", peer = %peer, intent = %op,
                                  signatures = signers.len(), required = need);
                            hex = r.body.hex;
                            current = Transaction::decode_hex(&hex).map_err(|e| anyhow!("{e}"))?;
                            have = signers.len();
                        }
                        Err(e) => {
                            *self.mem.peer_backoff.entry(peer.clone()).or_default() += 1;
                            warn!(event = "cancel_signature_rejected", peer = %peer, intent = %op,
                                  error = %format!("{e:#}"));
                        }
                    }
                    if have >= need {
                        return Ok(Some(hex));
                    }
                }
                Err(e) => info!(event = "cancel_signature_refused", peer = %peer, error = %e),
            }
        }
        warn!(event = "cancel_incomplete", intent = %op, signatures = have, required = need);
        Ok(None)
    }

    /// The fee-coin capacity check (every 20 ticks; finding 05/N-2, plan §5.5 / finding (76)):
    /// confirmed transparent P2PKH wallet coins of at least `VAULT_RPC_FEE +
    /// VAULT_RPC_MIN_CHANGE`, each one cancel this block (the node's `Fund` spends confirmed
    /// coins only). `fee-coins-low` below [`FEE_COINS_FLOOR`], `fee-coins-exhausted` at 0.
    pub(crate) async fn check_fee_coins(&mut self) -> Result<()> {
        if self.mem.fee_coins.is_some() && !self.mem.ticks.is_multiple_of(20) {
            return Ok(());
        }
        let coins = self.ctx.ycash.listunspent(Some(1), None, None).await?;
        let n = count_fee_coins(&coins);
        self.mem.fee_coins = Some(n);
        if n == 0 {
            self.alarm(
                "fee-coins-exhausted",
                "no confirmed wallet coin can fund a cancel: run `hawkeye split-coins`".into(),
            );
        } else {
            self.clear_alarm("fee-coins-exhausted");
        }
        if n < FEE_COINS_FLOOR {
            self.alarm(
                "fee-coins-low",
                format!(
                    "{n} confirmed fee coins < {FEE_COINS_FLOOR}: a flood of intents can outrun \
                     the cancels (`hawkeye split-coins --count 16`)"
                ),
            );
        } else {
            self.clear_alarm("fee-coins-low");
        }
        Ok(())
    }

    /// The script and value of an intent output (ledger cache or the node).
    async fn intent_coin_of(&mut self, op: &CoreOutPoint) -> Result<Option<(Vec<u8>, u64)>> {
        if let Some(o) = self
            .ctx
            .ycash
            .gettxout(&op_rpc(op).txid, op.vout, true)
            .await?
        {
            return Ok(Some((
                o.script_pub_key.hex.0,
                u64::try_from(o.value.zat()).unwrap_or(0),
            )));
        }
        let raw = match self.mem.raw_txs.get(&op.txid) {
            Some(r) => r.clone(),
            None => return Ok(None),
        };
        let tx = Transaction::decode(&raw).map_err(|e| anyhow!("{e}"))?;
        Ok(tx
            .outputs
            .get(op.vout as usize)
            .map(|o| (o.script_pubkey.clone(), u64::try_from(o.value).unwrap_or(0))))
    }
}

/// What [`Engine::cancel`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CancelOutcome {
    /// Broadcast now.
    Sent(hawkeye_core::bytes::Hash32),
    /// Already in the mempool or mined (the txid is learnt when it is mined).
    AlreadyKnown,
    /// Short of `cancelThreshold`: retried next tick.
    Incomplete,
}

/// `VAULT_RPC_FEE` (ycash-dd `src/policy/policy.h:131`, ycash6 `:189`).
pub const VAULT_RPC_FEE_ZAT: i64 = 10_000;
/// `VAULT_RPC_MIN_CHANGE` (`src/rpc/vault.cpp:58` on both lines).
pub const VAULT_RPC_MIN_CHANGE_ZAT: i64 = 1_000;
/// Below this many fee coins `fee-coins-low` is raised (plan §5.5, finding (76)).
pub const FEE_COINS_FLOOR: u64 = 8;

/// The coins of `listunspent` that can fund one vault spend alone: spendable, confirmed,
/// P2PKH, at least `VAULT_RPC_FEE + VAULT_RPC_MIN_CHANGE`.
pub fn count_fee_coins(coins: &[hawkeye_ycash::stock::Unspent]) -> u64 {
    coins
        .iter()
        .filter(|u| {
            u.spendable
                && u.confirmations >= 1
                && hawkeye_core::script::parse_p2pkh(&u.script_pub_key.0).is_some()
                && u.amount_zat >= VAULT_RPC_FEE_ZAT + VAULT_RPC_MIN_CHANGE_ZAT
        })
        .count() as u64
}

/// `POST /cancel/sign` (`cancelThreshold > 1` only): co-sign a member's cancel of an intent only
/// if this attestor's own ledger has judged that intent **unmatched** (`UNMATCHED` or
/// `CANCEL_SENT`: never one it matched, never one it has not seen), the transaction's template
/// input is that intent, and the request is member-signed ([`crate::peer_auth`]); then sign
/// once per intent on this node (`ycash-cancel`).
pub async fn verify_and_sign_cancel(
    ctx: &super::Ctx,
    requester: Option<hawkeye_core::PubKey33>,
    req: &CancelSignRequest,
) -> Result<CancelSignResponse> {
    let set = super::burn::set_snapshot(ctx).await?;
    let need = set.set.params.cancelthreshold;
    anyhow::ensure!(
        need > 1,
        "cancel co-signing is disabled: the set's cancelThreshold is 1 (HK-1); any member \
         cancels alone"
    );
    let requester = requester.ok_or_else(|| {
        anyhow!("unauthenticated request: cancel co-signing answers member-signed requests only")
    })?;
    let op = super::slash::parse_outpoint(&req.intent)?;
    let tx = Transaction::decode_hex(&req.hex).map_err(|e| anyhow!("cancel: {e}"))?;
    let idx = input_index(&tx, &op).ok_or_else(|| anyhow!("the transaction spends no {op}"))?;
    role_args(&tx, idx, Role::Cancel)?;
    // H-1: the cancel moves the intent's value and nothing else
    let iop = op_rpc(&op);
    let coin = ctx
        .ycash
        .gettxout(&iop.txid, iop.vout, true)
        .await?
        .ok_or_else(|| anyhow!("intent {op} is spent"))?;
    super::sign::unlock_value_bounded(&tx, u64::try_from(coin.value.zat()).unwrap_or(0))?;
    let i = ctx
        .db(|t| t.intent(&op))?
        .ok_or_else(|| anyhow!("intent {op} is not in this ledger: not judged here"))?;
    anyhow::ensure!(
        matches!(i.state, IntentState::Unmatched | IntentState::CancelSent),
        "intent {op} is {} here ({}): not cancelled",
        i.state,
        i.classification.as_deref().unwrap_or("unclassified")
    );
    let key = cancel_key(ctx.params.set_id, &op);
    let signer = SetSigning::prepare(ctx, &req.hex, Role::Cancel, op).await?;
    let status = std::cell::Cell::new(None);
    let rec = ctx.db(|t| {
        t.sign_once_ycash(&key, &req.hex, |h| {
            let o = signer.sign(h)?;
            status.set(Some((o.complete, o.signatures, o.required)));
            Ok::<_, String>((o.hex, o.sighash))
        })
    })?;
    let signed = Transaction::decode_hex(&rec.signed_hex).map_err(|e| anyhow!("{e}"))?;
    let n = role_args(&signed, idx, Role::Cancel)?.len() as u32;
    let (complete, signatures, required) = status.get().unwrap_or((n >= need, n, need));
    info!(event = "cancel_cosigned", intent = %op, requester = %hex::encode(requester),
          signatures, required);
    Ok(CancelSignResponse {
        hex: rec.signed_hex,
        complete,
        signatures,
        required,
    })
}

/// Adopt the recorded release of `i` as burn `nonce`'s: intent `MATURED_UNMATCHED → RELEASED`,
/// the burn `→ INTENT_PENDING → INTENT_CONFIRMED → RELEASED` (from `FINALIZED`, `ASSIGNED` or
/// `WAITING_CAP`; a burn already past those is left alone).
fn adopt_release(
    t: &hawkeye_store::Tx<'_>,
    p: &crate::config::Params,
    i: &IntentRecord,
    nonce: u64,
    tip: u32,
) -> Result<(), hawkeye_store::StoreError> {
    let k = BurnKey::new(p.deployment, nonce);
    let Some(b) = t.burn(&k)? else {
        return Ok(());
    };
    if !matches!(
        b.state,
        BurnState::Finalized | BurnState::Assigned | BurnState::WaitingCap
    ) {
        return Ok(());
    }
    t.adopt_release(&i.outpoint, &p.deployment, nonce, Some(tip))?;
    let mined = i.confirmed_height.unwrap_or(tip);
    link_burn(t, p, nonce, &i.outpoint, true, mined)?;
    if t.burn(&k)?
        .is_some_and(|b| b.state == BurnState::IntentConfirmed)
    {
        let released = i.released_height.unwrap_or(tip);
        t.transition_burn(
            &k,
            BurnState::Released,
            Some(released.into()),
            Some("adopted release"),
        )?;
    }
    info!(event = "release_adopted", nonce, intent = %i.outpoint,
          release = %i.released_txid.map(|r| txid_to_display(&r)).unwrap_or_default(),
          "an intent released before this attestor knew its burn pays that burn");
    Ok(())
}

/// The sign-once key of a cancel.
pub fn cancel_key(set_id: [u8; 32], op: &CoreOutPoint) -> YcashSignKey {
    YcashSignKey {
        domain: SignDomain::YcashCancel,
        set_id,
        prevout: *op,
    }
}
