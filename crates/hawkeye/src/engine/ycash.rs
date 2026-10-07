//! Following Ycash (plan §5.1, §5.4): blocks, reorgs, the set's vaults, new locks, and every
//! unlock transaction (an intent's creation) observed in a block or the mempool.

use anyhow::{Context, Result, anyhow};
use hawkeye_core::attribution::Attribution;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::lock::parse_destination;
use hawkeye_core::matcher::{Classification, MatchContext, ObservedIntent, classify_intent};
use hawkeye_core::policy::TxOut as CoreTxOut;
use hawkeye_core::script::{is_op_return, op_return_single_push, parse_p2pkh, parse_p2sh};
use hawkeye_core::template::{TAG_WYEC, TemplateKind, parse_intent, parse_selector, parse_vault};
use hawkeye_core::{IntentParams, OutPoint as CoreOutPoint, PubKey33, VaultParams};
use hawkeye_store::{
    BurnKey, BurnState, Chain, IntentState, NewIntent, NewLock, NewVault, StoreError, Tx,
    VaultState, classification_code,
};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{DecodedScript, TemplateKind as RpcKind, VaultListFilter};
use hawkeye_ycash::{Hash256, HexBytes};
use tracing::{debug, info, warn};

use super::{Engine, SeenSig};
use crate::config::Params;
use crate::convert::{intent_params, op_core, outputs, vault_params};

/// Most blocks processed per tick (the follower catches up over several ticks).
const MAX_BLOCKS_PER_TICK: u32 = 200;

/// An unlock transaction: one spend of a set vault and the intents it creates.
#[derive(Debug, Clone)]
pub struct UnlockObs {
    /// The unlock's txid (internal order).
    pub txid: Hash32,
    /// The template input's index.
    pub input_index: usize,
    /// The vault it spends.
    pub vault: CoreOutPoint,
    /// That vault's scriptPubKey.
    pub vault_spk: Vec<u8>,
    /// That vault's value.
    pub vault_value: u64,
    /// The vault's parameters, if its script parses.
    pub vault_params: Option<VaultParams>,
    /// The template input's selector.
    pub selector: Option<u8>,
    /// The set's intents it creates: (vout, parameters, value).
    pub intents: Vec<(u32, IntentParams, u64)>,
    /// Every output.
    pub outputs: Vec<CoreTxOut>,
    /// The single `OP_RETURN`'s payload, if exactly one.
    pub memo: Option<Vec<u8>>,
    /// Who signed it (if it attributes).
    pub attribution: Option<Attribution>,
    /// The raw transaction.
    pub raw: Vec<u8>,
}

impl UnlockObs {
    /// The first signer, if it is one of `members`.
    pub fn signer(&self, members: &[PubKey33]) -> Option<PubKey33> {
        self.attribution
            .as_ref()?
            .signers
            .iter()
            .map(|s| s.pubkey)
            .find(|k| members.contains(k))
    }
}

/// The matcher context of the configured deployment.
pub fn match_context(p: &Params, tip: u32) -> MatchContext {
    MatchContext {
        deployment: p.deployment,
        set_id: p.set_id,
        takeover: p.takeover,
        min_roll_owner_height: tip.saturating_add(p.min_owner_age),
    }
}

/// Link a matched intent to its burn (and confirm it).
pub fn link_burn(
    t: &Tx<'_>,
    p: &Params,
    nonce: u64,
    op: &CoreOutPoint,
    confirmed: bool,
    height: u32,
) -> Result<(), StoreError> {
    let k = BurnKey::new(p.deployment, nonce);
    let Some(b) = t.burn(&k)? else {
        return Ok(());
    };
    match b.state {
        BurnState::Finalized | BurnState::Assigned | BurnState::WaitingCap => {
            t.burn_intent_pending(&k, op, height)?;
            info!(event = "burn_intent_pending", nonce, intent = %op);
            if confirmed {
                t.transition_burn(&k, BurnState::IntentConfirmed, Some(height.into()), None)?;
                info!(event = "burn_intent_confirmed", nonce, intent = %op);
            }
        }
        BurnState::IntentPending if b.intent.as_ref() == Some(op) && confirmed => {
            t.transition_burn(&k, BurnState::IntentConfirmed, Some(height.into()), None)?;
            info!(event = "burn_intent_confirmed", nonce, intent = %op);
        }
        _ => {}
    }
    Ok(())
}

/// Record an unlock's intents and classify them (§3.2). `first_seen` is the height it was first
/// seen at (the tip for a mempool sighting), `confirmed` its block height.
pub fn apply_unlock(
    t: &Tx<'_>,
    p: &Params,
    obs: &UnlockObs,
    tip: u32,
    first_seen: u32,
    confirmed: Option<u32>,
    members: &[PubKey33],
) -> Result<(), StoreError> {
    let mctx = match_context(p, tip);
    for (vout, ip, value) in &obs.intents {
        if ip.tag != TAG_WYEC || ip.set_id != p.set_id || ip.cancel_set_id != p.set_id {
            continue;
        }
        let op = CoreOutPoint::new(obs.txid, *vout);
        let existed = t.intent(&op)?.is_some();
        let rec = t.insert_intent(&NewIntent {
            outpoint: op,
            value_zat: *value,
            recipient_hash: ip.recipient_hash,
            vault_hash: ip.vault_hash,
            origin_vault: Some(obs.vault),
            signer_key: obs.signer(members),
            memo: obs.memo.clone(),
            first_seen_height: first_seen,
            confirmed_height: confirmed,
        })?;
        if !existed {
            info!(event = "intent_observed", intent = %op, value = *value, confirmed = ?confirmed,
                  signer = ?rec.signer_key.map(hex::encode));
        }
        match rec.state {
            IntentState::Observed | IntentState::Matched | IntentState::Unmatched => {
                let c = classify_intent(
                    &mctx,
                    &ObservedIntent {
                        txid: obs.txid,
                        first_seen: rec.first_seen_height,
                        intent: ip,
                        value: *value,
                        outputs: &obs.outputs,
                        spent_vault: obs.vault_params.as_ref(),
                    },
                    |n| t.matcher_burn(&p.deployment, n).ok().flatten(),
                );
                if c == Classification::Foreign {
                    continue;
                }
                let code = classification_code(&c);
                if rec.classification.as_deref() != Some(code.as_str()) {
                    t.classify_intent(&op, &p.deployment, &c, Some(tip))?;
                    info!(event = "intent_classified", intent = %op, classification = %code);
                }
                if let Classification::MatchedBurn { nonce } = c {
                    link_burn(t, p, nonce, &op, rec.confirmed_height.is_some(), tip)?;
                }
            }
            _ => {
                if let (Some(h), Some(k)) = (rec.confirmed_height, rec.matched_burn) {
                    link_burn(t, p, k.nonce, &op, true, h)?;
                }
            }
        }
    }
    Ok(())
}

/// Spends of the set's vaults and intents by a mined transaction: vault `SPENT`, intent
/// `CANCELLED` (selector 2) or `RELEASED` (selector 1), and the burn moves with its intent.
fn apply_spends(t: &Tx<'_>, tx: &Transaction, txid: &Hash32, h: u32) -> Result<(), StoreError> {
    for input in &tx.inputs {
        let op = op_core(&input.prevout);
        if let Some(v) = t.vault(&op)?
            && matches!(
                v.state,
                VaultState::Live | VaultState::RollDue | VaultState::Rolling
            )
        {
            t.vault_spent(&op, VaultState::Spent, txid, h)?;
            info!(event = "vault_spent", vault = %op, by = %hawkeye_core::bytes::txid_to_display(txid), height = h);
        }
        let Some(i) = t.intent(&op)? else {
            continue;
        };
        let selector = parse_selector(TemplateKind::Intent, &input.script_sig)
            .map(|s| s.selector)
            .ok();
        let burn = t.burn_for_intent(&op)?;
        match selector {
            Some(1) => {
                if i.state == IntentState::Matched {
                    t.intent_released(&op, txid, h)?;
                    info!(event = "intent_released", intent = %op, height = h);
                    if let Some(b) = burn
                        && b.state == BurnState::IntentConfirmed
                    {
                        t.transition_burn(&b.key, BurnState::Released, Some(h.into()), None)?;
                        info!(event = "burn_released", nonce = b.key.nonce, intent = %op);
                    }
                } else if matches!(i.state, IntentState::Unmatched | IntentState::CancelSent) {
                    t.transition_intent(
                        &op,
                        IntentState::MaturedUnmatched,
                        Some(h),
                        Some("released unmatched"),
                    )?;
                    warn!(event = "intent_matured_unmatched", intent = %op, height = h);
                }
            }
            Some(2) => {
                if matches!(
                    i.state,
                    IntentState::Unmatched | IntentState::CancelSent | IntentState::Matched
                ) {
                    t.intent_cancelled(&op, txid, h)?;
                    info!(event = "intent_cancel_mined", intent = %op, height = h,
                          by_us = i.cancel_txid.as_ref() == Some(txid));
                }
                if let Some(b) = burn
                    && matches!(
                        b.state,
                        BurnState::IntentPending | BurnState::IntentConfirmed
                    )
                {
                    t.transition_burn(&b.key, BurnState::Cancelled, Some(h.into()), None)?;
                    t.transition_burn(
                        &b.key,
                        BurnState::Finalized,
                        Some(h.into()),
                        Some("intent cancelled: reassign"),
                    )?;
                    info!(event = "burn_reassign", nonce = b.key.nonce, cancelled_intent = %op);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The set's V outputs of a mined transaction (vaults), and the lock it is if it spends no
/// template of the set (a deposit).
fn apply_outputs(
    t: &Tx<'_>,
    p: &Params,
    tx: &Transaction,
    txid: &Hash32,
    h: u32,
    block_hash: &Hash32,
) -> Result<(), StoreError> {
    let mut spends_template = false;
    for i in &tx.inputs {
        let op = op_core(&i.prevout);
        if t.vault(&op)?.is_some() || t.intent(&op)?.is_some() {
            spends_template = true;
        }
    }
    let returns: Vec<&hawkeye_ycash::tx::TxOut> = tx
        .outputs
        .iter()
        .filter(|o| is_op_return(&o.script_pubkey))
        .collect();
    let destination = match returns.as_slice() {
        [one] => parse_destination(&one.script_pubkey).ok(),
        _ => None,
    };
    for (n, o) in tx.outputs.iter().enumerate() {
        let Ok(v) = parse_vault(&o.script_pubkey) else {
            continue;
        };
        if v.tag != TAG_WYEC || v.set_id != p.set_id {
            continue;
        }
        let op = CoreOutPoint::new(*txid, n as u32);
        let value = u64::try_from(o.value).unwrap_or(0);
        match t.insert_vault(&NewVault {
            outpoint: op,
            value_zat: value,
            owner_height: v.owner_height,
            created_height: h,
        }) {
            Ok(_) | Err(StoreError::Duplicate { .. }) => {}
            Err(e) => return Err(e),
        }
        if !spends_template {
            let rec = t.insert_lock(&NewLock {
                outpoint: op,
                value_zat: value,
                owner_height: v.owner_height,
                destination,
                block_hash: *block_hash,
                block_height: h,
            })?;
            info!(event = "lock_seen", lock_id = %format!("0x{}", hex::encode(rec.lock_id)),
                  outpoint = %op, value, height = h,
                  to = ?destination.map(|d| d.to_checksum()));
        }
    }
    Ok(())
}

impl Engine {
    async fn start_height(&self) -> Result<u32> {
        if let Some(h) = self.ctx.params.ycash_start_height {
            return Ok(h);
        }
        let info = self.ctx.ycash.vault_getinfo().await?;
        Ok(if info.activationheight >= 0 {
            u32::try_from(info.activationheight)
                .unwrap_or(0)
                .max(1)
                .min(self.mem.tip)
        } else {
            self.mem.tip
        })
    }

    /// Follow the active chain: rewind on a reorg, then process new blocks in order.
    pub(crate) async fn follow_ycash(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let cursor = self.ctx.db(|t| t.cursor(Chain::Ycash))?;
        let next = match cursor {
            None => self.start_height().await?,
            Some(c) => {
                let h = u32::try_from(c.height).unwrap_or(u32::MAX);
                let mut fork = h.min(tip);
                loop {
                    let ours = self
                        .ctx
                        .db(|t| t.block_hash(Chain::Ycash, u64::from(fork)))?;
                    let Some(ours) = ours else { break };
                    let node = self.ctx.ycash.getblockhash(fork).await?;
                    if node.0 == ours || fork == 0 {
                        break;
                    }
                    fork -= 1;
                }
                if fork < h {
                    let r = self.ctx.db(|t| t.rewind_ycash_to(fork))?;
                    warn!(
                        event = "ycash_reorg",
                        from = h,
                        to = fork,
                        locks_deleted = r.locks_deleted.len(),
                        exposures = r.exposures.len(),
                        intents_unconfirmed = r.intents_unconfirmed.len()
                    );
                    self.mem.mempool_seen.clear();
                    if !r.exposures.is_empty() {
                        let ids: Vec<String> = r.exposures.iter().map(hex::encode).collect();
                        self.alarm(
                            "exposure",
                            format!("signed locks left the active chain: {}", ids.join(", ")),
                        );
                    }
                }
                fork + 1
            }
        };
        let end = tip.min(next.saturating_add(MAX_BLOCKS_PER_TICK - 1));
        for h in next..=end {
            self.process_block(h)
                .await
                .with_context(|| format!("block {h}"))?;
        }
        Ok(())
    }

    async fn process_block(&mut self, h: u32) -> Result<()> {
        let hash = self.ctx.ycash.getblockhash(h).await?;
        let block = self.ctx.ycash.getblock_txs(&hash).await?;
        let mut txs = Vec::with_capacity(block.tx.len());
        for info in &block.tx {
            let Some(hex) = &info.hex else {
                return Err(anyhow!("getblock 2 without tx hex"));
            };
            let tx = Transaction::decode(hex.as_slice())
                .map_err(|e| anyhow!("tx {}: {e}", info.txid))?;
            if tx.inputs.iter().any(|i| i.is_coinbase()) {
                continue;
            }
            // vaults created here may be spent later in the same block
            self.cache_vault_outputs(&tx, info.txid.0);
            let obs = self.prepare_unlock(&tx, hex.as_slice(), None).await?;
            txs.push((tx, info.txid.0, obs));
        }
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let members = self.current_member_keys();
        for (_, _, obs) in &txs {
            if let Some(o) = obs {
                self.note_signatures(o).await;
            }
        }
        self.ctx.db(|t| {
            for (tx, txid, obs) in &txs {
                apply_spends(t, tx, txid, h)?;
                if let Some(o) = obs {
                    apply_unlock(t, &p, o, tip, h, Some(h), &members)?;
                }
                apply_outputs(t, &p, tx, txid, h, &hash.0)?;
            }
            t.advance_cursor(Chain::Ycash, u64::from(h), &hash.0)?;
            if h > 1000 {
                t.prune_blocks(Chain::Ycash, u64::from(h - 1000))?;
            }
            Ok(())
        })?;
        debug!(event = "ycash_block", height = h, hash = %hash, txs = txs.len());
        Ok(())
    }

    fn cache_vault_outputs(&mut self, tx: &Transaction, txid: Hash32) {
        for (n, o) in tx.outputs.iter().enumerate() {
            if let Ok(v) = parse_vault(&o.script_pubkey)
                && v.tag == TAG_WYEC
                && v.set_id == self.ctx.params.set_id
            {
                self.mem.vault_scripts.insert(
                    CoreOutPoint::new(txid, n as u32),
                    (o.script_pubkey.clone(), u64::try_from(o.value).unwrap_or(0)),
                );
            }
        }
    }

    /// The script and value of a set vault (cache; else the ledger's creating block).
    async fn vault_coin(&mut self, op: &CoreOutPoint) -> Result<Option<(Vec<u8>, u64)>> {
        if let Some(c) = self.mem.vault_scripts.get(op) {
            return Ok(Some(c.clone()));
        }
        let Some(v) = self.ctx.db(|t| t.vault(op))? else {
            return Ok(None);
        };
        let bh = self.ctx.ycash.getblockhash(v.created_height).await?;
        let info = self
            .ctx
            .ycash
            .getrawtransaction_verbose(&Hash256::from_internal(op.txid), Some(&bh))
            .await?;
        let Some(o) = info.vout.iter().find(|o| o.n == op.vout) else {
            return Ok(None);
        };
        let c = (o.script_pub_key.hex.0.clone(), v.value_zat);
        self.mem.vault_scripts.insert(*op, c.clone());
        Ok(Some(c))
    }

    /// If `tx` spends one of the set's vaults: the intents it creates, its memo and its signer.
    /// `origin` supplies the vault script when the vault is not known here (an intent found by
    /// `vault_list` whose vault predates this ledger).
    pub(crate) async fn prepare_unlock(
        &mut self,
        tx: &Transaction,
        raw: &[u8],
        origin: Option<&[u8]>,
    ) -> Result<Option<UnlockObs>> {
        let mut found = None;
        for (idx, input) in tx.inputs.iter().enumerate() {
            let op = op_core(&input.prevout);
            if let Some(c) = self.vault_coin(&op).await? {
                found = Some((idx, op, c));
                break;
            }
        }
        let (idx, vault, (vault_spk, vault_value)) = match (found, origin) {
            (Some(f), _) => f,
            (None, Some(spk)) if !tx.inputs.is_empty() => {
                // vault_buildunlock puts the template input first
                let op = op_core(&tx.inputs[0].prevout);
                let value = self.prev_value(&op).await.unwrap_or(0);
                (0, op, (spk.to_vec(), value))
            }
            _ => return Ok(None),
        };
        let selector = parse_selector(TemplateKind::Vault, &tx.inputs[idx].script_sig)
            .map(|s| s.selector)
            .ok();
        let mut intents = vec![];
        for (n, o) in tx.outputs.iter().enumerate() {
            let spk = &o.script_pubkey;
            if is_op_return(spk)
                || parse_p2pkh(spk).is_some()
                || parse_p2sh(spk).is_some()
                || parse_vault(spk).is_ok()
            {
                continue;
            }
            let ip = match parse_intent(spk) {
                Ok(ip) => ip,
                Err(_) => {
                    // the node's decoder (the mock's placeholder templates; any shape we lack)
                    match self
                        .ctx
                        .ycash
                        .vault_decodescript(&HexBytes(spk.clone()))
                        .await
                    {
                        Ok(DecodedScript::Intent(f)) => intent_params(&f)?,
                        _ => continue,
                    }
                }
            };
            intents.push((n as u32, ip, u64::try_from(o.value).unwrap_or(0)));
        }
        let returns: Vec<&[u8]> = tx
            .outputs
            .iter()
            .filter(|o| is_op_return(&o.script_pubkey))
            .filter_map(|o| op_return_single_push(&o.script_pubkey))
            .collect();
        let memo = match returns.as_slice() {
            [one] => Some(one.to_vec()),
            _ => None,
        };
        let attribution = if selector == Some(1) {
            match self.ctx.attributor.attribute(
                raw,
                idx,
                &vault_spk,
                vault_value,
                hawkeye_core::VAULT_BRANCH_ID,
            ) {
                Ok(a) => Some(a),
                Err(e) => {
                    debug!(event = "attribution_failed", txid = %tx.txid(), error = %e);
                    None
                }
            }
        } else {
            None
        };
        let txid = tx.txid().0;
        if !intents.is_empty() {
            self.mem.raw_txs.insert(txid, raw.to_vec());
        }
        Ok(Some(UnlockObs {
            txid,
            input_index: idx,
            vault,
            vault_params: parse_vault(&vault_spk).ok(),
            vault_spk,
            vault_value,
            selector,
            intents,
            outputs: outputs(tx),
            memo,
            attribution,
            raw: raw.to_vec(),
        }))
    }

    async fn prev_value(&self, op: &CoreOutPoint) -> Result<u64> {
        let raw = self
            .ctx
            .ycash
            .getrawtransaction(&Hash256::from_internal(op.txid))
            .await?;
        let tx = Transaction::decode(raw.as_slice()).map_err(|e| anyhow!("{e}"))?;
        let o = tx
            .outputs
            .get(op.vout as usize)
            .ok_or_else(|| anyhow!("no output"))?;
        Ok(u64::try_from(o.value).unwrap_or(0))
    }

    /// Record the set signatures of an unlock; two different signatures by one key over one
    /// prevout are an equivocation, submitted at once (§2.3 row 1, §5.3 step 4).
    pub(crate) async fn note_signatures(&mut self, obs: &UnlockObs) {
        let Some(a) = &obs.attribution else { return };
        let members = self.current_member_keys();
        let mut proofs = vec![];
        let seen = self.mem.sigs_seen.entry(a.prevout).or_default();
        for s in &a.signers {
            if !members.contains(&s.pubkey) {
                continue;
            }
            let role = a.role.byte();
            if let Some(prev) = seen
                .iter()
                .find(|x| x.key == s.pubkey && (x.role != role || x.sighash != a.sighash))
            {
                proofs.push((prev.clone(), role, a.sighash, s.pubkey, s.signature));
            }
            if !seen
                .iter()
                .any(|x| x.key == s.pubkey && x.role == role && x.sighash == a.sighash)
            {
                seen.push(SeenSig {
                    role,
                    sighash: a.sighash,
                    key: s.pubkey,
                    sig: s.signature,
                });
            }
        }
        for (prev, role, sighash, key, sig) in proofs {
            if !self.mem.equivocations_sent.insert((a.prevout, key)) {
                continue;
            }
            let proof = hawkeye_ycash::types::Proof {
                setid: self.ctx.set_hash(),
                prevout: crate::convert::op_rpc(&a.prevout),
                rolea: prev.role,
                sighasha: hawkeye_ycash::Bytes32(prev.sighash),
                siga: HexBytes(prev.sig.to_vec()),
                roleb: role,
                sighashb: hawkeye_ycash::Bytes32(sighash),
                sigb: HexBytes(sig.to_vec()),
            };
            let evidence = serde_json::json!({
                "fault": "EQUIVOCATION",
                "set_id": hawkeye_core::bytes::txid_to_display(&self.ctx.params.set_id),
                "target": hex::encode(key),
                "proof": proof,
            });
            let tip = self.mem.tip;
            let _ = self.ctx.db(|t| {
                t.open_slash_case(&hawkeye_store::NewSlashCase {
                    target_key: key,
                    fault: hawkeye_store::FaultKind::Equivocation,
                    subject: a.prevout.to_bytes().to_vec(),
                    evidence_json: evidence.to_string(),
                    opened_height: Some(tip),
                })
            });
            match self.ctx.ycash.set_equivocation(&proof).await {
                Ok(txid) => {
                    warn!(event = "equivocation_submitted", member = %hex::encode(key),
                          prevout = %a.prevout, txid = %txid)
                }
                Err(e) => {
                    warn!(event = "equivocation_failed", member = %hex::encode(key),
                          prevout = %a.prevout, error = %e)
                }
            }
        }
    }

    /// Bring the ledger's vault table and the script cache in line with `vault_list` (vaults
    /// created before the ledger's start), and total the locked value.
    pub(crate) async fn sync_vaults(&mut self) -> Result<()> {
        let rows = self
            .ctx
            .ycash
            .vault_list(Some(&VaultListFilter {
                tag: Some("WYEC".into()),
                setid: Some(self.ctx.set_hash()),
                kind: Some(RpcKind::Vault),
                ..VaultListFilter::default()
            }))
            .await?;
        let mut locked = 0u64;
        let mut new = vec![];
        for r in rows.iter().filter_map(|r| r.as_vault()) {
            if r.fields.setid != self.ctx.set_hash() {
                continue;
            }
            let Ok(vp) = vault_params(&r.fields) else {
                continue;
            };
            if vp.tag != TAG_WYEC {
                continue;
            }
            let op = op_core(&r.outpoint);
            let value = u64::try_from(r.valuezat).unwrap_or(0);
            locked = locked.saturating_add(value);
            self.mem
                .vault_scripts
                .insert(op, (r.script.0.clone(), value));
            new.push(NewVault {
                outpoint: op,
                value_zat: value,
                owner_height: vp.owner_height,
                created_height: r.height,
            });
        }
        self.mem.locked_value = locked;
        let cursor = self
            .ctx
            .db(|t| t.cursor(Chain::Ycash))?
            .map_or(0, |c| c.height);
        self.ctx.db(|t| {
            for v in &new {
                // only vaults the follower has passed (it inserts the others itself, in order)
                if u64::from(v.created_height) <= cursor && t.vault(&v.outpoint)?.is_none() {
                    t.insert_vault(v)?;
                    info!(event = "vault_synced", vault = %v.outpoint, value = v.value_zat);
                }
            }
            Ok(())
        })?;
        Ok(())
    }
}
