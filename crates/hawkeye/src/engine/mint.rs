//! The mint side (plan §1.2, §4.1, §5.3 step 2): lock policy after `C_Y`, the EIP-712 `Mint`
//! signature (sign-once), leader submission, the finalized event scan, and the mint watcher.

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use anyhow::{Result, anyhow};
use hawkeye_core::EthAddress;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::eip712::Domain;
use hawkeye_core::leader::mint_leader_for;
use hawkeye_core::policy::LockFacts;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_eth::bindings::{OptimisticMintBridge, WyecBridge};
use hawkeye_eth::{BridgeEvent, MintMode, MintSubmitted, U256};
use hawkeye_store::{
    BurnKey, BurnState, Chain, FaultKind, LockState, NewBurn, NewSlashCase, PendingMintRecord,
    StoreError, Tx,
};
use hawkeye_ycash::Hash256;
use hawkeye_ycash::tx::Transaction;
use tracing::{info, warn};

use super::Engine;
use crate::convert::{addr, b256, eth_addr, outputs};

/// Most Ethereum blocks scanned per tick.
const MAX_ETH_BLOCKS_PER_TICK: u64 = 5_000;

/// What a `Minted` event means for the ledger.
enum MintVerdict {
    /// Matches a policy-OK lock: recorded.
    Ok,
    /// Not decidable yet (this attestor has not evaluated the lock).
    Defer,
    /// No policy-OK lock with this `(amount, to)` behind it.
    Fraud(String),
}

fn lock_hex(id: &Hash32) -> String {
    format!("0x{}", hex::encode(id))
}

/// Judge a `Minted(lockId, to, amount)` against the ledger and, if it matches, move the lock to
/// `MINTED`.
fn judge_minted(
    t: &Tx<'_>,
    lock_id: &Hash32,
    to: &EthAddress,
    amount: u64,
    block: u64,
    proposal: bool,
) -> Result<MintVerdict, StoreError> {
    let Some(l) = t.lock(lock_id)? else {
        return Ok(MintVerdict::Defer);
    };
    use LockState::*;
    if matches!(l.state, Seen | Confirmed) {
        return Ok(MintVerdict::Defer);
    }
    if l.state == PolicyRejected {
        return Ok(MintVerdict::Fraud(format!(
            "lock refused by policy: {}",
            l.rejection_reason.unwrap_or_default()
        )));
    }
    if l.value_zat != amount || l.destination != Some(*to) {
        return Ok(MintVerdict::Fraud(format!(
            "lock is {} zat to {:?}, minted {amount} to {to}",
            l.value_zat,
            l.destination.map(|d| d.to_checksum())
        )));
    }
    if l.state == Reorged {
        return Ok(MintVerdict::Ok);
    }
    let h = Some(u32::try_from(block).unwrap_or(u32::MAX));
    if proposal {
        if l.state == Signed || l.state == Challenged {
            t.transition_lock(lock_id, Proposed, None, Some("proposal observed"))?;
        }
        return Ok(MintVerdict::Ok);
    }
    let path: &[LockState] = match l.state {
        PolicyOk | Signed | MintSubmitted | Executed => &[Minted],
        Proposed => &[Executed, Minted],
        Challenged => &[Proposed, Executed, Minted],
        _ => &[],
    };
    for s in path {
        t.transition_lock(lock_id, *s, h, Some("Minted observed (finalized)"))?;
    }
    if !path.is_empty() {
        info!(event = "mint_observed", lock_id = %lock_hex(lock_id), amount, to = %to.to_checksum(), block);
    }
    Ok(MintVerdict::Ok)
}

impl Engine {
    /// Scan finalized Ethereum blocks: burns into the ledger (orphans held, §3.4), `Minted` /
    /// `MintProposed` checked against locks.
    pub(crate) async fn scan_eth(&mut self) -> Result<()> {
        self.mem.eth_fresh = false;
        let fin = self
            .ctx
            .eth
            .finalized_block_number()
            .await
            .map_err(|e| anyhow!("finalized block: {e}"))?;
        self.mem.eth_finalized = fin;
        let cursor = self.ctx.db(|t| t.cursor(Chain::Ethereum))?;
        let from = cursor.map_or(self.ctx.params.eth_start_block, |c| c.height + 1);
        if fin < from {
            self.mem.eth_fresh = true;
            return Ok(());
        }
        let to = fin.min(from + MAX_ETH_BLOCKS_PER_TICK - 1);
        let events = self
            .ctx
            .eth
            .scan(from, to)
            .await
            .map_err(|e| anyhow!("scan {from}..={to}: {e}"))?;
        let to_hash = self
            .ctx
            .eth
            .provider()
            .get_block_by_number(BlockNumberOrTag::Number(to))
            .await?
            .ok_or_else(|| anyhow!("block {to} not found"))?
            .header
            .hash;
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let mut frauds = vec![];
        let mut rotated = false;
        self.ctx.db(|t| {
            for ev in &events {
                let m = &ev.meta;
                match &ev.event {
                    BridgeEvent::Burn {
                        nonce,
                        from,
                        amount,
                        ycash_recipient,
                    } => {
                        let nonce = u64::try_from(*nonce).unwrap_or(u64::MAX);
                        let amount = u64::try_from(*amount).unwrap_or(u64::MAX);
                        let key = BurnKey::new(p.deployment, nonce);
                        let existed = t.burn(&key)?.is_some();
                        let rec = t.insert_burn(&NewBurn {
                            key,
                            tx_hash: m.tx_hash.0,
                            block_number: m.block_number,
                            block_hash: m.block_hash.0,
                            from: eth_addr(from),
                            amount,
                            recipient: ycash_recipient.0,
                            finalized: true,
                        })?;
                        if existed {
                            continue;
                        }
                        let recipient = YcashRecipient::from_bytes32(&ycash_recipient.0);
                        info!(event = "burn_finalized", nonce, amount, tx = %m.tx_hash,
                              block = m.block_number,
                              recipient = ?recipient.as_ref().ok().map(|r| hawkeye_core::address::encode_address(r, p.network)));
                        if rec.state == BurnState::Finalized && (amount == 0 || recipient.is_err())
                        {
                            let why = if amount == 0 {
                                "zero amount"
                            } else {
                                "recipient does not decode (§4.2)"
                            };
                            t.transition_burn(
                                &key,
                                BurnState::Orphaned,
                                Some(m.block_number),
                                Some(why),
                            )?;
                            warn!(event = "burn_orphaned", nonce, reason = why);
                        }
                    }
                    BridgeEvent::Minted {
                        lock_id,
                        to,
                        amount,
                    }
                    | BridgeEvent::MintProposed {
                        lock_id,
                        to,
                        amount,
                        ..
                    } => {
                        let proposal = matches!(ev.event, BridgeEvent::MintProposed { .. });
                        let amount = u64::try_from(*amount).unwrap_or(u64::MAX);
                        let pm = PendingMintRecord {
                            lock_id: lock_id.0,
                            to: eth_addr(to),
                            amount,
                            tx_hash: m.tx_hash.0,
                            block: m.block_number,
                            since_height: tip,
                            proposal,
                        };
                        match judge_minted(t, &pm.lock_id, &pm.to, amount, m.block_number, proposal)?
                        {
                            MintVerdict::Ok => {}
                            MintVerdict::Defer => {
                                // persisted with the cursor: a restart re-judges it
                                if t.add_pending_mint(&pm)? {
                                    info!(event = "mint_check_deferred", lock_id = %lock_hex(&pm.lock_id),
                                          proposal);
                                }
                            }
                            MintVerdict::Fraud(why) => frauds.push((pm, why)),
                        }
                    }
                    BridgeEvent::MintChallenged { lock_id, .. } => {
                        if t.lock(&lock_id.0)?.is_some_and(|l| l.state == LockState::Proposed) {
                            t.transition_lock(
                                &lock_id.0,
                                LockState::Challenged,
                                None,
                                Some("challenged"),
                            )?;
                        }
                    }
                    BridgeEvent::GuardiansChanged {
                        guardians,
                        threshold,
                    } => {
                        info!(event = "guardians_changed", count = guardians.len(), threshold);
                        rotated = true;
                    }
                    BridgeEvent::Paused { paused, account } => {
                        warn!(event = "bridge_paused", paused, by = %account);
                    }
                }
            }
            t.advance_cursor(Chain::Ethereum, to, &to_hash.0)?;
            Ok(())
        })?;
        if rotated {
            self.mem.guardian_check_due = true;
        }
        for (pm, why) in frauds {
            self.fraudulent_mint(&pm, &why).await?;
        }
        self.mem.eth_fresh = to == fin;
        Ok(())
    }

    /// Re-judge deferred `Minted` / `MintProposed` events (from the ledger, so a restart resumes
    /// them); one with still no lock long after is a fraud.
    pub(crate) async fn check_pending_mints(&mut self) -> Result<()> {
        let pending = self.ctx.db(|t| t.pending_mints())?;
        if pending.is_empty() {
            return Ok(());
        }
        let tip = self.mem.tip;
        let grace = 2 * self.ctx.params.confirmations + 2 * self.ctx.params.takeover + 10;
        let caught_up = self
            .ctx
            .db(|t| t.cursor(Chain::Ycash))?
            .is_some_and(|c| c.height >= u64::from(tip));
        for pm in pending {
            let v = self.ctx.db(|t| {
                let v = judge_minted(t, &pm.lock_id, &pm.to, pm.amount, pm.block, pm.proposal)?;
                if matches!(v, MintVerdict::Ok) {
                    t.remove_pending_mint(&pm.lock_id, &pm.tx_hash)?;
                }
                Ok(v)
            })?;
            let why = match v {
                MintVerdict::Ok => continue,
                MintVerdict::Fraud(why) => why,
                MintVerdict::Defer if caught_up && tip >= pm.since_height + grace => {
                    "no policy-OK lock behind the lockId".to_owned()
                }
                MintVerdict::Defer => continue,
            };
            self.fraudulent_mint(&pm, &why).await?;
            self.ctx
                .db(|t| t.remove_pending_mint(&pm.lock_id, &pm.tx_hash))?;
        }
        Ok(())
    }

    /// A mint with no lock behind it (§2.3 row 3): recover its signers from the transaction's
    /// calldata, open a slash case against each member among them, alarm.
    async fn fraudulent_mint(&mut self, pm: &PendingMintRecord, why: &str) -> Result<()> {
        warn!(event = "fraudulent_mint", lock_id = %lock_hex(&pm.lock_id), amount = pm.amount,
              to = %pm.to.to_checksum(), tx = %format!("0x{}", hex::encode(pm.tx_hash)),
              proposal = pm.proposal, reason = why);
        self.alarm(
            "fraudulent-mint",
            format!(
                "{} of lockId {} has no lock: {why}",
                if pm.proposal { "mint proposal" } else { "mint" },
                lock_hex(&pm.lock_id)
            ),
        );
        if pm.proposal {
            self.challenge(pm).await;
        }
        let digest = Domain::new(
            self.ctx.params.deployment.chain_id,
            self.ctx.params.deployment.bridge,
        )
        .mint_digest(&pm.lock_id, pm.amount, &pm.to);
        let sigs = match self
            .ctx
            .eth
            .provider()
            .get_transaction_by_hash(b256(&pm.tx_hash))
            .await?
        {
            Some(tx) => {
                let input = tx.input();
                if let Ok(c) = WyecBridge::mintCall::abi_decode(input) {
                    c.sigs.into_iter().map(|b| b.to_vec()).collect()
                } else if let Ok(c) = OptimisticMintBridge::proposeMintCall::abi_decode(input) {
                    vec![c.sig.to_vec()]
                } else {
                    vec![]
                }
            }
            None => vec![],
        };
        let mut signers = vec![];
        for s in &sigs {
            if let Ok(a) = hawkeye_core::eth::recover_address(&digest, s) {
                signers.push((a, s.clone()));
            }
        }
        let tip = self.mem.tip;
        let members = self.current_member_keys();
        for (a, sig) in signers {
            let Some(key) = members
                .iter()
                .find(|k| hawkeye_core::eth::address_from_pubkey(&k[..]).ok() == Some(a))
            else {
                continue;
            };
            if *key == self.ctx.me {
                // this attestor's own signature (a drill, or its own fault): the others judge it
                warn!(event = "own_fraudulent_mint", lock_id = %lock_hex(&pm.lock_id));
                continue;
            }
            let evidence = serde_json::json!({
                "fault": "FRAUDULENT_MINT",
                "set_id": hawkeye_core::bytes::txid_to_display(&self.ctx.params.set_id),
                "target": hex::encode(key),
                "subject": hex::encode(pm.lock_id),
                "lock_id": lock_hex(&pm.lock_id),
                "amount": pm.amount,
                "to": pm.to.to_checksum(),
                "eth_tx": format!("0x{}", hex::encode(pm.tx_hash)),
                "eth_block": pm.block,
                "signer": a.to_checksum(),
                "signature": format!("0x{}", hex::encode(&sig)),
                "reason": why,
            });
            let (case, new) = self.ctx.db(|t| {
                t.open_slash_case(&NewSlashCase {
                    target_key: *key,
                    fault: FaultKind::FraudulentMint,
                    subject: pm.lock_id.to_vec(),
                    evidence_json: evidence.to_string(),
                    opened_height: Some(tip),
                })
            })?;
            if new {
                warn!(event = "slash_case_opened", case = case.id, fault = "FRAUDULENT_MINT",
                      target = %hex::encode(key), lock_id = %lock_hex(&pm.lock_id));
            }
        }
        Ok(())
    }

    /// CR-W1: challenge a fraudulent proposal while it is still pending (the proposal must be
    /// the one judged: same amount and recipient). Any one guardian's challenge deletes it, so a
    /// second attestor finding it gone does nothing.
    async fn challenge(&mut self, pm: &PendingMintRecord) {
        if self.ctx.params.mint_mode != MintMode::Optimistic {
            return;
        }
        let id = b256(&pm.lock_id);
        match self.ctx.eth.proposal(id).await {
            Ok(Some(p)) if p.amount == U256::from(pm.amount) && p.to == addr(&pm.to) => {
                match self.ctx.eth.challenge_mint(id).await {
                    Ok(m) => warn!(event = "mint_challenged", lock_id = %lock_hex(&pm.lock_id),
                                   proposer = %p.proposer, tx = %m.tx),
                    Err(e) => warn!(event = "mint_challenge_failed",
                                    lock_id = %lock_hex(&pm.lock_id), error = %e),
                }
            }
            Ok(Some(_)) => {
                info!(event = "mint_challenge_skipped", lock_id = %lock_hex(&pm.lock_id),
                                 reason = "a different proposal is pending")
            }
            Ok(None) => info!(event = "mint_challenge_skipped", lock_id = %lock_hex(&pm.lock_id),
                              reason = "no pending proposal (challenged or executed)"),
            Err(e) => warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&pm.lock_id),
                            error = %e),
        }
    }

    /// `SEEN` locks with `C_Y` confirmations: `CONFIRMED`, then the lock policy (§4.1).
    pub(crate) async fn evaluate_locks(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let c_y = self.ctx.params.confirmations;
        let seen = self.ctx.db(|t| t.locks_in_state(LockState::Seen))?;
        let policy = self.ctx.params.lock_policy();
        for l in seen {
            let confs = (tip + 1).saturating_sub(l.block_height);
            if confs < c_y {
                continue;
            }
            let node_hash = self.ctx.ycash.getblockhash(l.block_height).await?;
            let on_active = node_hash.0 == l.block_hash;
            if !on_active {
                continue; // the follower rewinds it
            }
            let info = self
                .ctx
                .ycash
                .getrawtransaction_verbose(
                    &Hash256::from_internal(l.outpoint.txid),
                    Some(&node_hash),
                )
                .await?;
            let hex = info
                .hex
                .ok_or_else(|| anyhow!("getrawtransaction without hex"))?;
            let tx = Transaction::decode(hex.as_slice()).map_err(|e| anyhow!("{e}"))?;
            let outs = outputs(&tx);
            let verdict = policy.evaluate(&LockFacts {
                txid: l.outpoint.txid,
                vout: l.outpoint.vout,
                outputs: &outs,
                coin_height: l.block_height,
                confirmations: confs,
                on_active_chain: on_active,
            });
            self.ctx.db(|t| {
                t.transition_lock(&l.lock_id, LockState::Confirmed, Some(tip), None)?;
                match &verdict {
                    Ok(m) => {
                        t.transition_lock(&l.lock_id, LockState::PolicyOk, Some(tip), None)?;
                        info!(event = "lock_policy_ok", lock_id = %lock_hex(&l.lock_id),
                              amount = m.amount, to = %m.to.to_checksum());
                    }
                    Err(why) => {
                        t.reject_lock(&l.lock_id, &why.to_string(), Some(tip))?;
                        warn!(event = "lock_policy_rejected", lock_id = %lock_hex(&l.lock_id),
                              reason = %why);
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Sign every policy-OK lock once; the mint leader collects `k` signatures and submits.
    pub(crate) async fn mint(&mut self) -> Result<()> {
        if self.signing_paused() || !self.is_current_member() {
            return Ok(());
        }
        let p = self.ctx.params.clone();
        let domain = Domain::new(p.deployment.chain_id, p.deployment.bridge);
        let key = self.ctx.key.clone();
        let to_sign = self.ctx.db(|t| t.locks_in_state(LockState::PolicyOk))?;
        for l in to_sign {
            let Some(to) = l.destination else { continue };
            let digest = domain.mint_digest(&l.lock_id, l.value_zat, &to);
            self.ctx.db(|t| {
                t.sign_once_mint(&l.lock_id, l.value_zat, &to, &digest, |d| {
                    hawkeye_core::eth::sign_digest(&key, d)
                })
            })?;
            info!(event = "mint_signed", lock_id = %lock_hex(&l.lock_id), amount = l.value_zat,
                  to = %to.to_checksum(), signer = %key.eth_address().to_checksum());
        }
        let tip = self.mem.tip;
        let mut candidates = self.ctx.db(|t| t.locks_in_state(LockState::Signed))?;
        candidates.extend(
            self.ctx
                .db(|t| t.locks_in_state(LockState::MintSubmitted))?,
        );
        for l in candidates {
            let Some(to) = l.destination else { continue };
            let confirmed_at = l.block_height + p.confirmations - 1;
            let since = tip.saturating_sub(confirmed_at);
            let Some(leader) = mint_leader_for(&l.lock_id, self.live(), since, p.takeover) else {
                continue;
            };
            if *leader != self.ctx.me {
                continue;
            }
            if let Some(at) = self.mem.submitted.get(&l.lock_id)
                && tip < at + p.takeover.max(1)
            {
                continue;
            }
            if self
                .ctx
                .eth
                .consumed(b256(&l.lock_id))
                .await
                .map_err(|e| anyhow!("consumed: {e}"))?
            {
                continue;
            }
            let digest = domain.mint_digest(&l.lock_id, l.value_zat, &to);
            let sigs = self.collect_mint_sigs(&l.lock_id, &digest).await?;
            let need = p.mint_mode.signatures_needed();
            if sigs.len() < need {
                info!(event = "mint_waiting_signatures", lock_id = %lock_hex(&l.lock_id),
                      have = sigs.len(), need);
                continue;
            }
            self.mem.submitted.insert(l.lock_id, tip);
            let res = self
                .ctx
                .eth
                .submit_mint(
                    p.mint_mode,
                    b256(&l.lock_id),
                    U256::from(l.value_zat),
                    addr(&to),
                    &sigs,
                )
                .await;
            match res {
                Ok(MintSubmitted::Minted(m)) => {
                    info!(event = "mint_submitted", lock_id = %lock_hex(&l.lock_id),
                          amount = l.value_zat, to = %to.to_checksum(), tx = %m.tx,
                          block = m.block_number, signatures = sigs.len());
                    if l.state == LockState::Signed {
                        self.ctx.db(|t| {
                            t.transition_lock(&l.lock_id, LockState::MintSubmitted, Some(tip), None)
                        })?;
                    }
                }
                Ok(MintSubmitted::Proposed {
                    mined,
                    executable_at,
                }) => {
                    info!(event = "mint_proposed", lock_id = %lock_hex(&l.lock_id),
                          tx = %mined.tx, executable_at);
                    if l.state == LockState::Signed {
                        self.ctx.db(|t| {
                            t.transition_lock(&l.lock_id, LockState::Proposed, Some(tip), None)
                        })?;
                    }
                }
                Err(e) => {
                    warn!(event = "mint_submit_failed", lock_id = %lock_hex(&l.lock_id), error = %e)
                }
            }
        }
        if p.mint_mode == MintMode::Optimistic {
            self.execute_proposals().await?;
        }
        Ok(())
    }

    /// Own signature plus peers' (`GET /locks/<id>`), each recovered to a current member's
    /// guardian address, distinct.
    async fn collect_mint_sigs(&self, lock_id: &Hash32, digest: &Hash32) -> Result<Vec<[u8; 65]>> {
        let need = self.ctx.params.mint_mode.signatures_needed();
        let own = self
            .ctx
            .db(|t| t.mint_signature(lock_id))?
            .ok_or_else(|| anyhow!("no own signature"))?;
        let mut sigs = vec![own.signature];
        let mut signers = vec![self.ctx.key.eth_address()];
        let guardians: Vec<EthAddress> = self
            .current_member_keys()
            .iter()
            .filter_map(|k| hawkeye_core::eth::address_from_pubkey(k).ok())
            .collect();
        for peer in self.ctx.peers.urls() {
            if sigs.len() >= need {
                break;
            }
            let view = match self.ctx.peers.lock(peer, &lock_hex(lock_id)).await {
                Ok(v) => v,
                Err(e) => {
                    info!(event = "peer_unreachable", peer = %peer, error = %e);
                    continue;
                }
            };
            let Some(sig) = view.signature else { continue };
            let Ok(bytes) = hex::decode(sig.trim_start_matches("0x")) else {
                continue;
            };
            let Ok(sig): Result<[u8; 65], _> = bytes.as_slice().try_into() else {
                continue;
            };
            match hawkeye_core::eth::recover_address(digest, &sig) {
                Ok(a) if guardians.contains(&a) && !signers.contains(&a) => {
                    signers.push(a);
                    sigs.push(sig);
                }
                _ => {
                    warn!(event = "peer_bad_signature", peer = %peer, lock_id = %lock_hex(lock_id))
                }
            }
        }
        Ok(sigs)
    }

    /// CR-W1 double: execute this attestor's matured proposals.
    async fn execute_proposals(&mut self) -> Result<()> {
        let proposed = self.ctx.db(|t| t.locks_in_state(LockState::Proposed))?;
        if proposed.is_empty() {
            return Ok(());
        }
        let now = self
            .ctx
            .eth
            .provider()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .map_or(0, |b| b.header.timestamp);
        for l in proposed {
            let Some(prop) = self
                .ctx
                .eth
                .proposal(b256(&l.lock_id))
                .await
                .map_err(|e| anyhow!("{e}"))?
            else {
                continue;
            };
            if prop.executable_at > now
                || prop.proposer != crate::convert::addr(&self.ctx.key.eth_address())
            {
                continue;
            }
            match self.ctx.eth.execute_mint(b256(&l.lock_id)).await {
                Ok(m) => {
                    info!(event = "mint_executed", lock_id = %lock_hex(&l.lock_id), tx = %m.tx)
                }
                Err(e) => {
                    warn!(event = "mint_execute_failed", lock_id = %lock_hex(&l.lock_id), error = %e)
                }
            }
        }
        Ok(())
    }
}
