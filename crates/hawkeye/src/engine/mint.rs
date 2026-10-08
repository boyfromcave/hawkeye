//! The mint side (plan §1.2, §3.3, §4.1, §5.3 step 2): lock policy after `C_Y`, the EIP-712
//! `Mint` signature (sign-once), submission in the configured mode, the finalized event scan, and
//! the mint watcher.
//!
//! **Optimistic mode** (wyec-contract-design.md §4.5, the Foundation's model): the mint leader
//! (§5.2, over the members the contract has not `vetoed` for the lock) calls `proposeMint` with its
//! own sign-once `Mint` signature; once the window has passed the leader (any attestor, after a
//! further window) calls `executeMint`. A challenged proposal is re-proposed by the next eligible
//! attestor: the challenged proposer is barred from that lock.
//!
//! **The watcher runs in every mode**: the contract's optimistic path cannot be switched off, so a
//! single key can propose whatever Hawkeye's own mode is. Every finalized `MintProposed` is judged
//! against this ledger's policy-OK locks; one that does not match is challenged with a sign-once
//! EIP-712 `Challenge(lockId, proposalId)` signature (definite fraud at once; an undecided one when
//! the lock is still absent `C_Y` blocks later, or at the latest when a quarter of the window is
//! left). A proposal matching a policy-OK lock is never challenged (the ledger refuses to sign it).
//! The proposer of a fraudulent proposal gets a `FRAUDULENT_MINT` slash case, as a fraudulent
//! threshold mint's signers do.

use std::collections::HashSet;

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
use hawkeye_eth::bindings::WyecBridge;
use hawkeye_eth::{BridgeEvent, MintMode, MintSubmitted, Proposal, ProposalStatus, U256};
use hawkeye_store::{
    BurnKey, BurnState, Chain, ChallengedProposal, FaultKind, LockRecord, LockState, NewBurn,
    NewSlashCase, PendingMintRecord, StoreError, Tx,
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

/// Whether an undecided proposal (§5.3 step 2) must be challenged now: at the latest when a
/// quarter of the challenge window is left (`now + window/4 ≥ eta`), and earlier when the lock is
/// still absent from this ledger `C_Y` Ycash blocks after the proposal was first judged with the
/// follower caught up (a lock a legitimate proposer saw with `C_Y` confirmations would be here).
pub fn challenge_due(
    lock_absent: bool,
    caught_up: bool,
    blocks_since: u32,
    confirmations: u32,
    now: u64,
    eta: u64,
    window: u64,
) -> bool {
    let margin = (window / 4).max(1);
    now.saturating_add(margin) >= eta || (lock_absent && caught_up && blocks_since >= confirmations)
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
            "lock is {} zat to {:?}, {} {amount} to {to}",
            l.value_zat,
            l.destination.map(|d| d.to_checksum()),
            if proposal { "proposed" } else { "minted" }
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
    /// `MintProposed` checked against locks, challenges and limit changes logged.
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
        let mut griefed = vec![];
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
                        if let BridgeEvent::MintProposed {
                            proposal_id,
                            proposer,
                            eta,
                            ..
                        } = &ev.event
                        {
                            info!(event = "mint_proposal_observed", lock_id = %lock_hex(&pm.lock_id),
                                  proposal_id, proposer = %proposer, amount, to = %pm.to.to_checksum(),
                                  eta, block = m.block_number);
                        }
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
                    BridgeEvent::MintChallenged {
                        lock_id,
                        proposal_id,
                        challenger,
                    } => {
                        let l = t.lock(&lock_id.0)?;
                        info!(event = "mint_challenge_observed", lock_id = %lock_hex(&lock_id.0),
                              proposal_id, challenger = %challenger,
                              lock_state = ?l.as_ref().map(|l| l.state.to_string()));
                        if l.is_some_and(|l| l.state == LockState::Proposed) {
                            // the lock's own (matching) proposal was challenged: re-proposed by
                            // the next eligible attestor; the challenge is attributable
                            t.transition_lock(
                                &lock_id.0,
                                LockState::Challenged,
                                None,
                                Some(&format!("proposal {proposal_id} challenged by {challenger}")),
                            )?;
                            griefed.push((lock_id.0, *proposal_id, *challenger));
                        }
                    }
                    BridgeEvent::GuardiansChanged {
                        guardians,
                        threshold,
                    } => {
                        info!(event = "guardians_changed", count = guardians.len(), threshold);
                        rotated = true;
                    }
                    BridgeEvent::MintLimitChanged {
                        mint_cap,
                        cap_window,
                    } => {
                        info!(event = "mint_limit_changed", mint_cap = %mint_cap, cap_window = %cap_window);
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
        for (lock_id, id, by) in griefed {
            self.alarm(
                "matching-proposal-challenged",
                format!(
                    "proposal {id} of policy-OK lock {} was challenged by {by}; it is re-proposed",
                    lock_hex(&lock_id)
                ),
            );
        }
        for (pm, why) in frauds {
            self.fraudulent_mint(&pm, &why).await?;
        }
        self.mem.eth_fresh = to == fin;
        Ok(())
    }

    /// Re-judge deferred `Minted` / `MintProposed` events (from the ledger, so a restart resumes
    /// them): an undecided proposal is challenged when [`challenge_due`]; one with still no lock
    /// long after is a fraud (slash case).
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
            let (v, absent) = self.ctx.db(|t| {
                let v = judge_minted(t, &pm.lock_id, &pm.to, pm.amount, pm.block, pm.proposal)?;
                if matches!(v, MintVerdict::Ok) {
                    t.remove_pending_mint(&pm.lock_id, &pm.tx_hash)?;
                }
                Ok((v, t.lock(&pm.lock_id)?.is_none()))
            })?;
            let why = match v {
                MintVerdict::Ok => continue,
                MintVerdict::Fraud(why) => why,
                MintVerdict::Defer if caught_up && tip >= pm.since_height + grace => {
                    "no policy-OK lock behind the lockId".to_owned()
                }
                MintVerdict::Defer => {
                    if pm.proposal {
                        self.challenge_if_due(&pm, absent, caught_up).await;
                    }
                    continue;
                }
            };
            self.fraudulent_mint(&pm, &why).await?;
            self.ctx
                .db(|t| t.remove_pending_mint(&pm.lock_id, &pm.tx_hash))?;
        }
        Ok(())
    }

    /// An undecided proposal: challenge it once [`challenge_due`] says so.
    async fn challenge_if_due(&mut self, pm: &PendingMintRecord, absent: bool, caught_up: bool) {
        let id = b256(&pm.lock_id);
        let (live, now, window) = match (
            self.ctx.eth.proposal(id).await,
            self.ctx.eth.latest_timestamp().await,
            self.challenge_window().await,
        ) {
            (Ok(Some(p)), Ok(now), Ok(w)) => (p, now, w),
            (Ok(None), _, _) => return,
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&pm.lock_id), error = %e);
                return;
            }
        };
        let blocks = self.mem.tip.saturating_sub(pm.since_height);
        if !challenge_due(
            absent,
            caught_up,
            blocks,
            self.ctx.params.confirmations,
            now,
            live.eta,
            window,
        ) {
            return;
        }
        let why = if absent {
            format!(
                "no lock with this lockId on this attestor's chain ({blocks} blocks after the proposal)"
            )
        } else {
            format!(
                "the lock is not policy-OK here {}s before the proposal's eta",
                live.eta.saturating_sub(now)
            )
        };
        self.challenge(pm, &why).await;
    }

    /// The contract's challenge window (read once).
    async fn challenge_window(&mut self) -> hawkeye_eth::Result<u64> {
        if let Some(w) = self.mem.challenge_window {
            return Ok(w);
        }
        let w = self.ctx.eth.challenge_window().await?;
        self.mem.challenge_window = Some(w);
        Ok(w)
    }

    /// A mint or proposal with no lock behind it (§2.3 row 3): a proposal is challenged first
    /// (the window is running), then its signers — recovered from the transaction's calldata —
    /// get a slash case each, and an alarm is raised.
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
            self.challenge(pm, why).await;
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
                } else if let Ok(c) = WyecBridge::proposeMintCall::abi_decode(input) {
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
                "proposal": pm.proposal,
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

    /// Challenge the live proposal for `pm`'s lock if it is the one judged (same amount and
    /// recipient): sign `Challenge(lockId, proposalId)` once (the ledger refuses a proposal that
    /// matches a policy-OK lock), submit it from this attestor's account. Any one guardian's
    /// challenge deletes the proposal, so another attestor finding it gone does nothing. A
    /// proposal this attestor made deliberately (the `rogue-mint` drill) is left to the others.
    async fn challenge(&mut self, pm: &PendingMintRecord, why: &str) {
        if !self.is_current_member() {
            return;
        }
        let id = b256(&pm.lock_id);
        let live = match self.ctx.eth.proposal(id).await {
            Ok(Some(p)) if p.amount == U256::from(pm.amount) && p.to == addr(&pm.to) => p,
            Ok(Some(p)) => {
                info!(event = "mint_challenge_skipped", lock_id = %lock_hex(&pm.lock_id),
                      proposal_id = p.id, reason = "a different proposal is live (judged on its own)");
                return;
            }
            Ok(None) => {
                info!(event = "mint_challenge_skipped", lock_id = %lock_hex(&pm.lock_id),
                      reason = "no live proposal (challenged, executed or overridden)");
                return;
            }
            Err(e) => {
                warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&pm.lock_id), error = %e);
                return;
            }
        };
        let me = self.ctx.key.eth_address();
        if live.proposer == addr(&me) {
            let deliberate = self
                .ctx
                .db(|t| t.drill_mint_signature(&pm.lock_id))
                .map(|r| r.is_some())
                .unwrap_or(false);
            if deliberate {
                if self.mem.own_proposals_logged.insert((pm.lock_id, live.id)) {
                    warn!(event = "own_fraudulent_proposal", lock_id = %lock_hex(&pm.lock_id),
                          proposal_id = live.id,
                          "signed here (drill); left to the other watchers");
                }
                return;
            }
            warn!(event = "own_key_proposal", lock_id = %lock_hex(&pm.lock_id),
                  proposal_id = live.id, "a proposal under this attestor's key that it never signed");
        }
        self.submit_challenge(pm.lock_id, &live, why).await;
    }

    /// Sign (once) and submit the challenge of `live`.
    async fn submit_challenge(&mut self, lock_id: Hash32, live: &Proposal, why: &str) {
        let digest = Domain::new(
            self.ctx.params.deployment.chain_id,
            self.ctx.params.deployment.bridge,
        )
        .challenge_digest(&lock_id, live.id);
        let key = self.ctx.key.clone();
        let rec = self.ctx.db(|t| {
            t.sign_once_challenge(
                &ChallengedProposal {
                    lock_id,
                    proposal_id: live.id,
                    proposer: eth_addr(&live.proposer),
                    amount: u64::try_from(live.amount).unwrap_or(u64::MAX),
                    to: eth_addr(&live.to),
                },
                why,
                &digest,
                |d| hawkeye_core::eth::sign_digest(&key, d),
            )
        });
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                warn!(event = "mint_challenge_refused", lock_id = %lock_hex(&lock_id),
                      proposal_id = live.id, error = %format!("{e:#}"));
                return;
            }
        };
        match self
            .ctx
            .eth
            .challenge_mint(b256(&lock_id), live.id, &rec.signature)
            .await
        {
            Ok(m) => {
                warn!(event = "mint_challenged", lock_id = %lock_hex(&lock_id), proposal_id = live.id,
                      proposer = %live.proposer, tx = %m.tx, reason = why);
                self.mem.challenges_done.insert((lock_id, live.id));
            }
            Err(e) if e.is_revert("NoProposal") => {
                info!(event = "mint_challenge_skipped", lock_id = %lock_hex(&lock_id),
                      proposal_id = live.id, reason = "already gone (another attestor challenged first)");
                self.mem.challenges_done.insert((lock_id, live.id));
            }
            Err(e) => warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&lock_id),
                            proposal_id = live.id, error = %e),
        }
    }

    /// Re-submit recorded challenges whose proposal is still live (a failed submission, a
    /// restart): the recorded bytes, never a new signature.
    pub(crate) async fn resubmit_challenges(&mut self) -> Result<()> {
        let recs = self.ctx.db(|t| t.challenge_signatures())?;
        for r in recs {
            if self
                .mem
                .challenges_done
                .contains(&(r.lock_id, r.proposal_id))
            {
                continue;
            }
            match self.ctx.eth.proposal(b256(&r.lock_id)).await {
                Ok(Some(p)) if p.id == r.proposal_id => {
                    match self
                        .ctx
                        .eth
                        .challenge_mint(b256(&r.lock_id), r.proposal_id, &r.signature)
                        .await
                    {
                        Ok(m) => {
                            warn!(event = "mint_challenged", lock_id = %lock_hex(&r.lock_id),
                                  proposal_id = r.proposal_id, proposer = %p.proposer, tx = %m.tx,
                                  reason = %r.reason, resubmitted = true);
                            self.mem.challenges_done.insert((r.lock_id, r.proposal_id));
                        }
                        Err(e) => warn!(event = "mint_challenge_failed",
                                        lock_id = %lock_hex(&r.lock_id),
                                        proposal_id = r.proposal_id, error = %e),
                    }
                }
                Ok(_) => {
                    self.mem.challenges_done.insert((r.lock_id, r.proposal_id));
                }
                Err(e) => warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&r.lock_id),
                                error = %e),
            }
        }
        Ok(())
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

    /// Sign every policy-OK lock once; then mint the configured way. Recorded challenges whose
    /// proposal is still live are re-submitted first (any mode).
    pub(crate) async fn mint(&mut self) -> Result<()> {
        if self.is_current_member() {
            self.resubmit_challenges().await?;
        }
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
            super::drill_crash_point(&p, "mint_signed");
        }
        match p.mint_mode {
            MintMode::Threshold { .. } => self.mint_threshold().await,
            MintMode::Optimistic => self.mint_optimistic().await,
        }
    }

    /// Threshold mode: the mint leader collects `k` signatures and calls `mint`.
    async fn mint_threshold(&mut self) -> Result<()> {
        let p = self.ctx.params.clone();
        let domain = Domain::new(p.deployment.chain_id, p.deployment.bridge);
        let tip = self.mem.tip;
        let mut candidates = self.ctx.db(|t| t.locks_in_state(LockState::Signed))?;
        candidates.extend(
            self.ctx
                .db(|t| t.locks_in_state(LockState::MintSubmitted))?,
        );
        for l in candidates {
            let Some(to) = l.destination else { continue };
            let since = tip.saturating_sub(l.block_height + p.confirmations - 1);
            let Some(leader) = mint_leader_for(&l.lock_id, self.live(), since, p.takeover) else {
                continue;
            };
            if *leader != self.ctx.me || self.recently_submitted(&l.lock_id) {
                continue;
            }
            if self.consumed(&l.lock_id).await? {
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
                Ok(MintSubmitted::Proposed { .. }) => {}
                Err(e) => {
                    warn!(event = "mint_submit_failed", lock_id = %lock_hex(&l.lock_id), error = %e)
                }
            }
        }
        Ok(())
    }

    /// Optimistic mode, per signed lock: nothing live → the eligible leader proposes with its own
    /// sign-once signature; a matching live proposal → executed once ready (by the leader at
    /// `eta`, by anyone a further window later); a different live proposal → the watcher's
    /// business, the lock waits; a void one (proposer rotated out) is replaced.
    async fn mint_optimistic(&mut self) -> Result<()> {
        let mut locks = vec![];
        for s in [
            LockState::Signed,
            LockState::Proposed,
            LockState::Challenged,
        ] {
            locks.extend(self.ctx.db(|t| t.locks_in_state(s))?);
        }
        if locks.is_empty() {
            return Ok(());
        }
        let now = self
            .ctx
            .eth
            .latest_timestamp()
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let window = self
            .challenge_window()
            .await
            .map_err(|e| anyhow!("challenge window: {e}"))?;
        for l in locks {
            let Some(to) = l.destination else { continue };
            if self.consumed(&l.lock_id).await? {
                continue; // the Minted event moves the lock
            }
            let id = b256(&l.lock_id);
            let live = self
                .ctx
                .eth
                .proposal(id)
                .await
                .map_err(|e| anyhow!("proposal: {e}"))?;
            let status = match live {
                Some(_) => self
                    .ctx
                    .eth
                    .proposal_status(id)
                    .await
                    .map_err(|e| anyhow!("proposal status: {e}"))?,
                None => ProposalStatus::None,
            };
            match (live, status) {
                (Some(p), ProposalStatus::Pending | ProposalStatus::Ready)
                    if p.amount == U256::from(l.value_zat) && p.to == addr(&to) =>
                {
                    if status == ProposalStatus::Ready {
                        self.execute(&l, &p, now, window).await?;
                    }
                }
                (Some(p), ProposalStatus::Pending | ProposalStatus::Ready) => {
                    if self.mem.squat_logged.insert((l.lock_id, p.id)) {
                        warn!(event = "mint_proposal_mismatch", lock_id = %lock_hex(&l.lock_id),
                              proposal_id = p.id, proposer = %p.proposer,
                              "a different proposal holds the lock; waiting for its challenge");
                    }
                }
                _ => self.propose(&l, &to).await?,
            }
        }
        Ok(())
    }

    /// Propose `l` if this attestor is the mint leader among the live members the contract has
    /// not barred from the lock (`vetoed`).
    async fn propose(&mut self, l: &LockRecord, to: &EthAddress) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        if self.recently_submitted(&l.lock_id) {
            return Ok(());
        }
        let mut eligible = Vec::with_capacity(self.live().len());
        for k in self.live().to_vec() {
            let a = hawkeye_core::eth::address_from_pubkey(&k).map_err(|e| anyhow!("{e}"))?;
            let barred = self
                .ctx
                .eth
                .vetoed(b256(&l.lock_id), addr(&a))
                .await
                .map_err(|e| anyhow!("vetoed: {e}"))?;
            if !barred {
                eligible.push(k);
            }
        }
        let since = tip.saturating_sub(l.block_height + p.confirmations - 1);
        let Some(leader) = mint_leader_for(&l.lock_id, &eligible, since, p.takeover) else {
            if self.mem.squat_logged.insert((l.lock_id, 0)) {
                warn!(event = "mint_no_eligible_proposer", lock_id = %lock_hex(&l.lock_id),
                      "every live member is barred from this lock: a threshold mint is needed");
            }
            return Ok(());
        };
        if *leader != self.ctx.me {
            return Ok(());
        }
        let own = self
            .ctx
            .db(|t| t.mint_signature(&l.lock_id))?
            .ok_or_else(|| anyhow!("no own signature"))?;
        self.mem.submitted.insert(l.lock_id, tip);
        let res = self
            .ctx
            .eth
            .propose_mint(
                b256(&l.lock_id),
                U256::from(l.value_zat),
                addr(to),
                &own.signature,
            )
            .await;
        match res {
            Ok(MintSubmitted::Proposed {
                mined,
                proposal_id,
                eta,
            }) => {
                info!(event = "mint_proposed", lock_id = %lock_hex(&l.lock_id), proposal_id,
                      amount = l.value_zat, to = %to.to_checksum(), tx = %mined.tx, eta,
                      reproposal = l.state == LockState::Challenged);
                if matches!(l.state, LockState::Signed | LockState::Challenged) {
                    self.ctx.db(|t| {
                        t.transition_lock(&l.lock_id, LockState::Proposed, Some(tip), None)
                    })?;
                }
            }
            Ok(MintSubmitted::Minted(_)) => {}
            Err(e) if e.is_revert("ProposalPending") || e.is_revert("LockConsumed") => {
                info!(event = "mint_propose_skipped", lock_id = %lock_hex(&l.lock_id), reason = %e)
            }
            Err(e) => {
                warn!(event = "mint_submit_failed", lock_id = %lock_hex(&l.lock_id), error = %e)
            }
        }
        Ok(())
    }

    /// `executeMint` of a ready, matching proposal: the current mint leader at once, every other
    /// attestor once a further window has passed (anyone may; this only spreads the gas).
    async fn execute(&mut self, l: &LockRecord, p: &Proposal, now: u64, window: u64) -> Result<()> {
        let params = self.ctx.params.clone();
        let since = self
            .mem
            .tip
            .saturating_sub(l.block_height + params.confirmations - 1);
        let leader = mint_leader_for(&l.lock_id, self.live(), since, params.takeover);
        let mine = leader == Some(&self.ctx.me)
            || p.proposer == addr(&self.ctx.key.eth_address())
            || now >= p.eta.saturating_add(window);
        if !mine {
            return Ok(());
        }
        match self.ctx.eth.execute_mint(b256(&l.lock_id)).await {
            Ok(m) => {
                info!(event = "mint_executed", lock_id = %lock_hex(&l.lock_id), proposal_id = p.id,
                      tx = %m.tx)
            }
            Err(e) if e.is_revert("MintRateLimited") => {
                if self.mem.squat_logged.insert((l.lock_id, u128::MAX)) {
                    warn!(event = "mint_rate_limited", lock_id = %lock_hex(&l.lock_id),
                          proposal_id = p.id, error = %e, "retried every tick until a window opens");
                }
            }
            Err(e) if e.is_revert("NoProposal") => {}
            Err(e) => {
                warn!(event = "mint_execute_failed", lock_id = %lock_hex(&l.lock_id), error = %e)
            }
        }
        Ok(())
    }

    fn recently_submitted(&self, lock_id: &Hash32) -> bool {
        self.mem
            .submitted
            .get(lock_id)
            .is_some_and(|at| self.mem.tip < at + self.ctx.params.takeover.max(1))
    }

    async fn consumed(&self, lock_id: &Hash32) -> Result<bool> {
        self.ctx
            .eth
            .consumed(b256(lock_id))
            .await
            .map_err(|e| anyhow!("consumed: {e}"))
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
}

/// Keys of `(lockId, proposalId)` pairs the engine remembers in memory.
pub(crate) type ProposalKeys = HashSet<(Hash32, u128)>;

#[cfg(test)]
mod tests {
    use super::challenge_due;

    #[test]
    fn challenge_deadline() {
        // window 12 s, eta 112: due at 109 at the latest (a quarter left)
        assert!(!challenge_due(false, true, 0, 2, 100, 112, 12));
        assert!(challenge_due(false, false, 0, 2, 109, 112, 12));
        assert!(challenge_due(false, true, 99, 2, 200, 112, 12), "past eta");
        // an absent lock: C_Y blocks after it was first judged, with the follower caught up
        assert!(!challenge_due(true, true, 1, 2, 100, 112, 12));
        assert!(challenge_due(true, true, 2, 2, 100, 112, 12));
        assert!(
            !challenge_due(true, false, 5, 2, 100, 112, 12),
            "lagging: wait"
        );
        // a lock that is here but not judged yet waits for the deadline only
        assert!(!challenge_due(false, true, 50, 2, 100, 112, 12));
        // a one-second window still has a margin of one second
        assert!(challenge_due(false, true, 0, 2, 100, 101, 1));
    }
}
