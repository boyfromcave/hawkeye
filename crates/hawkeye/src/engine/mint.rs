//! The mint side (plan §1.2, §3.3, §4.1, §5.3 step 2): lock policy after `C_Y`, the `Mint`
//! attestation (sign-once; EIP-712 on Ethereum, through the adapter's
//! [`AttestationScheme`](crate::foreign::AttestationScheme)),
//! submission in the configured mode, the finalized event scan, and the mint watcher. Every
//! foreign-chain call goes through [`ForeignChain`](crate::foreign::ForeignChain).
//!
//! The ledger (schema v4) stores lock destinations, mint recipients, burners and proposers as
//! chain-neutral accounts and guardians: an Ethereum address or a NEAR account id, a 20-byte
//! address or a 64-byte key (NEAR plan NH4).
//!
//! **Optimistic mode** (wyec-contract-design.md §4.5, the Foundation's model): the mint leader
//! (§5.2, over the members the contract has not `vetoed` for the lock) calls `proposeMint` with its
//! own sign-once `Mint` signature; once the window has passed the leader (any attestor, after a
//! further window) calls `executeMint`. A challenged proposal is re-proposed by the next eligible
//! attestor: the challenged proposer is barred from that lock.
//!
//! **The watcher runs in every mode**: the contract's optimistic path cannot be switched off, so a
//! single key can propose whatever Hawkeye's own mode is. Every `MintProposed` is judged — at the
//! chain's head first (`Engine::scan_proposals_latest`, audit 05/H-2: the contract runs the
//! window at `latest`, so waiting for finality would cost two epochs of it, or all of it during a
//! finality stall), then again once final — against this ledger's policy-OK locks; one that does
//! not match is challenged with a sign-once
//! EIP-712 `Challenge(lockId, proposalId)` signature (definite fraud at once; an undecided one when
//! the lock is still absent `C_Y` blocks later, or at the latest when a quarter of the window is
//! left). A proposal matching a policy-OK lock is never challenged (the ledger refuses to sign it).
//! The proposer of a fraudulent proposal gets a `FRAUDULENT_MINT` slash case, as a fraudulent
//! threshold mint's signers do — once the proposal is **final**: an unfinalized proposal is
//! challenged (a challenge binds `(lockId, proposalId)` and is harmless if the proposal reorgs
//! out), never the ground of a slash case or a `fraudulent-mint` alarm.

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use hawkeye_core::PubKey33;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::leader::mint_leader_for;
use hawkeye_core::policy::LockFacts;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_eth::MintMode;
use hawkeye_store::{
    BurnKey, BurnState, Chain, ChallengedProposal, FaultKind, LockRecord, LockState, NewBurn,
    NewSlashCase, PendingMintRecord, StoreError, Tx,
};
use hawkeye_ycash::Hash256;
use hawkeye_ycash::tx::Transaction;
use tracing::{info, warn};

use super::{Engine, FinalityWatch};
use crate::convert::outputs;
use crate::foreign::{
    Account, ForeignError, ForeignEvent, ForeignResult, Guardian, Proposal, ProposalStatus, TxId,
};

/// What a `Minted` event means for the ledger.
enum MintVerdict {
    /// Matches a policy-OK lock: recorded.
    Ok,
    /// Not decidable yet (this attestor has not evaluated the lock).
    Defer,
    /// No policy-OK lock with this `(amount, to)` behind it.
    Fraud(String),
}

/// The head-of-chain proposal scan re-reads this many blocks below the last one it covered, so a
/// proposal that reorgs out and back in within the unfinalized range is seen again: two epochs.
pub const PROPOSAL_RESCAN_DEPTH: u64 = 64;

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
/// `MINTED`. A `provisional` (unfinalized, audit 05/H-2) proposal is judged the same way but
/// never moves the lock: `PROPOSED` keeps meaning "a matching proposal is final", which the
/// finalized scan's challenge classification (griefing vs an honest challenge) relies on.
fn judge_minted(
    t: &Tx<'_>,
    lock_id: &Hash32,
    to: &Account,
    amount: u64,
    block: u64,
    proposal: bool,
    provisional: bool,
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
    if l.value_zat != amount || l.destination.as_ref() != Some(to) {
        return Ok(MintVerdict::Fraud(format!(
            "lock is {} zat to {:?}, {} {amount} to {to}",
            l.value_zat,
            l.destination.as_ref().map(|d| d.to_string()),
            if proposal { "proposed" } else { "minted" }
        )));
    }
    if l.state == Reorged {
        return Ok(MintVerdict::Ok);
    }
    let h = Some(u32::try_from(block).unwrap_or(u32::MAX));
    if proposal {
        if !provisional && (l.state == Signed || l.state == Challenged) {
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
        info!(event = "mint_observed", lock_id = %lock_hex(lock_id), amount, to = %to, block);
    }
    Ok(MintVerdict::Ok)
}

impl Engine {
    /// Scan the foreign chain's final blocks (Ethereum: finalized; NEAR: `final`): burns into the
    /// ledger (orphans held, §3.4), `Minted` / `MintProposed` checked against locks, challenges
    /// and limit changes logged.
    pub(crate) async fn scan_eth(&mut self) -> Result<()> {
        self.mem.eth_fresh = false;
        let fin = self
            .ctx
            .foreign
            .finalized_height()
            .await
            .map_err(|e| anyhow!("finalized block: {e}"))?;
        self.mem.eth_finalized = fin;
        let cursor = self.ctx.db(|t| t.cursor(Chain::Foreign))?;
        let from = cursor.map_or(self.ctx.params.eth_start_block, |c| c.height + 1);
        if fin < from {
            self.mem.eth_fresh = true;
            return Ok(());
        }
        let to = fin.min(from + self.ctx.foreign.max_scan_blocks().max(1) - 1);
        let batch = self
            .ctx
            .foreign
            .scan(from, to)
            .await
            .map_err(|e| anyhow!("scan {from}..={to}: {e}"))?;
        let (events, to_hash) = (batch.events, batch.to_hash);
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let mut frauds = vec![];
        let mut griefed = vec![];
        let mut rotated = false;
        let mut cap_change = None;
        self.ctx.db(|t| {
            for ev in &events {
                let m = &ev.meta;
                match &ev.event {
                    ForeignEvent::Burn {
                        nonce,
                        from,
                        amount,
                        ycash_recipient,
                    } => {
                        let nonce = *nonce;
                        let amount = u64::try_from(*amount).unwrap_or(u64::MAX);
                        let key = BurnKey::new(p.deployment, nonce);
                        let existed = t.burn(&key)?.is_some();
                        let rec = t.insert_burn(&NewBurn {
                            key,
                            tx_hash: m.tx.0,
                            block_number: m.height,
                            block_hash: m.block_hash,
                            from: from.clone(),
                            amount,
                            recipient: ycash_recipient.clone(),
                            finalized: true,
                        })?;
                        if existed {
                            continue;
                        }
                        let recipient = YcashRecipient::from_bytes(ycash_recipient);
                        info!(event = "burn_finalized", nonce, amount, tx = %m.tx,
                              block = m.height,
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
                                Some(m.height),
                                Some(why),
                            )?;
                            warn!(event = "burn_orphaned", nonce, reason = why);
                        }
                    }
                    ForeignEvent::Minted {
                        lock_id,
                        to,
                        amount,
                    }
                    | ForeignEvent::MintProposed {
                        lock_id,
                        to,
                        amount,
                        ..
                    } => {
                        let proposal = matches!(ev.event, ForeignEvent::MintProposed { .. });
                        let amount = u64::try_from(*amount).unwrap_or(u64::MAX);
                        let pm = PendingMintRecord {
                            lock_id: *lock_id,
                            to: to.clone(),
                            amount,
                            tx_hash: m.tx.0,
                            block: m.height,
                            since_height: tip,
                            proposal,
                            provisional: false,
                        };
                        // seen at `latest` first (audit 05/H-2): its deferred check is final now
                        let had = t.finalize_pending_mint(&pm.lock_id, &pm.tx_hash, m.height)?;
                        if let ForeignEvent::MintProposed {
                            proposal_id,
                            proposer,
                            eta,
                            ..
                        } = &ev.event
                        {
                            info!(event = "mint_proposal_observed", lock_id = %lock_hex(&pm.lock_id),
                                  proposal_id, proposer = %proposer, amount, to = %pm.to,
                                  eta, block = m.height);
                        }
                        match judge_minted(t, &pm.lock_id, &pm.to, amount, m.height, proposal, false)?
                        {
                            MintVerdict::Ok => {
                                if had {
                                    t.remove_pending_mint(&pm.lock_id, &pm.tx_hash)?;
                                }
                            }
                            MintVerdict::Defer => {
                                // persisted with the cursor: a restart re-judges it
                                if t.add_pending_mint(&pm)? {
                                    info!(event = "mint_check_deferred", lock_id = %lock_hex(&pm.lock_id),
                                          proposal);
                                }
                            }
                            MintVerdict::Fraud(why) => {
                                // judged here, final: a provisional record of it is done with
                                if had {
                                    t.remove_pending_mint(&pm.lock_id, &pm.tx_hash)?;
                                }
                                frauds.push((pm, why));
                            }
                        }
                    }
                    ForeignEvent::MintChallenged {
                        lock_id,
                        proposal_id,
                        challenger,
                    } => {
                        let l = t.lock(lock_id)?;
                        info!(event = "mint_challenge_observed", lock_id = %lock_hex(lock_id),
                              proposal_id, challenger = %challenger,
                              lock_state = ?l.as_ref().map(|l| l.state.to_string()));
                        if let Some(l) = l.filter(|l| l.state == LockState::Proposed) {
                            // the lock's own (matching) proposal was challenged: re-proposed by
                            // the next eligible attestor; the challenge is attributable
                            t.transition_lock(
                                lock_id,
                                LockState::Challenged,
                                None,
                                Some(&format!("proposal {proposal_id} challenged by {challenger}")),
                            )?;
                            griefed.push(Griefed {
                                lock_id: *lock_id,
                                proposal_id: *proposal_id,
                                challenger: *challenger,
                                challenge_tx: m.tx.0,
                                block: m.height,
                                amount: l.value_zat,
                                to: l.destination.clone(),
                            });
                        }
                    }
                    ForeignEvent::GuardiansChanged { count, threshold } => {
                        info!(event = "guardians_changed", count, threshold);
                        rotated = true;
                    }
                    ForeignEvent::MintLimitChanged {
                        mint_cap,
                        cap_window,
                    } => {
                        info!(event = "mint_limit_changed", mint_cap = %mint_cap, cap_window = %cap_window);
                        cap_change = Some(*mint_cap);
                    }
                    ForeignEvent::Paused { paused, by } => {
                        warn!(event = "bridge_paused", paused, by = %by);
                    }
                }
            }
            // a proposal seen at `latest` whose block is final now without it was reorged out
            let dropped = t.drop_unfinalized_pending_mints(to)?;
            if dropped > 0 {
                info!(event = "unfinalized_proposals_dropped", count = dropped, finalized_to = to);
            }
            t.advance_cursor(Chain::Foreign, to, &to_hash)?;
            Ok(())
        })?;
        if rotated {
            self.mem.guardian_check_due = true;
        }
        if let Some(cap) = cap_change {
            self.mint_cap_changed(cap == 0);
        }
        for g in griefed {
            self.alarm(
                "matching-proposal-challenged",
                format!(
                    "proposal {} of policy-OK lock {} was challenged by {}; it is re-proposed",
                    g.proposal_id,
                    lock_hex(&g.lock_id),
                    g.challenger
                ),
            );
            self.griefing_case(&g)?;
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
                let v = judge_minted(
                    t,
                    &pm.lock_id,
                    &pm.to,
                    pm.amount,
                    pm.block,
                    pm.proposal,
                    pm.provisional,
                )?;
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
            if pm.provisional {
                // not final yet (audit 05/H-2): challenge it (the window runs at `latest`), but
                // no slash case and no alarm; the finalized scan re-judges the row and opens the
                // case then, or drops it if the proposal was reorged out
                if self
                    .mem
                    .provisional_challenged
                    .insert((pm.lock_id, pm.tx_hash))
                {
                    warn!(event = "unfinalized_proposal_challenge", lock_id = %lock_hex(&pm.lock_id),
                          amount = pm.amount, to = %pm.to, reason = %why);
                    self.challenge(&pm, &why).await;
                }
                continue;
            }
            self.fraudulent_mint(&pm, &why).await?;
            self.ctx
                .db(|t| t.remove_pending_mint(&pm.lock_id, &pm.tx_hash))?;
        }
        Ok(())
    }

    /// An undecided proposal: challenge it once [`challenge_due`] says so.
    async fn challenge_if_due(&mut self, pm: &PendingMintRecord, absent: bool, caught_up: bool) {
        let (live, now, window) = match (
            self.ctx.foreign.proposal(pm.lock_id).await,
            self.ctx.foreign.now().await,
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

    /// The optimistic path's events at the chain's head, ahead of finality (audit 05/H-2): the
    /// contract runs the window at `latest` (`eta = block.timestamp + challengeWindow`,
    /// `executeMint` at `eta`, `challengeMint` at any time), so a watcher reading only finalized
    /// blocks would lose two epochs of every window, and the whole window during a finality
    /// stall. Each tick reads `MintProposed` / `MintChallenged` in `(finalized, latest]`,
    /// re-reading [`PROPOSAL_RESCAN_DEPTH`] blocks below the last scan (no ledger cursor: the
    /// range is not final). A proposal is judged as the finalized scan judges it: one matching a
    /// policy-OK lock is left alone (the lock moves to `PROPOSED` once it is final); an undecided
    /// one is recorded `provisional`
    /// and challenged when [`challenge_due`]; a fraudulent one is challenged at once. None of it
    /// opens a slash case or raises `fraudulent-mint`: the finalized scan does, once the
    /// proposal is final. Also runs the finality watch.
    pub(crate) async fn scan_proposals_latest(&mut self) -> Result<()> {
        let foreign = self.ctx.foreign.clone();
        let latest = foreign
            .latest_height()
            .await
            .map_err(|e| anyhow!("latest block: {e}"))?;
        self.mem.eth_latest = latest;
        let fin = self.mem.eth_finalized;
        self.watch_finality(fin, latest);
        self.mem.provisional_seen.retain(|_, block| *block > fin);
        let from = (fin + 1).max(self.ctx.params.eth_start_block).max(
            self.mem
                .latest_scanned
                .saturating_sub(PROPOSAL_RESCAN_DEPTH),
        );
        if latest < from {
            return Ok(());
        }
        let to = latest.min(from + foreign.max_scan_blocks().max(1) - 1);
        let batch = foreign
            .scan_proposals(from, to)
            .await
            .map_err(|e| anyhow!("scan proposals {from}..={to}: {e}"))?;
        self.mem.latest_scanned = to;
        let tip = self.mem.tip;
        let mut fresh = vec![];
        for ev in &batch.events {
            let m = &ev.meta;
            match &ev.event {
                ForeignEvent::MintProposed {
                    lock_id,
                    proposal_id,
                    proposer,
                    to,
                    amount,
                    eta,
                } if m.height > fin
                    && !self.mem.provisional_seen.contains_key(&(*lock_id, m.tx.0)) =>
                {
                    info!(event = "mint_proposal_seen_unfinalized", lock_id = %lock_hex(lock_id),
                          proposal_id, proposer = %proposer, amount = %amount, to = %to, eta,
                          block = m.height, finalized = fin);
                    fresh.push(PendingMintRecord {
                        lock_id: *lock_id,
                        to: to.clone(),
                        amount: u64::try_from(*amount).unwrap_or(u64::MAX),
                        tx_hash: m.tx.0,
                        block: m.height,
                        since_height: tip,
                        proposal: true,
                        provisional: true,
                    });
                }
                ForeignEvent::MintChallenged {
                    lock_id,
                    proposal_id,
                    ..
                } => {
                    self.mem.challenges_done.insert((*lock_id, *proposal_id));
                }
                _ => {}
            }
        }
        if fresh.is_empty() {
            return Ok(());
        }
        let frauds = self.ctx.db(|t| {
            let mut frauds = vec![];
            for pm in &fresh {
                match judge_minted(t, &pm.lock_id, &pm.to, pm.amount, pm.block, true, true)? {
                    MintVerdict::Ok => {}
                    MintVerdict::Defer => {
                        if t.add_pending_mint(pm)? {
                            info!(event = "mint_check_deferred", lock_id = %lock_hex(&pm.lock_id),
                                  proposal = true, provisional = true);
                        }
                    }
                    MintVerdict::Fraud(why) => frauds.push((pm.clone(), why)),
                }
            }
            Ok(frauds)
        })?;
        for pm in &fresh {
            self.mem
                .provisional_seen
                .insert((pm.lock_id, pm.tx_hash), pm.block);
        }
        for (pm, why) in frauds {
            warn!(event = "unfinalized_proposal_challenge", lock_id = %lock_hex(&pm.lock_id),
                  amount = pm.amount, to = %pm.to, block = pm.block, reason = %why);
            self.mem
                .provisional_challenged
                .insert((pm.lock_id, pm.tx_hash));
            self.challenge(&pm, &why).await;
        }
        Ok(())
    }

    /// The finality watch (audit 05/H-2): `finalized` unchanged for
    /// [`ETH_FINALITY_STALL_SECS`](hawkeye_eth::mode::ETH_FINALITY_STALL_SECS) while the head
    /// advanced is a stall — alarm `eth-finality-stall`, and on mainnet this attestor's own
    /// mint-side acts pause ([`Engine::mint_paused`]); cleared when `finalized` moves. A chain
    /// whose head does not move either (an idle devnet) is not stalled: nothing can be proposed.
    fn watch_finality(&mut self, fin: u64, latest: u64) {
        let now = self.instant();
        let w = match self.mem.finality_watch {
            Some(w) if w.finalized == fin => w,
            _ => {
                self.mem.finality_watch = Some(FinalityWatch {
                    finalized: fin,
                    since: now,
                    latest_then: latest,
                });
                if self.mem.finality_stalled {
                    self.mem.finality_stalled = false;
                    info!(event = "eth_finality_resumed", finalized = fin, latest);
                }
                self.clear_alarm("eth-finality-stall");
                return;
            }
        };
        let age = now.saturating_duration_since(w.since).as_secs();
        if age >= hawkeye_eth::mode::ETH_FINALITY_STALL_SECS && latest > w.latest_then {
            self.mem.finality_stalled = true;
            let paused = if self.ctx.params.mainnet {
                "; own proposals, executions and Mint signatures paused, challenges continue"
            } else {
                ""
            };
            self.alarm(
                "eth-finality-stall",
                format!("finalized {fin} unchanged for {age}s; latest {latest}{paused}"),
            );
        }
    }

    /// The rate limit seen unbounded or bounded (a finalized `MintLimitChanged`, or the
    /// contract's state at start and every 60 ticks): on mainnet a cap of 0 (no limit) raises
    /// `mint-cap-unbounded` and pauses this attestor's mint-side acts until a cap is set again
    /// (audit 05/H-2); elsewhere it is only logged.
    pub(crate) fn mint_cap_changed(&mut self, unbounded: bool) {
        if !self.ctx.params.mainnet {
            return;
        }
        if unbounded {
            self.mem.mint_cap_unbounded = true;
            self.alarm(
                "mint-cap-unbounded",
                "the bridge's mintCap was set to 0 (no rate limit): own proposals, executions and \
                 Mint signatures paused until a quorum sets a cap"
                    .into(),
            );
        } else {
            self.mem.mint_cap_unbounded = false;
            self.clear_alarm("mint-cap-unbounded");
        }
    }

    /// The contract's challenge window (read once).
    async fn challenge_window(&mut self) -> ForeignResult<u64> {
        if let Some(w) = self.mem.challenge_window {
            return Ok(w);
        }
        let w = self.ctx.foreign.challenge_window().await?;
        self.mem.challenge_window = Some(w);
        Ok(w)
    }

    /// A mint or proposal with no lock behind it (§2.3 row 3): a proposal is challenged first
    /// (the window is running), then its signers — recovered from the transaction's calldata —
    /// get a slash case each, and an alarm is raised.
    async fn fraudulent_mint(&mut self, pm: &PendingMintRecord, why: &str) -> Result<()> {
        warn!(event = "fraudulent_mint", lock_id = %lock_hex(&pm.lock_id), amount = pm.amount,
              to = %pm.to, tx = %format!("0x{}", hex::encode(pm.tx_hash)),
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
        let foreign = self.ctx.foreign.clone();
        let digest = foreign
            .mint_digest(&pm.lock_id, pm.amount, &pm.to)
            .map_err(|e| anyhow!("{e}"))?;
        let sigs = foreign
            .mint_signatures(TxId(pm.tx_hash))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let mut signers = vec![];
        for s in &sigs {
            if let Ok(a) = foreign.recover(&digest, s) {
                signers.push((a, s.clone()));
            }
        }
        let tip = self.mem.tip;
        let members = self.slashable_member_keys();
        for (a, sig) in signers {
            let Some(key) = members
                .iter()
                .find(|k| foreign.guardian_of(k).ok() == Some(a))
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
                "to": pm.to.to_string(),
                "eth_tx": format!("0x{}", hex::encode(pm.tx_hash)),
                "eth_block": pm.block,
                "proposal": pm.proposal,
                "signer": a.to_string(),
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
        let live = match self.ctx.foreign.proposal(pm.lock_id).await {
            Ok(Some(p)) if p.amount == u128::from(pm.amount) && p.to == pm.to => p,
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
        let me = match self.ctx.guardian() {
            Ok(g) => g,
            Err(e) => {
                warn!(event = "mint_challenge_failed", lock_id = %lock_hex(&pm.lock_id), error = %e);
                return;
            }
        };
        if live.proposer == me {
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
        let foreign = self.ctx.foreign.clone();
        let digest = foreign.challenge_digest(&lock_id, live.id);
        let key = self.ctx.key.clone();
        let rec = self.ctx.db(|t| {
            t.sign_once_challenge(
                &ChallengedProposal {
                    lock_id,
                    proposal_id: live.id,
                    proposer: live.proposer,
                    amount: u64::try_from(live.amount).unwrap_or(u64::MAX),
                    to: live.to.clone(),
                },
                why,
                &digest,
                |d| foreign.sign(&key, d),
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
            .foreign
            .challenge_mint(lock_id, live.id, rec.signature)
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
            match self.ctx.foreign.proposal(r.lock_id).await {
                Ok(Some(p)) if p.id == r.proposal_id => {
                    match self
                        .ctx
                        .foreign
                        .challenge_mint(r.lock_id, r.proposal_id, r.signature)
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
            let verdict = policy.evaluate_for(
                self.ctx.params.bridge_kind,
                &LockFacts {
                    txid: l.outpoint.txid,
                    vout: l.outpoint.vout,
                    outputs: &outs,
                    coin_height: l.block_height,
                    confirmations: confs,
                    on_active_chain: on_active,
                },
            );
            self.ctx.db(|t| {
                t.transition_lock(&l.lock_id, LockState::Confirmed, Some(tip), None)?;
                match &verdict {
                    Ok(m) => {
                        t.transition_lock(&l.lock_id, LockState::PolicyOk, Some(tip), None)?;
                        info!(event = "lock_policy_ok", lock_id = %lock_hex(&l.lock_id),
                              amount = m.amount, to = %m.destination);
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
        if self.mint_paused() || !self.is_current_member() {
            return Ok(());
        }
        let p = self.ctx.params.clone();
        let foreign = self.ctx.foreign.clone();
        let key = self.ctx.key.clone();
        let signer = self.ctx.guardian()?;
        let to_sign = self.ctx.db(|t| t.locks_in_state(LockState::PolicyOk))?;
        for l in to_sign {
            let Some(to) = l.destination.clone() else {
                continue;
            };
            let digest = foreign
                .mint_digest(&l.lock_id, l.value_zat, &to)
                .map_err(|e| anyhow!("{e}"))?;
            self.ctx.db(|t| {
                t.sign_once_mint(&l.lock_id, l.value_zat, &to, &digest, |d| {
                    foreign.sign(&key, d)
                })
            })?;
            info!(event = "mint_signed", lock_id = %lock_hex(&l.lock_id), amount = l.value_zat,
                  to = %to, signer = %signer);
            super::drill_crash_point(&p, "mint_signed");
        }
        match p.mint_mode {
            MintMode::Threshold { k } => self.mint_threshold(k).await,
            MintMode::Optimistic => self.mint_optimistic().await,
        }
    }

    /// Threshold mode: the mint leader collects `k` signatures and calls `mint`.
    async fn mint_threshold(&mut self, k: u8) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        let mut candidates = self.ctx.db(|t| t.locks_in_state(LockState::Signed))?;
        candidates.extend(
            self.ctx
                .db(|t| t.locks_in_state(LockState::MintSubmitted))?,
        );
        for l in candidates {
            let Some(to) = l.destination.clone() else {
                continue;
            };
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
            self.threshold_mint_for(&l, &to, k, p.mint_mode.signatures_needed())
                .await?;
        }
        Ok(())
    }

    /// Gather `need` distinct current guardians' `Mint` signatures for `l` (this attestor's own,
    /// then peers' over `GET /locks/<id>`) and `mint` at once with threshold `k`. `true` once
    /// submitted.
    async fn threshold_mint_for(
        &mut self,
        l: &LockRecord,
        to: &Account,
        k: u8,
        need: usize,
    ) -> Result<bool> {
        let tip = self.mem.tip;
        let digest = self
            .ctx
            .foreign
            .mint_digest(&l.lock_id, l.value_zat, to)
            .map_err(|e| anyhow!("{e}"))?;
        let sigs = self.collect_mint_sigs(&l.lock_id, &digest, need).await?;
        if sigs.len() < need {
            info!(event = "mint_waiting_signatures", lock_id = %lock_hex(&l.lock_id),
                  have = sigs.len(), need);
            return Ok(false);
        }
        self.mem.submitted.insert(l.lock_id, tip);
        let n = sigs.len();
        let res = self
            .ctx
            .foreign
            .threshold_mint(k, l.lock_id, l.value_zat, to.clone(), sigs)
            .await;
        match res {
            Ok(m) => {
                info!(event = "mint_submitted", lock_id = %lock_hex(&l.lock_id),
                      amount = l.value_zat, to = %to, tx = %m.tx,
                      block = m.height, signatures = n);
                if l.state == LockState::Signed {
                    self.ctx.db(|t| {
                        t.transition_lock(&l.lock_id, LockState::MintSubmitted, Some(tip), None)
                    })?;
                }
                Ok(true)
            }
            Err(e) => {
                warn!(event = "mint_submit_failed", lock_id = %lock_hex(&l.lock_id), error = %e);
                Ok(false)
            }
        }
    }

    /// HK-15 (audit 05/L-4): every live member is barred from `l` — `vetoed` by the contract, or a
    /// recorded griefer of it — so the optimistic path cannot mint it. The mint leader over **all**
    /// live members but the griefers (takeover covers a silent one) gathers the contract's
    /// threshold of `Mint` signatures and calls `mint`, which overrides at once. Each signature was
    /// made only after its signer's own policy check (sign-once), so this is the design's
    /// "quorum, immediate" path, not a weaker one. Gated by `mint_paused` like every mint-side submission.
    async fn threshold_fallback(
        &mut self,
        l: &LockRecord,
        to: &Account,
        griefers: &[PubKey33],
    ) -> Result<()> {
        if self.mint_paused() || self.recently_submitted(&l.lock_id) {
            return Ok(());
        }
        let p = self.ctx.params.clone();
        let since = self
            .mem
            .tip
            .saturating_sub(l.block_height + p.confirmations - 1);
        let submitters: Vec<PubKey33> = self
            .live()
            .iter()
            .copied()
            .filter(|k| !griefers.contains(k))
            .collect();
        if mint_leader_for(&l.lock_id, &submitters, since, p.takeover) != Some(&self.ctx.me) {
            return Ok(());
        }
        let k = self
            .ctx
            .foreign
            .threshold()
            .await
            .map_err(|e| anyhow!("threshold: {e}"))?;
        let mut barred = vec![];
        for m in self.live().to_vec() {
            let g = self
                .ctx
                .foreign
                .guardian_of(&m)
                .map_err(|e| anyhow!("{e}"))?;
            if griefers.contains(&m) {
                barred.push(format!("{g} (griefer)"));
            } else if self
                .ctx
                .foreign
                .vetoed(l.lock_id, g)
                .await
                .map_err(|e| anyhow!("vetoed: {e}"))?
            {
                barred.push(g.to_string());
            }
        }
        warn!(event = "mint_threshold_fallback", lock_id = %lock_hex(&l.lock_id), threshold = k,
              barred = %barred.join(", "), "every live proposer is barred: minting by threshold");
        self.threshold_mint_for(l, to, k, usize::from(k)).await?;
        Ok(())
    }

    /// The members with a `GRIEFING` case for `lock_id` in this ledger (any state).
    fn griefers_of(&self, lock_id: &Hash32) -> Result<Vec<PubKey33>> {
        self.ctx.db(|t| {
            let mut v = vec![];
            for s in <hawkeye_store::SlashState as hawkeye_store::Machine>::ALL {
                for c in t.slash_cases_in_state(*s)? {
                    if c.fault == FaultKind::Griefing
                        && c.subject.get(..32) == Some(lock_id.as_slice())
                        && !v.contains(&c.target_key)
                    {
                        v.push(c.target_key);
                    }
                }
            }
            Ok(v)
        })
    }

    /// A matching proposal of a policy-OK lock was challenged (audit 05/L-4): open a `GRIEFING`
    /// case (`SET_REMOVE burn=0`, plan §2.3) against the challenger when it is a member a slash
    /// still reaches and not this attestor. One case per `(challenger, lock, proposal)`.
    fn griefing_case(&mut self, g: &Griefed) -> Result<()> {
        let foreign = self.ctx.foreign.clone();
        let members = self.slashable_member_keys();
        let Some(key) = members
            .iter()
            .find(|k| foreign.guardian_of(k).ok() == Some(g.challenger))
            .copied()
        else {
            return Ok(());
        };
        if key == self.ctx.me {
            warn!(event = "own_griefing_challenge", lock_id = %lock_hex(&g.lock_id),
                  proposal_id = g.proposal_id);
            return Ok(());
        }
        let mut subject = g.lock_id.to_vec();
        subject.extend_from_slice(&g.proposal_id.to_be_bytes());
        let evidence = serde_json::json!({
            "fault": "GRIEFING",
            "set_id": hawkeye_core::bytes::txid_to_display(&self.ctx.params.set_id),
            "target": hex::encode(key),
            "subject": hex::encode(&subject),
            "lock_id": lock_hex(&g.lock_id),
            "proposal_id": g.proposal_id.to_string(),
            "challenger": g.challenger.to_string(),
            "challenge_tx": format!("0x{}", hex::encode(g.challenge_tx)),
            "challenge_block": g.block,
            "lock_state": LockState::Proposed.to_string(),
            "amount": g.amount,
            "to": g.to.as_ref().map(ToString::to_string),
        });
        let tip = self.mem.tip;
        let (case, new) = self.ctx.db(|t| {
            t.open_slash_case(&NewSlashCase {
                target_key: key,
                fault: FaultKind::Griefing,
                subject,
                evidence_json: evidence.to_string(),
                opened_height: Some(tip),
            })
        })?;
        if new {
            warn!(event = "slash_case_opened", case = case.id, fault = "GRIEFING",
                  target = %hex::encode(key), lock_id = %lock_hex(&g.lock_id),
                  proposal_id = g.proposal_id);
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
        let now = self.ctx.foreign.now().await.map_err(|e| anyhow!("{e}"))?;
        let window = self
            .challenge_window()
            .await
            .map_err(|e| anyhow!("challenge window: {e}"))?;
        for l in locks {
            let Some(to) = l.destination.clone() else {
                continue;
            };
            if self.consumed(&l.lock_id).await? {
                continue; // the Minted event moves the lock
            }
            let live = self
                .ctx
                .foreign
                .proposal(l.lock_id)
                .await
                .map_err(|e| anyhow!("proposal: {e}"))?;
            let status = match live {
                Some(_) => self
                    .ctx
                    .foreign
                    .proposal_status(l.lock_id)
                    .await
                    .map_err(|e| anyhow!("proposal status: {e}"))?,
                None => ProposalStatus::None,
            };
            match (live, status) {
                (Some(p), ProposalStatus::Pending | ProposalStatus::Ready)
                    if p.amount == u128::from(l.value_zat) && p.to == to =>
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
    async fn propose(&mut self, l: &LockRecord, to: &Account) -> Result<()> {
        let p = self.ctx.params.clone();
        let tip = self.mem.tip;
        if self.recently_submitted(&l.lock_id) {
            return Ok(());
        }
        // a member that challenged a matching proposal of this lock (an open GRIEFING case here)
        // is not waited for as its proposer: it would hold the lock by never proposing
        let griefers = self.griefers_of(&l.lock_id)?;
        let mut eligible = Vec::with_capacity(self.live().len());
        for k in self.live().to_vec() {
            if griefers.contains(&k) {
                continue;
            }
            let a = self
                .ctx
                .foreign
                .guardian_of(&k)
                .map_err(|e| anyhow!("{e}"))?;
            let barred = self
                .ctx
                .foreign
                .vetoed(l.lock_id, a)
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
                      fallback = p.fallback_to_threshold,
                      "every live member is barred from this lock: a threshold mint is needed");
            }
            if p.fallback_to_threshold {
                return self.threshold_fallback(l, to, &griefers).await;
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
            .foreign
            .propose_mint(l.lock_id, l.value_zat, to.clone(), own.signature)
            .await;
        match res {
            Ok(crate::foreign::Proposed {
                mined,
                proposal_id,
                eta,
            }) => {
                info!(event = "mint_proposed", lock_id = %lock_hex(&l.lock_id), proposal_id,
                      amount = l.value_zat, to = %to, tx = %mined.tx, eta,
                      reproposal = l.state == LockState::Challenged);
                if matches!(l.state, LockState::Signed | LockState::Challenged) {
                    self.ctx.db(|t| {
                        t.transition_lock(&l.lock_id, LockState::Proposed, Some(tip), None)
                    })?;
                }
            }
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
            || p.proposer == self.ctx.guardian()?
            || now >= p.eta.saturating_add(window);
        if !mine {
            return Ok(());
        }
        match self.ctx.foreign.execute_mint(l.lock_id).await {
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
            .foreign
            .consumed(*lock_id)
            .await
            .map_err(|e: ForeignError| anyhow!("consumed: {e}"))
    }

    /// Own signature plus peers' (`GET /locks/<id>`), each recovered to a current member's
    /// guardian, distinct.
    async fn collect_mint_sigs(
        &self,
        lock_id: &Hash32,
        digest: &Hash32,
        need: usize,
    ) -> Result<Vec<[u8; 65]>> {
        let own = self
            .ctx
            .db(|t| t.mint_signature(lock_id))?
            .ok_or_else(|| anyhow!("no own signature"))?;
        let mut sigs = vec![own.signature];
        let mut signers = vec![self.ctx.guardian()?];
        let guardians: Vec<Guardian> = self
            .current_member_keys()
            .iter()
            .filter_map(|k| self.ctx.foreign.guardian_of(k).ok())
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
            match self.ctx.foreign.recover(digest, &sig) {
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

/// A final `MintChallenged` of a proposal that matched a policy-OK lock here (griefing, §2.3).
struct Griefed {
    lock_id: Hash32,
    proposal_id: u128,
    challenger: Guardian,
    challenge_tx: Hash32,
    block: u64,
    amount: u64,
    to: Option<Account>,
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
