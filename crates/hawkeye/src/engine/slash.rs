//! Slash cases (plan §2.3, §5.3 steps 3–4): the case owner builds `SET_REMOVE burn=1`, signs it on
//! its own node, gathers the other members' signatures over `POST /slash/sign`, and sends it;
//! every attestor records the removal when it is mined.
//!
//! A peer asked to co-sign **re-derives the fault itself** ([`verify_evidence`]) from its own
//! node and its own ledger — never from the requester's word: for a fraudulent intent it fetches
//! the unlock transaction, recovers its set signature, checks the signer is a current member and
//! classifies the intent against its own finalized burns; for a fraudulent mint it recovers the
//! EIP-712 signature and confirms no policy-OK lock with that `(lockId, amount, to)` is in its
//! ledger. Only then does it call `set_signact` (sign-once). It never signs its own removal, and
//! never a removal for a benign race.
//!
//! Progress survives a restart (schema v2): the owner's act with the signatures gathered and the
//! peers who gave them, and each vote this attestor gave, keyed by the act's prevout.

use anyhow::{Result, anyhow, bail, ensure};
use hawkeye_core::bytes::{Hash32, sha256d, txid_from_display};
use hawkeye_core::eip712::Domain;
use hawkeye_core::leader::leader_for;
use hawkeye_core::matcher::Classification;
use hawkeye_core::template::{TAG_WYEC, parse_intent, parse_vault};
use hawkeye_core::{EthAddress, IntentParams, OutPoint as CoreOutPoint, PubKey33};
use hawkeye_store::{
    Chain, FaultKind, LockState, SignDomain, SlashCaseRecord, SlashProgress, SlashState, VoteGiven,
    YcashSignKey, classification_code,
};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{ActBody, BuildAct, DecodedAct, DecodedScript};
use hawkeye_ycash::{Hash256, HexBytes, PubKey};
use tracing::{info, warn};

use super::ycash::{IntentFacts, classify};
use super::{Ctx, Engine, block_on};
use crate::convert::{intent_params, op_core, outputs};
use crate::peers::{SlashSignRequest, SlashSignResponse};

/// Cases that lapse after this many Ycash blocks without a removal.
pub const CASE_EXPIRY_BLOCKS: u32 = 2_880;

fn act_prevout(act_hex: &str) -> Result<CoreOutPoint> {
    let tx = Transaction::decode_hex(act_hex).map_err(|e| anyhow!("act: {e}"))?;
    tx.inputs
        .first()
        .map(|i| op_core(&i.prevout))
        .ok_or_else(|| anyhow!("act has no input"))
}

fn act_key(ctx: &Ctx, act_hex: &str) -> Result<YcashSignKey> {
    Ok(YcashSignKey {
        domain: SignDomain::YcashAct,
        set_id: ctx.params.set_id,
        prevout: act_prevout(act_hex)?,
    })
}

/// `(complete, signatures, required)` of a `set_signact` answer.
type ActStatus = (bool, u32, i32);

/// Builds the vote record from the signed hex and the node's status.
type VoteRecorder<'a> = &'a dyn Fn(&str, ActStatus) -> VoteGiven;

/// `set_signact` through the sign-once record, recording the vote given (if any) in the same
/// ledger transaction. Returns the signed hex and the node's status (`None` on a repeat).
fn sign_act(
    ctx: &Ctx,
    act_hex: &str,
    given: Option<VoteRecorder<'_>>,
) -> Result<(String, Option<ActStatus>)> {
    let key = act_key(ctx, act_hex)?;
    let ycash = ctx.ycash.clone();
    let set = ctx.set_hash();
    let status = std::cell::Cell::new(None);
    let rec = ctx.db(|t| {
        let rec = t.sign_once_ycash(&key, act_hex, |h| {
            let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
            let r = block_on(ycash.set_signact(&hex, Some(&set))).map_err(|e| e.to_string())?;
            status.set(Some((r.complete, r.signatures, r.required)));
            Ok::<_, String>((r.hex.to_string(), sha256d(&hex.0)))
        })?;
        if let (Some(f), Some(st)) = (given, status.get()) {
            t.record_vote_given(&f(&rec.signed_hex, st))?;
        }
        Ok(rec)
    })?;
    Ok((rec.signed_hex, status.get()))
}

/// Decode the `SET_REMOVE` an act transaction carries (through the node's decoder).
async fn decode_remove(ctx: &Ctx, act_hex: &str) -> Result<(PubKey33, bool)> {
    let tx = Transaction::decode_hex(act_hex).map_err(|e| anyhow!("act: {e}"))?;
    // the act OP_RETURN: the payload push, then one push per act signature
    for o in tx.outputs.iter().filter(|o| o.is_op_return()) {
        let d = ctx
            .ycash
            .vault_decodescript(&HexBytes(o.script_pubkey.clone()))
            .await?;
        if let DecodedScript::Act(DecodedAct::Act { body, .. }) = &d
            && let ActBody::Remove {
                setid,
                memberkey,
                burn,
            } = **body
        {
            if setid != ctx.set_hash() {
                return Err(anyhow!("the act names another set"));
            }
            return Ok((memberkey.0, burn != 0));
        }
        if matches!(d, DecodedScript::Act(_)) {
            return Err(anyhow!("the act does not decode as a SET_REMOVE: {d:?}"));
        }
    }
    Err(anyhow!("the act does not decode as a SET_REMOVE"))
}

/// What this attestor's own verification of an evidence bundle established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The fault.
    pub fault: FaultKind,
    /// The member at fault (a current member, not this attestor).
    pub target: PubKey33,
    /// The case subject (the unlock's txid, the `lockId`).
    pub subject: Vec<u8>,
    /// What was found (the classification, or the mint mismatch).
    pub reason: String,
}

fn ev_str<'a>(ev: &'a serde_json::Value, k: &str) -> Result<&'a str> {
    ev[k]
        .as_str()
        .ok_or_else(|| anyhow!("evidence without {k:?}"))
}

fn parse_outpoint(s: &str) -> Result<CoreOutPoint> {
    let (txid, vout) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("outpoint {s:?} is not txid:vout"))?;
    Ok(CoreOutPoint::new(
        txid_from_display(txid).map_err(|e| anyhow!("outpoint {s:?}: {e}"))?,
        vout.parse().map_err(|e| anyhow!("outpoint {s:?}: {e}"))?,
    ))
}

/// The current members, from this attestor's own node.
async fn current_members(ctx: &Ctx) -> Result<Vec<PubKey33>> {
    Ok(ctx
        .ycash
        .set_getinfo(&ctx.set_hash(), None)
        .await?
        .memberlist
        .iter()
        .filter(|m| m.current)
        .map(|m| m.key.0)
        .collect())
}

/// The scriptPubKey and value of `op`, from this attestor's own node.
async fn coin(ctx: &Ctx, op: &CoreOutPoint) -> Result<(Vec<u8>, u64)> {
    let raw = ctx
        .ycash
        .getrawtransaction(&Hash256::from_internal(op.txid))
        .await?;
    let tx = Transaction::decode(raw.as_slice()).map_err(|e| anyhow!("{e}"))?;
    let o = tx
        .outputs
        .get(op.vout as usize)
        .ok_or_else(|| anyhow!("{op}: no such output"))?;
    Ok((o.script_pubkey.clone(), u64::try_from(o.value).unwrap_or(0)))
}

/// Re-derive the fault of an evidence bundle from this attestor's own node and ledger
/// (§5.3 step 3). Errors say why the fault is **not** established here.
pub async fn verify_evidence(ctx: &Ctx, ev: &serde_json::Value) -> Result<Verdict> {
    let fault: FaultKind = ev_str(ev, "fault")?.parse().map_err(|e| anyhow!("{e}"))?;
    match fault {
        FaultKind::FraudulentIntent => verify_intent(ctx, ev).await,
        FaultKind::FraudulentMint => verify_mint(ctx, ev).await,
        FaultKind::Equivocation => {
            bail!("an equivocation needs no vote: set_equivocation ejects the member by itself")
        }
        other => bail!("{other} is not verified by this version: not signing"),
    }
}

/// A fraudulent intent: the unlock is fetched from this node, its set signature recovered to a
/// current member, and the intent classified against this ledger's finalized burns.
async fn verify_intent(ctx: &Ctx, ev: &serde_json::Value) -> Result<Verdict> {
    let op = parse_outpoint(ev_str(ev, "intent")?)?;
    let p = &ctx.params;
    // the unlock, from this node (the evidence's copy only for a transaction this ledger saw)
    let raw = match ctx
        .ycash
        .getrawtransaction(&Hash256::from_internal(op.txid))
        .await
    {
        Ok(r) => r.0,
        Err(e) => {
            let seen = ctx.db(|t| t.intent(&op))?.is_some();
            let copy = ev["unlock_hex"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .filter(|r| Transaction::decode(r).is_ok_and(|t| t.txid().0 == op.txid));
            match (seen, copy) {
                (true, Some(r)) => r,
                _ => bail!(
                    "this node does not know the unlock {}: {e}",
                    op.txid_display()
                ),
            }
        }
    };
    let tx = Transaction::decode(&raw).map_err(|e| anyhow!("unlock: {e}"))?;
    ensure!(tx.txid().0 == op.txid, "the unlock's txid differs");
    // the vault input of this set
    let mut found = None;
    for (idx, input) in tx.inputs.iter().enumerate() {
        let prev = op_core(&input.prevout);
        let Ok((spk, value)) = coin(ctx, &prev).await else {
            continue;
        };
        if let Ok(v) = parse_vault(&spk)
            && v.tag == TAG_WYEC
            && v.set_id == p.set_id
        {
            found = Some((idx, prev, spk, value, v));
            break;
        }
    }
    let (idx, vault, spk, value, vp) =
        found.ok_or_else(|| anyhow!("the transaction spends no WYEC vault of this set"))?;
    // who signed it: recovered here, a current member here
    let attribution = ctx
        .attributor
        .attribute(&raw, idx, &spk, value, hawkeye_core::VAULT_BRANCH_ID)
        .map_err(|e| anyhow!("the unlock does not attribute: {e}"))?;
    let members = current_members(ctx).await?;
    let signer = attribution
        .signers
        .iter()
        .map(|s| s.pubkey)
        .find(|k| members.contains(k))
        .ok_or_else(|| anyhow!("no set signature of the unlock recovers to a current member"))?;
    let claimed: PubKey33 = hex::decode(ev_str(ev, "target")?)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("evidence target is not a 33-byte key"))?;
    ensure!(
        claimed == signer,
        "the unlock was signed by {}, not by the accused {}",
        hex::encode(signer),
        hex::encode(claimed)
    );
    // the intent output
    let o = tx
        .outputs
        .get(op.vout as usize)
        .ok_or_else(|| anyhow!("the unlock has no output {}", op.vout))?;
    let ip: IntentParams = match parse_intent(&o.script_pubkey) {
        Ok(ip) => ip,
        Err(_) => match ctx
            .ycash
            .vault_decodescript(&HexBytes(o.script_pubkey.clone()))
            .await?
        {
            DecodedScript::Intent(f) => intent_params(&f)?,
            _ => bail!("output {} is not an intent", op.vout),
        },
    };
    // classified here, against this ledger's burns
    let tip = ctx.ycash.getblockcount().await?;
    let first_seen = match ctx.db(|t| t.intent(&op))? {
        Some(i) => i.first_seen_height,
        None => ctx
            .ycash
            .getrawtransaction_verbose(&Hash256::from_internal(op.txid), None)
            .await
            .ok()
            .and_then(|i| i.height)
            .and_then(|h| u32::try_from(h).ok())
            .unwrap_or(tip),
    };
    let outs = outputs(&tx);
    let c = ctx.db(|t| {
        Ok(classify(
            t,
            p,
            &IntentFacts {
                txid: op.txid,
                first_seen,
                intent: &ip,
                value: u64::try_from(o.value).unwrap_or(0),
                outputs: &outs,
                spent_vault: Some(&vp),
                origin: Some(&vault),
            },
        ))
    })?;
    let code = classification_code(&c);
    match c {
        Classification::Foreign => bail!("the intent is not a WYEC intent of this set"),
        Classification::MatchedBurn { nonce } => {
            bail!("the intent matches finalized burn {nonce} here: not a fault")
        }
        Classification::MatchedRoll { .. } => bail!("the intent is a valid roll here: not a fault"),
        Classification::Unmatched(u) if !u.slashable() => {
            bail!("{code}: a benign race (§5.2) is cancelled, never slashed")
        }
        Classification::Unmatched(hawkeye_core::matcher::Unmatched::UnknownBurn) => {
            // this attestor's Ethereum view may lag the burn's finality
            let fin = ctx
                .eth
                .finalized_block_number()
                .await
                .map_err(|e| anyhow!("{e}"))?;
            let cursor = ctx
                .db(|t| t.cursor(Chain::Ethereum))?
                .map_or(0, |c| c.height);
            ensure!(
                cursor >= fin,
                "{code}, but this attestor's Ethereum view lags (cursor {cursor} < finalized {fin})"
            );
        }
        Classification::Unmatched(_) => {}
    }
    Ok(Verdict {
        fault: FaultKind::FraudulentIntent,
        target: signer,
        subject: op.txid.to_vec(),
        reason: code,
    })
}

/// A fraudulent mint signature: it recovers to the accused member's guardian address, and no
/// policy-OK lock with that `(lockId, amount, to)` is in this ledger, whose Ycash view is current.
async fn verify_mint(ctx: &Ctx, ev: &serde_json::Value) -> Result<Verdict> {
    let p = &ctx.params;
    let lock_id: Hash32 = hex::decode(ev_str(ev, "lock_id")?.trim_start_matches("0x"))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("lock_id is not 32 bytes"))?;
    let amount = ev["amount"]
        .as_u64()
        .ok_or_else(|| anyhow!("evidence without amount"))?;
    let to = EthAddress::parse(ev_str(ev, "to")?).map_err(|e| anyhow!("to: {e}"))?;
    let sig = hex::decode(ev_str(ev, "signature")?.trim_start_matches("0x"))?;
    let claimed: PubKey33 = hex::decode(ev_str(ev, "target")?)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("evidence target is not a 33-byte key"))?;
    let digest =
        Domain::new(p.deployment.chain_id, p.deployment.bridge).mint_digest(&lock_id, amount, &to);
    let signer = hawkeye_core::eth::recover_address(&digest, &sig)
        .map_err(|e| anyhow!("the mint signature does not recover: {e}"))?;
    let want = hawkeye_core::eth::address_from_pubkey(&claimed)
        .map_err(|e| anyhow!("evidence target: {e}"))?;
    ensure!(
        signer == want,
        "the Mint signature recovers to {}, not to the accused's guardian address {}",
        signer.to_checksum(),
        want.to_checksum()
    );
    ensure!(
        current_members(ctx).await?.contains(&claimed),
        "the accused is not a current member here"
    );
    let tip = ctx.ycash.getblockcount().await?;
    let (lock, cursor) = ctx.db(|t| Ok((t.lock(&lock_id)?, t.cursor(Chain::Ycash)?)))?;
    let reason = match lock {
        Some(l) if matches!(l.state, LockState::Seen | LockState::Confirmed) => {
            bail!("the lock is not judged here yet ({}): not signing", l.state)
        }
        Some(l) if l.state == LockState::PolicyRejected => format!(
            "lock refused by policy here: {}",
            l.rejection_reason.unwrap_or_default()
        ),
        Some(l) if l.value_zat != amount || l.destination != Some(to) => format!(
            "lock is {} zat to {:?} here, signed {amount} to {}",
            l.value_zat,
            l.destination.map(|d| d.to_checksum()),
            to.to_checksum()
        ),
        Some(l) => bail!(
            "a lock with this (lockId, amount, to) is {} here: not a fault",
            l.state
        ),
        None => {
            let h = cursor.map_or(0, |c| c.height);
            ensure!(
                h >= u64::from(tip),
                "no such lock here, but this attestor's Ycash view lags (cursor {h} < tip {tip})"
            );
            "no lock with this lockId on this attestor's chain".to_owned()
        }
    };
    Ok(Verdict {
        fault: FaultKind::FraudulentMint,
        target: claimed,
        subject: lock_id.to_vec(),
        reason,
    })
}

/// `POST /slash/sign`: verify the evidence independently ([`verify_evidence`]), check that the
/// act removes exactly that member of this set with the right `burn`, then sign it on this node
/// (sign-once). A repeated request for the same act is answered from the vote recorded then.
pub async fn verify_and_sign(ctx: &Ctx, req: &SlashSignRequest) -> Result<SlashSignResponse> {
    let prevout = act_prevout(&req.act)?;
    if let Some(v) = ctx.db(|t| t.vote_given(&prevout))? {
        info!(event = "slash_vote_repeated", fault = %v.fault, target = %hex::encode(v.target_key));
        return Ok(SlashSignResponse {
            hex: v.signed_hex,
            complete: v.complete,
            signatures: v.signatures,
            required: v.required,
        });
    }
    let (act_target, burn) = decode_remove(ctx, &req.act).await?;
    let verdict = verify_evidence(ctx, &req.evidence).await?;
    if verdict.target == ctx.me {
        bail!("refusing to vote on my own removal");
    }
    ensure!(
        act_target == verdict.target,
        "the act removes {}, the evidence accuses {}",
        hex::encode(act_target),
        hex::encode(verdict.target)
    );
    ensure!(
        burn == (verdict.fault != FaultKind::Griefing),
        "the act's burn flag does not fit the fault"
    );
    let record = |signed: &str, st: ActStatus| VoteGiven {
        act_prevout: prevout,
        fault: verdict.fault,
        target_key: verdict.target,
        subject: verdict.subject.clone(),
        signed_hex: signed.to_owned(),
        complete: st.0,
        signatures: st.1,
        required: st.2,
        reason: verdict.reason.clone(),
    };
    let (hex, status) = sign_act(ctx, &req.act, Some(&record))?;
    let (complete, signatures, required) = status.unwrap_or((false, 0, -1));
    warn!(event = "slash_vote_given", fault = %verdict.fault, target = %hex::encode(verdict.target),
          reason = %verdict.reason, complete, signatures, required);
    Ok(SlashSignResponse {
        hex,
        complete,
        signatures,
        required,
    })
}

impl Engine {
    /// Advance every open case.
    pub(crate) async fn slash(&mut self) -> Result<()> {
        let tip = self.mem.tip;
        let mut cases: Vec<SlashCaseRecord> = vec![];
        self.ctx.db(|t| {
            for s in [SlashState::Opened, SlashState::Voted, SlashState::Submitted] {
                cases.extend(t.slash_cases_in_state(s)?);
            }
            Ok(())
        })?;
        for c in cases {
            if self.is_removed(&c.target_key) {
                self.ctx
                    .db(|t| t.slash_slashed(c.id, tip, Some("member removed")))?;
                warn!(event = "slash_done", case = c.id, target = %hex::encode(c.target_key),
                      fault = %c.fault);
                continue;
            }
            let opened = c.opened_height.unwrap_or(tip);
            if tip > opened + CASE_EXPIRY_BLOCKS && c.state != SlashState::Submitted {
                self.ctx.db(|t| {
                    t.transition_slash(c.id, SlashState::Expired, Some(tip), Some("lapsed"))
                })?;
                continue;
            }
            if !self.ctx.params.auto_slash {
                self.alarm(
                    &format!("slash-case-{}", c.id),
                    format!(
                        "{} against {}: auto_slash is off, operator action needed",
                        c.fault,
                        hex::encode(c.target_key)
                    ),
                );
                continue;
            }
            if c.fault == FaultKind::Equivocation {
                continue; // set_equivocation needs no vote
            }
            let others: Vec<PubKey33> = self
                .live()
                .iter()
                .copied()
                .filter(|k| *k != c.target_key)
                .collect();
            let owner = leader_for(
                0,
                &others,
                tip.saturating_sub(opened),
                self.ctx.params.takeover * 2,
            );
            if owner != Some(&self.ctx.me) {
                continue;
            }
            if let Err(e) = self.drive_case(&c).await {
                warn!(event = "slash_progress_failed", case = c.id, error = %format!("{e:#}"));
            }
        }
        Ok(())
    }

    async fn drive_case(&mut self, c: &SlashCaseRecord) -> Result<()> {
        let tip = self.mem.tip;
        let progress = self.ctx.db(|t| t.slash_progress(c.id))?;
        let mut prog = match (c.state, progress) {
            (SlashState::Opened, _) => {
                let act = self
                    .ctx
                    .ycash
                    .set_buildact(&BuildAct::Remove {
                        setid: self.ctx.set_hash(),
                        memberkey: PubKey(c.target_key),
                        burn: c.fault != FaultKind::Griefing,
                    })
                    .await?;
                let built = act.hex.to_string();
                let (signed, status) = sign_act(&self.ctx, &built, None)?;
                let (complete, signatures, required) = status.unwrap_or((false, 0, act.required));
                let prog = SlashProgress {
                    case_id: c.id,
                    act_hex: signed.clone(),
                    complete,
                    signatures,
                    required,
                };
                self.ctx.db(|t| {
                    t.slash_vote(c.id, &built, &signed, Some(tip))?;
                    t.set_slash_progress(&prog)
                })?;
                warn!(event = "slash_act_built", case = c.id, target = %hex::encode(c.target_key),
                      fault = %c.fault, complete, signatures, required);
                prog
            }
            (SlashState::Voted, Some(p)) => p,
            (SlashState::Voted, None) => SlashProgress {
                case_id: c.id,
                act_hex: c.my_vote.clone().unwrap_or_default(),
                complete: false,
                signatures: 0,
                required: -1,
            },
            _ => return Ok(()),
        };
        if !prog.complete {
            let evidence: serde_json::Value = serde_json::from_str(&c.evidence_json)?;
            let voted = self.ctx.db(|t| t.slash_voters(c.id))?;
            for peer in self.ctx.peers.urls().to_vec() {
                if voted.contains(&peer) {
                    continue;
                }
                let req = SlashSignRequest {
                    evidence: evidence.clone(),
                    act: prog.act_hex.clone(),
                };
                match self.ctx.peers.slash_sign(&peer, &req).await {
                    Ok(r) => {
                        info!(event = "slash_vote_received", case = c.id, peer = %peer,
                              signatures = r.signatures, required = r.required, complete = r.complete);
                        prog.act_hex = r.hex;
                        prog.complete = r.complete;
                        prog.signatures = r.signatures;
                        prog.required = r.required;
                        self.ctx.db(|t| {
                            t.record_slash_vote(c.id, &peer, r.signatures, r.complete)?;
                            t.set_slash_progress(&prog)
                        })?;
                        if prog.complete {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(event = "slash_vote_refused", case = c.id, peer = %peer, error = %e)
                    }
                }
            }
        }
        if prog.complete {
            let h: HexBytes = prog.act_hex.parse().map_err(|e| anyhow!("{e}"))?;
            let txid = self.ctx.ycash.set_sendact(&h).await?;
            self.ctx
                .db(|t| t.slash_submitted(c.id, &txid.0, Some(tip)))?;
            warn!(event = "slash_submitted", case = c.id, target = %hex::encode(c.target_key),
                  txid = %txid);
        }
        Ok(())
    }
}
