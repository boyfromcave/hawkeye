//! Slash cases (plan §2.3, §5.3 steps 3–4): the case owner builds `SET_REMOVE burn=1`, signs it on
//! its own node, gathers the other members' signatures over `POST /slash/sign` (each verifies
//! independently), and sends it; every attestor records the removal when it is mined.

use anyhow::{Result, anyhow};
use hawkeye_core::bytes::sha256d;
use hawkeye_core::leader::leader_for;
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33};
use hawkeye_store::{FaultKind, SignDomain, SlashCaseRecord, SlashState, YcashSignKey};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{ActBody, BuildAct, DecodedAct, DecodedScript};
use hawkeye_ycash::{HexBytes, PubKey};
use tracing::{info, warn};

use super::{Ctx, Engine, block_on};
use crate::convert::op_core;
use crate::peers::{SlashSignRequest, SlashSignResponse};

/// Cases that lapse after this many Ycash blocks without a removal.
pub const CASE_EXPIRY_BLOCKS: u32 = 2_880;

fn act_key(ctx: &Ctx, act_hex: &str) -> Result<YcashSignKey> {
    let tx = Transaction::decode_hex(act_hex).map_err(|e| anyhow!("act: {e}"))?;
    let prevout: CoreOutPoint = tx
        .inputs
        .first()
        .map(|i| op_core(&i.prevout))
        .ok_or_else(|| anyhow!("act has no input"))?;
    Ok(YcashSignKey {
        domain: SignDomain::YcashAct,
        set_id: ctx.params.set_id,
        prevout,
    })
}

/// `set_signact` through the sign-once record. Returns the node's answer (the stored signed
/// hex with `complete` unknown on a repeat).
/// `(complete, signatures, required)` of a `set_signact` answer.
type ActStatus = (bool, u32, i32);

fn sign_act(ctx: &Ctx, act_hex: &str) -> Result<(String, Option<ActStatus>)> {
    let key = act_key(ctx, act_hex)?;
    let ycash = ctx.ycash.clone();
    let set = ctx.set_hash();
    let status = std::cell::Cell::new(None);
    let rec = ctx.db(|t| {
        t.sign_once_ycash(&key, act_hex, |h| {
            let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
            let r = block_on(ycash.set_signact(&hex, Some(&set))).map_err(|e| e.to_string())?;
            status.set(Some((r.complete, r.signatures, r.required)));
            Ok::<_, String>((r.hex.to_string(), sha256d(&hex.0)))
        })
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

/// `POST /slash/sign`: agree only if this attestor's own ledger independently holds a case for
/// the same `(fault, subject, target)` (opened from its own node and chain), and the act removes
/// that target from this set with the right `burn`; then sign it on this node (sign-once).
pub async fn verify_and_sign(ctx: &Ctx, req: &SlashSignRequest) -> Result<SlashSignResponse> {
    let ev = &req.evidence;
    let fault: FaultKind = ev["fault"]
        .as_str()
        .ok_or_else(|| anyhow!("evidence without fault"))?
        .parse()
        .map_err(|e| anyhow!("{e}"))?;
    let target: PubKey33 = hex::decode(ev["target"].as_str().unwrap_or_default())?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("evidence target is not a 33-byte key"))?;
    let subject = hex::decode(ev["subject"].as_str().unwrap_or_default())?;
    if target == ctx.me {
        return Err(anyhow!("refusing to vote on my own removal"));
    }
    let mine = ctx.db(|t| {
        let mut all = vec![];
        for s in [
            SlashState::Opened,
            SlashState::Voted,
            SlashState::Submitted,
            SlashState::Slashed,
        ] {
            all.extend(t.slash_cases_in_state(s)?);
        }
        Ok(all)
    })?;
    if !mine
        .iter()
        .any(|c| c.fault == fault && c.target_key == target && c.subject == subject)
    {
        return Err(anyhow!(
            "no matching case here: this attestor has not observed that fault"
        ));
    }
    let (act_target, burn) = decode_remove(ctx, &req.act).await?;
    if act_target != target {
        return Err(anyhow!("the act removes another member"));
    }
    if burn != (fault != FaultKind::Griefing) {
        return Err(anyhow!("the act's burn flag does not fit the fault"));
    }
    let (hex, status) = sign_act(ctx, &req.act)?;
    let (complete, signatures, required) = status.unwrap_or((false, 0, -1));
    info!(event = "slash_vote_given", fault = %fault, target = %hex::encode(target), complete);
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
        let (mut hex, mut complete) = match (c.state, self.mem.case_hex.get(&c.id)) {
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
                let (signed, status) = sign_act(&self.ctx, &built)?;
                let complete = status.is_some_and(|s| s.0);
                self.ctx
                    .db(|t| t.slash_vote(c.id, &built, &signed, Some(tip)))?;
                warn!(event = "slash_act_built", case = c.id, target = %hex::encode(c.target_key),
                      fault = %c.fault, complete);
                (signed, complete)
            }
            (SlashState::Voted, Some((h, done))) => (h.clone(), *done),
            (SlashState::Voted, None) => (c.my_vote.clone().unwrap_or_default(), false),
            _ => return Ok(()),
        };
        if !complete {
            let evidence: serde_json::Value = serde_json::from_str(&c.evidence_json)?;
            for peer in self.ctx.peers.urls().to_vec() {
                let req = SlashSignRequest {
                    evidence: evidence.clone(),
                    act: hex.clone(),
                };
                match self.ctx.peers.slash_sign(&peer, &req).await {
                    Ok(r) => {
                        info!(event = "slash_vote_received", case = c.id, peer = %peer,
                              signatures = r.signatures, required = r.required, complete = r.complete);
                        hex = r.hex;
                        complete = r.complete;
                        if complete {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(event = "slash_vote_refused", case = c.id, peer = %peer, error = %e)
                    }
                }
            }
        }
        self.mem.case_hex.insert(c.id, (hex.clone(), complete));
        if complete {
            let h: HexBytes = hex.parse().map_err(|e| anyhow!("{e}"))?;
            let txid = self.ctx.ycash.set_sendact(&h).await?;
            self.ctx
                .db(|t| t.slash_submitted(c.id, &txid.0, Some(tip)))?;
            warn!(event = "slash_submitted", case = c.id, target = %hex::encode(c.target_key),
                  txid = %txid);
        }
        Ok(())
    }
}
