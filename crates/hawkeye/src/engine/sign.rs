// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Set signatures on a template input (UNLOCK role 1, CANCEL role 2) and the checks applied to
//! co-signatures a peer returns (remedial report 05/H-1 §4.4).
//!
//! Signing runs inside a sign-once ledger transaction (synchronous): `SetSigning::prepare`
//! does the asynchronous reads first, `SetSigning::sign` is then called by the sign-once
//! closure. In `[keys] ycash_signing = "self"` mode (remedial report 05/M-1) Hawkeye makes the
//! member key's set and act signatures itself ([`self_sign_template`], [`self_sign_act`]): the
//! node wallet never holds the member key and signs only its fee inputs (`vault_send`,
//! `set_sendact`), and the node's own sign-once guard (`set-sign-once`) no longer applies — the
//! ledger's records are the guard.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Result, anyhow, ensure};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::script::{push_to, push_values};
use hawkeye_core::setsig::{Role, act_msg, recover_compact, set_sig_msg, sign_compact};
use hawkeye_core::sighash::{SET_SIG_HASH_TYPE, zip243};
use hawkeye_core::template::{TemplateKind, parse_selector, selector_script_sig};
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33, SecretKey};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::{HexBytes, YcashRpc};

use super::{Ctx, block_on};
use crate::config::{Params, YcashSigning};
use crate::convert::op_rpc;

/// What one signing call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutcome {
    /// The transaction with the signature(s) added.
    pub hex: String,
    /// The template input's sighash.
    pub sighash: Hash32,
    /// Threshold reached.
    pub complete: bool,
    /// Signatures now on the input.
    pub signatures: u32,
    /// Signatures needed.
    pub required: u32,
}

/// A prepared set signature for one template spend.
pub(crate) struct SetSigning {
    role: Role,
    how: How,
}

enum How {
    /// The node wallet signs (`set_signunlock` / `set_signcancel`).
    Wallet(Arc<YcashRpc>),
    /// Hawkeye signs with the member key (`[keys] ycash_signing = "self"`, 05/M-1).
    SelfSigned(Box<SelfSigner>),
}

struct SelfSigner {
    key: SecretKey,
    set_id: Hash32,
    template: CoreOutPoint,
    coin: (Vec<u8>, u64),
    branch_id: u32,
    need: u32,
}

impl SetSigning {
    /// Prepare to sign `role` on the template input spending `template`, in this attestor's
    /// signing mode.
    pub(crate) async fn prepare(
        ctx: &Ctx,
        _hex: &str,
        role: Role,
        template: CoreOutPoint,
    ) -> Result<Self> {
        Self::prepare_with(&ctx.ycash, &ctx.params, &ctx.key, role, template).await
    }

    /// [`SetSigning::prepare`] from parts (the CLI's drills, which run no engine).
    pub(crate) async fn prepare_with(
        ycash: &Arc<YcashRpc>,
        params: &Params,
        key: &SecretKey,
        role: Role,
        template: CoreOutPoint,
    ) -> Result<Self> {
        let how = match params.ycash_signing {
            YcashSigning::Wallet => How::Wallet(ycash.clone()),
            YcashSigning::SelfSigned => {
                let op = op_rpc(&template);
                let o = ycash
                    .gettxout(&op.txid, op.vout, true)
                    .await?
                    .ok_or_else(|| anyhow!("the template input {template} is spent or unknown"))?;
                let set = ycash.set_getinfo(&params.set_hash(), None).await?;
                let need = match role {
                    Role::Unlock => set.set.params.unlockthreshold,
                    Role::Cancel => set.set.params.cancelthreshold,
                };
                How::SelfSigned(Box::new(SelfSigner {
                    key: key.clone(),
                    set_id: params.set_id,
                    template,
                    coin: (
                        o.script_pub_key.hex.0,
                        u64::try_from(o.value.zat()).unwrap_or(0),
                    ),
                    branch_id: next_branch_id(ycash).await?,
                    need,
                }))
            }
        };
        Ok(Self { role, how })
    }

    /// Sign (synchronously: inside the sign-once closure).
    pub(crate) fn sign(&self, hex: &str) -> core::result::Result<SignOutcome, String> {
        match &self.how {
            How::Wallet(ycash) => {
                let h: HexBytes = hex.parse().map_err(|e| format!("{e}"))?;
                let r = match self.role {
                    Role::Unlock => block_on(ycash.set_signunlock(&h)),
                    Role::Cancel => block_on(ycash.set_signcancel(&h)),
                }
                .map_err(|e| e.to_string())?;
                Ok(SignOutcome {
                    hex: r.hex.to_string(),
                    sighash: r.sighash.0,
                    complete: r.complete,
                    signatures: r.signatures,
                    required: r.required,
                })
            }
            How::SelfSigned(s) => self_sign_template(
                &s.key,
                &s.set_id,
                self.role,
                &s.template,
                &s.coin,
                s.branch_id,
                s.need,
                hex,
            )
            .map_err(|e| format!("{e:#}")),
        }
    }
}

/// The next block's consensus branch id (`getblockchaininfo.consensus.nextblock`): what a
/// ZIP-243 signature made now commits to.
pub async fn next_branch_id(ycash: &YcashRpc) -> Result<u32> {
    let b = ycash.getblockchaininfo().await?.consensus.nextblock;
    u32::from_str_radix(&b, 16).map_err(|e| anyhow!("consensus.nextblock {b:?}: {e}"))
}

/// The self-signed set signature (05/M-1 §4.3 step 1): the ZIP-243 sighash of the template
/// input under `branch_id`, `SetSigMsg(setId, role, prevout, sighash)`, `sign_compact` with the
/// member key, appended to the input's existing signatures (none added if one of them is
/// already this key's: idempotent), then the selector — the scriptSig `SignSetInPlace` builds.
#[allow(clippy::too_many_arguments)]
pub fn self_sign_template(
    key: &SecretKey,
    set_id: &Hash32,
    role: Role,
    template: &CoreOutPoint,
    coin: &(Vec<u8>, u64),
    branch_id: u32,
    need: u32,
    hex: &str,
) -> Result<SignOutcome> {
    let mut tx = Transaction::decode_hex(hex).map_err(|e| anyhow!("decode: {e}"))?;
    let idx = input_index(&tx, template)
        .ok_or_else(|| anyhow!("the transaction spends no {template}"))?;
    let mut args = role_args(&tx, idx, role)?;
    let core = hawkeye_core::tx::Transaction::parse(&tx.encode()).map_err(|e| anyhow!("{e}"))?;
    let sighash = zip243(&core, idx, &coin.0, coin.1, SET_SIG_HASH_TYPE, branch_id)
        .map_err(|e| anyhow!("sighash: {e}"))?;
    let msg = set_sig_msg(set_id, role.byte(), template, &sighash);
    let me = key.public_key();
    for a in &args {
        let k = recover_compact(a, &msg).map_err(|_| {
            anyhow!("an existing set signature does not verify (the transaction changed?)")
        })?;
        if k == me {
            let n = args.len() as u32;
            return Ok(SignOutcome {
                hex: tx.encode_hex(),
                sighash,
                complete: n >= need,
                signatures: n,
                required: need,
            });
        }
    }
    if (args.len() as u32) < need {
        args.push(
            sign_compact(key, &msg)
                .map_err(|e| anyhow!("{e}"))?
                .to_vec(),
        );
    }
    let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    tx.inputs[idx].script_sig =
        selector_script_sig(&refs, role.byte()).map_err(|e| anyhow!("{e}"))?;
    let n = args.len() as u32;
    Ok(SignOutcome {
        hex: tx.encode_hex(),
        sighash,
        complete: n >= need,
        signatures: n,
        required: need,
    })
}

/// The act output of an act transaction (`OP_RETURN <P: "YV"…> <sig>*`, ycash-dd
/// `src/vault/act.cpp` `EncodeAct`): its index, the payload and the signatures already on it.
pub fn act_parts(tx: &Transaction) -> Result<(usize, Vec<u8>, Vec<Vec<u8>>)> {
    for (n, o) in tx.outputs.iter().enumerate() {
        let spk = &o.script_pubkey;
        if spk.first() != Some(&0x6a) {
            continue;
        }
        let Ok(pushes) = push_values(&spk[1..]) else {
            continue;
        };
        if let Some((p, sigs)) = pushes.split_first()
            && p.len() >= 4
            && p[0] == 0x59
            && p[1] == 0x56
        {
            return Ok((n, p.clone(), sigs.to_vec()));
        }
    }
    Err(anyhow!("the transaction carries no YV act"))
}

/// The self-signed act signature (05/M-1 §4.3 step 2): `ActMsg(P, vin[0].prevout)` signed with
/// the member key and appended to the act output, as `set_signact` does (`SignActInPlace`:
/// `OP_RETURN <P> <sig1> … <sigk>`); idempotent when the key already signed. Returns the hex,
/// the act message and the signatures now on the act.
pub fn self_sign_act(key: &SecretKey, hex: &str) -> Result<(String, Hash32, u32)> {
    let mut tx = Transaction::decode_hex(hex).map_err(|e| anyhow!("act: {e}"))?;
    let vin0 = tx
        .inputs
        .first()
        .ok_or_else(|| anyhow!("an act transaction needs a transparent input"))?;
    let prevout = CoreOutPoint::new(vin0.prevout.txid.0, vin0.prevout.vout);
    let (n, payload, mut sigs) = act_parts(&tx)?;
    let msg = act_msg(&payload, &prevout);
    let me = key.public_key();
    let mut mine = false;
    for s in &sigs {
        let k = recover_compact(s, &msg)
            .map_err(|_| anyhow!("an existing act signature does not recover (vin[0] changed?)"))?;
        mine |= k == me;
    }
    if !mine {
        sigs.push(
            sign_compact(key, &msg)
                .map_err(|e| anyhow!("{e}"))?
                .to_vec(),
        );
    }
    let mut spk = vec![0x6a];
    push_to(&mut spk, &payload);
    for s in &sigs {
        push_to(&mut spk, s);
    }
    tx.outputs[n].script_pubkey = spk;
    Ok((tx.encode_hex(), msg, sigs.len() as u32))
}

/// The index of the input spending `prevout` in `tx`.
pub fn input_index(tx: &Transaction, prevout: &hawkeye_core::OutPoint) -> Option<usize> {
    tx.inputs
        .iter()
        .position(|i| i.prevout.txid.0 == prevout.txid && i.prevout.vout == prevout.vout)
}

/// The set-signature pushes on input `idx` for `role` (none for an empty scriptSig).
pub fn role_args(tx: &Transaction, idx: usize, role: Role) -> Result<Vec<Vec<u8>>> {
    let ss = &tx
        .inputs
        .get(idx)
        .ok_or_else(|| anyhow!("no input {idx}"))?
        .script_sig;
    if ss.is_empty() {
        return Ok(vec![]);
    }
    let kind = match role {
        Role::Unlock => TemplateKind::Vault,
        Role::Cancel => TemplateKind::Intent,
    };
    let s = parse_selector(kind, ss).map_err(|e| anyhow!("scriptSig: {e}"))?;
    ensure!(
        s.selector == role.byte(),
        "the template input is spent with selector {}, not {}",
        s.selector,
        role.byte()
    );
    Ok(s.args)
}

/// What a peer's co-signed transaction must satisfy to be adopted (remedial report 05/H-1
/// §4.4, finding 05/L-1).
pub struct Adoption<'a> {
    /// Our transaction (the signatures we hold).
    pub ours: &'a Transaction,
    /// The template input.
    pub idx: usize,
    /// UNLOCK or CANCEL.
    pub role: Role,
    /// The threshold.
    pub need: usize,
    /// The template coin's script and value.
    pub coin: (&'a [u8], u64),
    /// The current members.
    pub members: &'a [PubKey33],
}

impl Adoption<'_> {
    /// Check `theirs` and return its signers. It must be our transaction byte for byte except
    /// the template input's scriptSig; that scriptSig must carry `role`'s selector with at most
    /// `need` pushes of exactly 65 bytes; every push must be a valid set signature of a
    /// **distinct current member** over the transaction (checked by `ctx`'s attributor: the
    /// daemon recomputes the ZIP-243 sighash, which excludes scriptSigs, so it is the sighash of
    /// our own record); every signer we already had must still be there; and it must carry
    /// more signatures than ours.
    pub fn check(&self, ctx: &Ctx, theirs_hex: &str) -> Result<Vec<PubKey33>> {
        let theirs = Transaction::decode_hex(theirs_hex).map_err(|e| anyhow!("decode: {e}"))?;
        let o = self.ours;
        ensure!(
            theirs.overwintered == o.overwintered
                && theirs.version == o.version
                && theirs.version_group_id == o.version_group_id
                && theirs.lock_time == o.lock_time
                && theirs.expiry_height == o.expiry_height
                && theirs.outputs == o.outputs
                && theirs.sapling == o.sapling
                && theirs.joinsplits == o.joinsplits
                && theirs.inputs.len() == o.inputs.len(),
            "not the transaction we built (outputs, version, locktime, expiry or inputs differ)"
        );
        for (j, (a, b)) in theirs.inputs.iter().zip(&o.inputs).enumerate() {
            ensure!(
                a.prevout == b.prevout && a.sequence == b.sequence,
                "input {j} differs"
            );
            ensure!(
                j == self.idx || a.script_sig == b.script_sig,
                "input {j}'s scriptSig differs (only the template input may)"
            );
        }
        let args = role_args(&theirs, self.idx, self.role)?;
        ensure!(
            args.len() <= self.need,
            "{} signatures, more than the threshold {}",
            args.len(),
            self.need
        );
        ensure!(
            args.iter().all(|a| a.len() == 65),
            "a push is not a 65-byte signature"
        );
        ensure!(
            theirs.inputs[self.idx].script_sig.len() <= 66 * self.need + 1,
            "the template scriptSig is longer than {} signatures",
            self.need
        );
        let had = role_args(o, self.idx, self.role)?;
        ensure!(args.len() > had.len(), "no new signature");
        let a = ctx
            .attributor
            .attribute(
                &theirs.encode(),
                self.idx,
                self.coin.0,
                self.coin.1,
                hawkeye_core::VAULT_BRANCH_ID,
            )
            .map_err(|e| anyhow!("attribution: {e}"))?;
        ensure!(
            a.set_id == ctx.params.set_id && a.role == self.role,
            "the signatures are for another set or role"
        );
        ensure!(
            a.signers.len() == args.len(),
            "a signature does not recover"
        );
        let signers: Vec<PubKey33> = a.signers.iter().map(|s| s.pubkey).collect();
        let distinct: HashSet<_> = signers.iter().collect();
        ensure!(distinct.len() == signers.len(), "a member signed twice");
        for k in &signers {
            ensure!(
                self.members.contains(k),
                "signer {} is not a current member",
                hex::encode(k)
            );
        }
        if !had.is_empty() {
            let mine = ctx
                .attributor
                .attribute(
                    &o.encode(),
                    self.idx,
                    self.coin.0,
                    self.coin.1,
                    hawkeye_core::VAULT_BRANCH_ID,
                )
                .map_err(|e| anyhow!("our own attribution: {e}"))?;
            for s in &mine.signers {
                ensure!(
                    signers.contains(&s.pubkey),
                    "our signer {} was dropped",
                    hex::encode(s.pubkey)
                );
            }
        }
        Ok(signers)
    }
}

/// Whether a re-funded spend is `old` with only its fee inputs replaced (01/V-2): the template
/// input spending `template` — prevout, sequence and the scriptSig with the set signatures —
/// once in each, every output, the version, lock time and expiry byte-identical, nothing
/// shielded. Exactly what `SIGHASH_ALL|SIGHASH_ANYONECANPAY` binds, so the set signatures on
/// the template input are valid on the re-funded spend too, and Hawkeye never broadcasts a
/// spend that pays anyone else.
pub fn same_set_signed_spend(
    old: &Transaction,
    new: &Transaction,
    template: &CoreOutPoint,
) -> Result<()> {
    ensure!(
        new.overwintered == old.overwintered
            && new.version == old.version
            && new.version_group_id == old.version_group_id
            && new.lock_time == old.lock_time
            && new.expiry_height == old.expiry_height,
        "the version, lock time or expiry changed"
    );
    ensure!(new.outputs == old.outputs, "the outputs changed");
    ensure!(
        !new.has_shielded(),
        "the re-funded spend has shielded parts"
    );
    let spends = |t: &Transaction| {
        t.inputs
            .iter()
            .filter(|i| i.prevout.txid.0 == template.txid && i.prevout.vout == template.vout)
            .count()
    };
    ensure!(
        spends(old) == 1 && spends(new) == 1,
        "the template input {template} is not spent exactly once"
    );
    let (a, b) = (
        &old.inputs[input_index(old, template).expect("counted")],
        &new.inputs[input_index(new, template).expect("counted")],
    );
    ensure!(
        a.sequence == b.sequence && a.script_sig == b.script_sig,
        "the template input's sequence or scriptSig changed"
    );
    Ok(())
}

/// [`same_set_signed_spend`] whatever set signatures either carries: the same unlock or cancel
/// (one sighash under `SIGHASH_ALL|SIGHASH_ANYONECANPAY`), only the fee inputs and the template
/// input's signatures may differ.
pub fn same_spend_any_signatures(
    old: &Transaction,
    new: &Transaction,
    template: &CoreOutPoint,
) -> Result<()> {
    let clear = |t: &Transaction| {
        let mut t = t.clone();
        if let Some(i) = input_index(&t, template) {
            t.inputs[i].script_sig.clear();
        }
        t
    };
    same_set_signed_spend(&clear(old), &clear(new), template)
}

/// Whether a send failed because a fee input is gone: spent in a block (`-26 "18:
/// bad-txns-inputs-spent"` while its transaction has unspent outputs, `-25 Missing inputs` once
/// it has none: both node lines, regtest_self_signing.rs) or by a mempool transaction
/// (`txn-mempool-conflict`). The template input gone fails the same way; `vault_refee` then
/// refuses and the original error stands.
fn fee_input_lost(e: &hawkeye_ycash::Error) -> bool {
    match e.reason() {
        Some(hawkeye_ycash::ErrorReason::MissingInputs) => true,
        Some(hawkeye_ycash::ErrorReason::Rejected { reason, .. }) => {
            reason.contains("inputs-spent") || reason.contains("mempool-conflict")
        }
        _ => false,
    }
}

/// `vault_send` of a set-signed UNLOCK or CANCEL spend of `template`; when a fee input is gone,
/// re-fund it once with `vault_refee` (01/V-2: the set signatures are over
/// `SIGHASH_ALL|SIGHASH_ANYONECANPAY`, so they stay valid), check that only the fee inputs
/// changed ([`same_set_signed_spend`]), and send that. The stored signed bytes are kept: a
/// later retry re-funds again. Any refusal of the re-fund returns the original error.
pub async fn send_set_signed(
    ycash: &YcashRpc,
    hex: &HexBytes,
    template: &CoreOutPoint,
) -> core::result::Result<hawkeye_ycash::primitives::Txid, hawkeye_ycash::Error> {
    let err = match ycash.vault_send(hex).await {
        Ok(t) => return Ok(t),
        Err(e) if fee_input_lost(&e) => e,
        Err(e) => return Err(e),
    };
    match checked_refee(ycash, hex, template).await {
        Ok(h) => ycash.vault_send(&h).await,
        Err(e) => {
            tracing::warn!(event = "refee_refused", template = %template, error = %e,
                           send_error = %err);
            Err(err)
        }
    }
}

/// The most this wallet pays to re-fund (or exactly fund) a set-signed spend, zatoshi: its fee,
/// nothing else (review H-1). 0.001 YEC: far above a ZIP-317 fee of a 2-in / 3-out unlock.
pub const MAX_REFUND_ZAT: u64 = 100_000;

/// **Review H-1.** A set-signed UNLOCK (burn or roll) may move only the template coin: the value
/// of all its outputs equals the vault's value exactly (the intent, the byte-identical re-lock
/// of the remainder, a zero-value memo), so whoever funds it — the builder, a re-funder, a
/// takeover leader — pays the fee and nothing more. The node (S-2) bounds only the vault's
/// value; a change output, or any output beyond it, would be paid by the fee inputs, and
/// `vault_refee` funds whatever the outputs need. Hawkeye builds no change
/// ([`fund_exactly`]); co-signers and adopters refuse anything else.
pub fn unlock_value_bounded(tx: &Transaction, vault_value: u64) -> Result<()> {
    let mut total: u64 = 0;
    for o in &tx.outputs {
        let v = u64::try_from(o.value).map_err(|_| anyhow!("a negative output"))?;
        total = total
            .checked_add(v)
            .ok_or_else(|| anyhow!("outputs overflow"))?;
    }
    ensure!(
        total == vault_value,
        "the outputs move {total} zat, the vault holds {vault_value}: an unlock may carry no \
         change or extra output (its funder would pay it, review H-1)"
    );
    Ok(())
}

/// What re-funding costs this wallet: the outputs' value beyond the template coin, plus the fee.
pub fn refund_cost(tx: &Transaction, template_value: u64, fee_zat: u64) -> Result<u64> {
    let mut total: u64 = 0;
    for o in &tx.outputs {
        total = total
            .checked_add(u64::try_from(o.value).map_err(|_| anyhow!("a negative output"))?)
            .ok_or_else(|| anyhow!("outputs overflow"))?;
    }
    Ok(total.saturating_sub(template_value).saturating_add(fee_zat))
}

fn refused(message: String) -> hawkeye_ycash::Error {
    hawkeye_ycash::Error::Rpc(hawkeye_ycash::RpcError {
        method: "vault_refee".into(),
        code: -8,
        message,
    })
}

/// Re-fund `hex` with `vault_refee` and check it before anything is sent: only the fee inputs
/// changed ([`same_set_signed_spend`]), and this wallet pays at most [`MAX_REFUND_ZAT`] in all
/// (fee plus any value the outputs take beyond the template coin, review H-1). Fails closed:
/// a transaction that does not decode, a template coin that is gone, a cost over the bound.
async fn checked_refee(
    ycash: &YcashRpc,
    hex: &HexBytes,
    template: &CoreOutPoint,
) -> core::result::Result<HexBytes, hawkeye_ycash::Error> {
    let op = op_rpc(template);
    let coin = ycash
        .gettxout(&op.txid, op.vout, true)
        .await?
        .ok_or_else(|| refused(format!("the template coin {template} is spent")))?;
    let value = u64::try_from(coin.value.zat()).unwrap_or(0);
    let refunded = ycash.vault_refee(hex).await?;
    let (Ok(old), Ok(new)) = (
        Transaction::decode(&hex.0),
        Transaction::decode(&refunded.hex.0),
    ) else {
        return Err(refused("a re-funded spend that does not decode".into()));
    };
    if let Err(why) = same_set_signed_spend(&old, &new, template) {
        return Err(refused(format!("the re-funded spend changed: {why:#}")));
    }
    let fee = u64::try_from(refunded.fee.zat()).unwrap_or(u64::MAX);
    let cost = refund_cost(&new, value, fee).map_err(|e| refused(format!("{e:#}")))?;
    if fee > MAX_REFUND_ZAT || cost > MAX_REFUND_ZAT {
        return Err(refused(format!(
            "re-funding {template} would cost this wallet {cost} zat (fee {fee}) > \
             {MAX_REFUND_ZAT}: not sent (review H-1)"
        )));
    }
    tracing::info!(event = "refee", template = %template, replaced = refunded.replaced.len(),
                   fee = %refunded.fee, cost);
    Ok(refunded.hex)
}

/// `vault_send` of set-signed bytes after re-funding **every** fee input with `vault_refee`
/// (01/V-2): for bytes this wallet did not fund — a co-signed unlock adopted as the burn's new
/// leader, a previous leader's unlock fetched at takeover — or whose fee input is gone. The
/// re-fund is checked first (`checked_refee`: only the fee inputs change, and it costs at most
/// [`MAX_REFUND_ZAT`]); nothing is sent otherwise.
pub async fn send_refunded(
    ycash: &YcashRpc,
    hex: &HexBytes,
    template: &CoreOutPoint,
) -> core::result::Result<hawkeye_ycash::primitives::Txid, hawkeye_ycash::Error> {
    let h = checked_refee(ycash, hex, template).await?;
    ycash.vault_send(&h).await
}

/// Fund an **unsigned** unlock exactly (review H-1): drop the change output(s) the node's build
/// added (P2PKH / P2SH outputs: an unlock pays its recipient through the intent), then
/// `vault_refee`, which funds exactly the fee. The result moves the vault's value and nothing
/// else ([`unlock_value_bounded`]), so no re-funder can ever be made to pay a change output.
pub async fn fund_exactly(
    ycash: &YcashRpc,
    hex: &str,
    template: &CoreOutPoint,
    vault_value: u64,
) -> Result<String> {
    let mut tx = Transaction::decode_hex(hex).map_err(|e| anyhow!("{e}"))?;
    tx.outputs.retain(|o| {
        hawkeye_core::script::parse_p2pkh(&o.script_pubkey).is_none()
            && hawkeye_core::script::parse_p2sh(&o.script_pubkey).is_none()
    });
    unlock_value_bounded(&tx, vault_value)?;
    let stripped = HexBytes(tx.encode());
    let h = checked_refee(ycash, &stripped, template)
        .await
        .map_err(|e| anyhow!("funding the unlock exactly: {e}"))?;
    let funded = Transaction::decode(&h.0).map_err(|e| anyhow!("{e}"))?;
    unlock_value_bounded(&funded, vault_value)?;
    Ok(funded.encode_hex())
}

/// `vault_buildunlock` of `vault` to `recipients`. The node wallet remembers one build per vault
/// (07/N-2) and refuses other recipients (`already built a different unlock`); `unsigned_here`
/// (this attestor's ledger holds no unlock signature of the vault: it never handed one out —
/// in self mode it signs only inside the ledger transaction, in wallet mode the node's own
/// `set-sign-once` record still refuses a second spend) then discards it with `rebuild`, once.
pub async fn build_unlock(
    ycash: &YcashRpc,
    vault: &hawkeye_ycash::OutPoint,
    recipients: &[hawkeye_ycash::types::Recipient],
    unsigned_here: bool,
) -> core::result::Result<hawkeye_ycash::types::BuildUnlockResult, hawkeye_ycash::Error> {
    match ycash.vault_buildunlock(vault, recipients).await {
        Err(e)
            if unsigned_here
                && e.reason() == Some(hawkeye_ycash::ErrorReason::AlreadyBuiltDifferent) =>
        {
            tracing::warn!(event = "unlock_rebuild", vault = %vault,
                           "the node wallet remembered another unlock of this vault, signed by no one here: rebuilding");
            ycash.vault_buildunlock_with(vault, recipients, true).await
        }
        r => r,
    }
}

#[cfg(test)]
mod tests {
    use hawkeye_ycash::tx::{TxIn, TxOut};
    use hawkeye_ycash::{Hash256, OutPoint};

    use super::*;

    fn op(b: u8, n: u32) -> OutPoint {
        OutPoint::new(Hash256([b; 32]), n)
    }

    fn signed() -> Transaction {
        Transaction::new_v4(
            vec![
                TxIn {
                    prevout: op(1, 0),
                    script_sig: vec![0x41, 0x1f, 0x51],
                    sequence: u32::MAX,
                },
                TxIn {
                    prevout: op(2, 3),
                    script_sig: vec![],
                    sequence: u32::MAX,
                },
            ],
            vec![
                TxOut {
                    value: 5,
                    script_pubkey: vec![0x51],
                },
                TxOut {
                    value: 7,
                    script_pubkey: vec![0x52],
                },
            ],
            0,
            99,
        )
    }

    #[test]
    fn a_refunded_spend_changes_only_its_fee_inputs() {
        let t = CoreOutPoint::new([1; 32], 0);
        let old = signed();
        // the node's re-fund: template input first, the fee input replaced by two coins
        let mut new = old.clone();
        new.inputs[1].prevout = op(9, 0);
        new.inputs.push(TxIn {
            prevout: op(9, 1),
            script_sig: vec![],
            sequence: u32::MAX,
        });
        same_set_signed_spend(&old, &new, &t).unwrap();
        let bad: [fn(&mut Transaction); 7] = [
            |x| x.outputs[1].value += 1,
            |x| x.outputs.push(TxOut::op_return(b"x")),
            |x| x.inputs[0].script_sig.push(0),
            |x| x.inputs[0].sequence = 0,
            |x| x.expiry_height += 1,
            |x| x.lock_time = 5,
            |x| x.inputs.push(x.inputs[0].clone()),
        ];
        for (n, f) in bad.iter().enumerate() {
            let mut b = new.clone();
            f(&mut b);
            assert!(same_set_signed_spend(&old, &b, &t).is_err(), "case {n}");
        }
        let mut gone = new.clone();
        gone.inputs.remove(0);
        assert!(same_set_signed_spend(&old, &gone, &t).is_err());
        assert!(same_set_signed_spend(&old, &new, &CoreOutPoint::new([3; 32], 0)).is_err());
    }
}
