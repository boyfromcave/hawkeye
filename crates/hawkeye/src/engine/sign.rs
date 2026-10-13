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
use hawkeye_core::sighash::{SIGHASH_ALL, zip243};
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
    let sighash = zip243(&core, idx, &coin.0, coin.1, SIGHASH_ALL, branch_id)
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
