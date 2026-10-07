//! Set-signature attribution (plan §2.3, §4.5): which keys signed a template spend.
//!
//! An UNLOCK of a vault V (selector 1) and a CANCEL of an intent I (selector 2) carry `k`
//! 65-byte recoverable set signatures in the scriptSig, each over
//! `SetSigMsg(setId, role, prevout, sighash)` with
//! `sighash = SignatureHash(scriptCode = prev scriptPubKey, tx, nIn, SIGHASH_ALL, amount,
//! consensusBranchId)` (upgrade plan §15.2 steps 3–4). Recovering each signature over that
//! message names the signer: the evidence for a slash case.

use crate::bytes::{Hash32, OutPoint};
use crate::error::{Error, Result, array};
use crate::keys::PubKey33;
use crate::setsig::{Role, SIG_LEN, recover_compact, set_sig_msg};
use crate::sighash::{SIGHASH_ALL, zip243};
use crate::template::{
    SEL_CANCEL, SEL_UNLOCK, TemplateKind, TemplateShape, parse_selector, template_shape,
};
use crate::tx::Transaction;

/// The consensus branch id of the vault network upgrade (`UPGRADE_VAULT`, `0x6d5b7a31`): the
/// `branch_id` for every spend mined at or after its activation.
pub const VAULT_BRANCH_ID: u32 = 0x6d5b_7a31;

/// One set signature of a template input and the key it recovers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSigner {
    /// The compressed key the signature recovers to over the input's `SetSigMsg`.
    pub pubkey: PubKey33,
    /// The 65-byte signature as it appears in the scriptSig (`header ‖ r ‖ s`).
    pub signature: [u8; SIG_LEN],
}

/// What a template input's set signatures commit to and who made them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The set the signatures are checked against (a V's `setId` for an UNLOCK, an I's
    /// `cancelSetId` for a CANCEL), internal byte order.
    pub set_id: Hash32,
    /// [`Role::Unlock`] (V selector 1) or [`Role::Cancel`] (I selector 2).
    pub role: Role,
    /// The coin the input spends.
    pub prevout: OutPoint,
    /// The input's `SIGHASH_ALL` signature hash (internal byte order).
    pub sighash: Hash32,
    /// The set signatures in scriptSig order, each with its recovered key.
    pub signers: Vec<SetSigner>,
}

impl Attribution {
    /// The `SetSigMsg` every signature signs.
    pub fn set_sig_msg(&self) -> Hash32 {
        set_sig_msg(&self.set_id, self.role.byte(), &self.prevout, &self.sighash)
    }
}

/// Attribute input `input_index` of the serialised v4 (or v3) transaction `tx_bytes`, which
/// spends a coin with scriptPubKey `prev_spk` and value `prev_value_zat`, under consensus branch
/// `branch_id` (normally [`VAULT_BRANCH_ID`]).
///
/// `prev_spk` must be a vault V spent with selector 1 (UNLOCK) or an intent I spent with
/// selector 2 (CANCEL). Every argument pushed before the selector must be a strict set signature
/// (65 bytes, header 31..34, low S) that recovers over the input's `SetSigMsg`; there must be at
/// least one.
///
/// The recovered keys are what the signatures **name**, not a membership proof: any 65 bytes
/// recover to some key. A spend the node accepted had `k` signatures by distinct current members
/// (§15.2 step 5); for a spend not yet mined, check the keys against the set before acting.
///
/// Errors: [`Error::Tx`] (the transaction does not parse, or has no such input),
/// [`Error::Template`] (`prev_spk` is not a V or I), [`Error::Selector`] (the scriptSig is not a
/// template scriptSig, or its selector is not UNLOCK on a V / CANCEL on an I, or it carries no
/// signatures), [`Error::Signature`] / [`Error::Length`] (an argument is not a strict set
/// signature).
pub fn attribute_template_input(
    tx_bytes: &[u8],
    input_index: usize,
    prev_spk: &[u8],
    prev_value_zat: u64,
    branch_id: u32,
) -> Result<Attribution> {
    let tx = Transaction::parse(tx_bytes)?;
    let input = tx
        .vin
        .get(input_index)
        .ok_or(Error::Tx("input index out of range"))?;
    let (kind, set_id, role, want) = match template_shape(prev_spk) {
        Some(TemplateShape::Vault(v)) => (TemplateKind::Vault, v.set_id, Role::Unlock, SEL_UNLOCK),
        Some(TemplateShape::Intent(i)) => (
            TemplateKind::Intent,
            i.cancel_set_id,
            Role::Cancel,
            SEL_CANCEL,
        ),
        Some(TemplateShape::Malformed) => {
            return Err(Error::Template("template-shaped but malformed"));
        }
        None => return Err(Error::Template("not a vault or intent scriptPubKey")),
    };
    let spend = parse_selector(kind, &input.script_sig)?;
    if spend.selector != want {
        return Err(Error::Selector(match kind {
            TemplateKind::Vault => "vault spend is not an UNLOCK (selector 1)",
            TemplateKind::Intent => "intent spend is not a CANCEL (selector 2)",
        }));
    }
    if spend.args.is_empty() {
        return Err(Error::Selector("no set signatures"));
    }
    let sighash = zip243(
        &tx,
        input_index,
        prev_spk,
        prev_value_zat,
        SIGHASH_ALL,
        branch_id,
    )?;
    let prevout = input.prevout;
    let msg = set_sig_msg(&set_id, role.byte(), &prevout, &sighash);
    let signers = spend
        .args
        .iter()
        .map(|sig| {
            Ok(SetSigner {
                pubkey: recover_compact(sig, &msg)?,
                signature: array("set signature", sig)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Attribution {
        set_id,
        role,
        prevout,
        sighash,
        signers,
    })
}
