//! The vault primitive's templates (upgrade plan §15.3): the vault V, the intent I, the bond B,
//! and the selector scriptSigs. A port of `test_framework/vault.py`; the node's
//! `src/test/data/vault_vectors.json` pins every byte.
//!
//! Builders emit exactly the node's bytes; parsers accept **only** those bytes — the opcode
//! skeleton, canonical pushes, minimal numbers in their `push_int` form, field sizes and ranges
//! — by decoding the fields and rebuilding the script for comparison.

use crate::bytes::{Hash32, sha256};
use crate::error::{Error, Result, array};
use crate::keys::{PubKey33, is_compressed_pubkey};
use crate::script::*;

/// The bridge's vault tag, `"WYEC"`.
pub const TAG_WYEC: [u8; 4] = *b"WYEC";

/// `delay` range (V and I).
pub const DELAY_MIN: u16 = 1;
/// `delay` range (V and I).
pub const DELAY_MAX: u16 = 65535;
/// `ownerHeight` range.
pub const OWNER_HEIGHT_MIN: u32 = 1;
/// `ownerHeight` range (below `LOCKTIME_THRESHOLD`: a height, never a time).
pub const OWNER_HEIGHT_MAX: u32 = 499_999_999;
/// `appHeight` range (0 disables the APP branch).
pub const APP_HEIGHT_MAX: u32 = 499_999_999;

/// V selector: set unlock into an intent.
pub const SEL_UNLOCK: u8 = 1;
/// V selector: owner after `ownerHeight`.
pub const SEL_OWNER: u8 = 2;
/// V and I selector: owner once the set is released (dormant / wound down).
pub const SEL_OWNER_RELEASED: u8 = 3;
/// V selector: the application branch after `appHeight`.
pub const SEL_APP: u8 = 4;
/// I selector: release to the recipient after `delay`.
pub const SEL_RELEASE: u8 = 1;
/// I selector: cancel back into a vault.
pub const SEL_CANCEL: u8 = 2;

/// The fields of a vault V. Ids are 32 internal bytes (the `SET_CREATE` txid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultParams {
    /// Application tag (`WYEC` for the bridge).
    pub tag: [u8; 4],
    /// The set whose members sign unlocks (selector 1) and whose dormancy releases the owner.
    pub set_id: Hash32,
    /// The set whose members may cancel the intents this vault unlocks into.
    pub cancel_set_id: Hash32,
    /// The intent's challenge window in blocks.
    pub delay: u16,
    /// The height from which the owner may spend unconditionally (selector 2).
    pub owner_height: u32,
    /// The APP branch's height (0 = disabled).
    pub app_height: u32,
    /// The owner's compressed key.
    pub owner_key: PubKey33,
}

/// The fields of an intent I.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntentParams {
    /// The originating vault's tag.
    pub tag: [u8; 4],
    /// `SHA256(recipient scriptPubKey)`.
    pub recipient_hash: Hash32,
    /// `SHA256(originating V scriptPubKey)`.
    pub vault_hash: Hash32,
    /// Blocks before release (the challenge window).
    pub delay: u16,
    /// The set whose members may cancel (selector 2).
    pub cancel_set_id: Hash32,
    /// The originating vault's set (its dormancy releases the owner, selector 3).
    pub set_id: Hash32,
    /// The originating vault's owner key.
    pub owner_key: PubKey33,
}

impl VaultParams {
    /// Check §15.3's field ranges.
    pub fn check(&self) -> Result<()> {
        if self.delay < DELAY_MIN {
            return Err(Error::Template("delay out of range"));
        }
        if !(OWNER_HEIGHT_MIN..=OWNER_HEIGHT_MAX).contains(&self.owner_height) {
            return Err(Error::Template("ownerHeight out of range"));
        }
        if self.app_height > APP_HEIGHT_MAX {
            return Err(Error::Template("appHeight out of range"));
        }
        if !is_compressed_pubkey(&self.owner_key) {
            return Err(Error::Template("ownerKey not compressed"));
        }
        Ok(())
    }

    /// The V scriptPubKey (bare); fails on out-of-range fields.
    pub fn script(&self) -> Result<Vec<u8>> {
        self.check()?;
        Ok(self.script_unchecked())
    }

    /// `SHA256` of the V scriptPubKey (an intent's `vaultHash`, a roll's `recipientHash`).
    pub fn script_hash(&self) -> Result<Hash32> {
        Ok(sha256(&self.script()?))
    }

    fn script_unchecked(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(220);
        push_to(&mut s, &self.tag);
        push_to(&mut s, &self.cancel_set_id);
        push_int_to(&mut s, i64::from(self.delay));
        s.extend_from_slice(&[OP_2DROP, OP_DROP, OP_DUP, OP_1, OP_EQUAL, OP_IF, OP_DROP]);
        push_to(&mut s, &self.set_id);
        s.extend_from_slice(&[OP_1, OP_CHECKSETSIG]);
        s.extend_from_slice(&[OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF, OP_DROP]);
        push_int_to(&mut s, i64::from(self.owner_height));
        s.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
        push_to(&mut s, &self.owner_key);
        s.push(OP_CHECKSIG);
        s.extend_from_slice(&[OP_ELSE, OP_DUP, OP_3, OP_EQUAL, OP_IF, OP_DROP]);
        push_to(&mut s, &self.set_id);
        s.extend_from_slice(&[OP_CHECKSETDORMANT, OP_VERIFY]);
        push_to(&mut s, &self.owner_key);
        s.push(OP_CHECKSIG);
        s.extend_from_slice(&[OP_ELSE, OP_4, OP_EQUALVERIFY]);
        push_int_to(&mut s, i64::from(self.app_height));
        s.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_ENDIF, OP_ENDIF, OP_ENDIF]);
        s
    }
}

impl IntentParams {
    /// Check §15.3's field ranges.
    pub fn check(&self) -> Result<()> {
        if self.delay < DELAY_MIN {
            return Err(Error::Template("delay out of range"));
        }
        if !is_compressed_pubkey(&self.owner_key) {
            return Err(Error::Template("ownerKey not compressed"));
        }
        Ok(())
    }

    /// The I scriptPubKey (bare); fails on out-of-range fields.
    pub fn script(&self) -> Result<Vec<u8>> {
        self.check()?;
        Ok(self.script_unchecked())
    }

    fn script_unchecked(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(220);
        push_to(&mut s, &self.tag);
        push_to(&mut s, &self.recipient_hash);
        push_to(&mut s, &self.vault_hash);
        s.extend_from_slice(&[OP_2DROP, OP_DROP, OP_DUP, OP_1, OP_EQUAL, OP_IF, OP_DROP]);
        push_int_to(&mut s, i64::from(self.delay));
        s.push(OP_CHECKSEQUENCEVERIFY);
        s.extend_from_slice(&[OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF, OP_DROP]);
        push_to(&mut s, &self.cancel_set_id);
        s.extend_from_slice(&[OP_2, OP_CHECKSETSIG, OP_ELSE, OP_3, OP_EQUALVERIFY]);
        push_to(&mut s, &self.set_id);
        s.extend_from_slice(&[OP_CHECKSETDORMANT, OP_VERIFY]);
        push_to(&mut s, &self.owner_key);
        s.extend_from_slice(&[OP_CHECKSIG, OP_ENDIF, OP_ENDIF]);
        s
    }
}

/// The V scriptPubKey of `p` (see [`VaultParams::script`]).
pub fn vault_script(p: &VaultParams) -> Result<Vec<u8>> {
    p.script()
}

/// The I scriptPubKey of `p` (see [`IntentParams::script`]).
pub fn intent_script(p: &IntentParams) -> Result<Vec<u8>> {
    p.script()
}

const V_OPS: usize = 43;
const I_OPS: usize = 31;

fn data_field<const N: usize>(op: &Op<'_>, what: &'static str) -> Result<[u8; N]> {
    let d = op.data.ok_or(Error::Template(what))?;
    array(what, d).map_err(|_| Error::Template(what))
}

fn num_field(op: &Op<'_>, what: &'static str) -> Result<i64> {
    if op.opcode == OP_0 {
        return Ok(0);
    }
    op.script_num(DEFAULT_MAX_NUM_SIZE)
        .map_err(|_| Error::Template(what))
}

fn ranged<T: TryFrom<i64>>(v: i64, what: &'static str) -> Result<T> {
    T::try_from(v).map_err(|_| Error::Template(what))
}

/// The fields of `spk` if it is exactly a V (§15.3: shape, canonical pushes, minimal numbers,
/// ranges, both `setId` and `ownerKey` copies equal).
pub fn parse_vault(spk: &[u8]) -> Result<VaultParams> {
    let ops = get_ops(spk).map_err(|_| Error::Template("shape"))?;
    if ops.len() != V_OPS {
        return Err(Error::Template("shape"));
    }
    let delay = num_field(&ops[2], "delay")?;
    let owner_height = num_field(&ops[19], "ownerHeight")?;
    let app_height = num_field(&ops[38], "appHeight")?;
    let p = VaultParams {
        tag: data_field(&ops[0], "tag")?,
        cancel_set_id: data_field(&ops[1], "cancelSetId")?,
        set_id: data_field(&ops[10], "setId")?,
        owner_key: data_field(&ops[22], "ownerKey")?,
        delay: ranged::<u16>(delay, "delay out of range")?,
        owner_height: ranged::<u32>(owner_height, "ownerHeight out of range")?,
        app_height: ranged::<u32>(app_height, "appHeight out of range")?,
    };
    p.check()?;
    if p.script_unchecked() != spk {
        return Err(Error::Template("not the canonical V bytes"));
    }
    Ok(p)
}

/// The fields of `spk` if it is exactly an I.
pub fn parse_intent(spk: &[u8]) -> Result<IntentParams> {
    let ops = get_ops(spk).map_err(|_| Error::Template("shape"))?;
    if ops.len() != I_OPS {
        return Err(Error::Template("shape"));
    }
    let delay = num_field(&ops[10], "delay")?;
    let p = IntentParams {
        tag: data_field(&ops[0], "tag")?,
        recipient_hash: data_field(&ops[1], "recipientHash")?,
        vault_hash: data_field(&ops[2], "vaultHash")?,
        delay: ranged::<u16>(delay, "delay out of range")?,
        cancel_set_id: data_field(&ops[18], "cancelSetId")?,
        set_id: data_field(&ops[24], "setId")?,
        owner_key: data_field(&ops[27], "ownerKey")?,
    };
    p.check()?;
    if p.script_unchecked() != spk {
        return Err(Error::Template("not the canonical I bytes"));
    }
    Ok(p)
}

/// The I a V's unlock creates for `recipient_spk` (S-2: the V's tag, sets, delay and owner key;
/// `vaultHash = SHA256(V)`, `recipientHash = SHA256(recipient)`).
pub fn intent_for(vault: &VaultParams, recipient_spk: &[u8]) -> Result<IntentParams> {
    Ok(IntentParams {
        tag: vault.tag,
        recipient_hash: sha256(recipient_spk),
        vault_hash: vault.script_hash()?,
        delay: vault.delay,
        cancel_set_id: vault.cancel_set_id,
        set_id: vault.set_id,
        owner_key: vault.owner_key,
    })
}

/// What a scriptPubKey is to the vault primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateShape {
    /// An exact V.
    Vault(VaultParams),
    /// An exact I.
    Intent(IntentParams),
    /// A V or I opcode skeleton whose fields do not parse: the node rejects the transaction
    /// (`bad-txns-vault-malformed`).
    Malformed,
}

const F: Option<u8> = None;
const fn o(op: u8) -> Option<u8> {
    Some(op)
}
#[rustfmt::skip]
const V_SKELETON: [Option<u8>; V_OPS] = [
    F, F, F, o(OP_2DROP), o(OP_DROP),
    o(OP_DUP), o(OP_1), o(OP_EQUAL), o(OP_IF),
    o(OP_DROP), F, o(OP_1), o(OP_CHECKSETSIG),
    o(OP_ELSE), o(OP_DUP), o(OP_2), o(OP_EQUAL), o(OP_IF),
    o(OP_DROP), F, o(OP_CHECKLOCKTIMEVERIFY), o(OP_DROP), F, o(OP_CHECKSIG),
    o(OP_ELSE), o(OP_DUP), o(OP_3), o(OP_EQUAL), o(OP_IF),
    o(OP_DROP), F, o(OP_CHECKSETDORMANT), o(OP_VERIFY), F, o(OP_CHECKSIG),
    o(OP_ELSE), o(OP_4), o(OP_EQUALVERIFY), F, o(OP_CHECKLOCKTIMEVERIFY),
    o(OP_ENDIF), o(OP_ENDIF), o(OP_ENDIF),
];
#[rustfmt::skip]
const I_SKELETON: [Option<u8>; I_OPS] = [
    F, F, F, o(OP_2DROP), o(OP_DROP),
    o(OP_DUP), o(OP_1), o(OP_EQUAL), o(OP_IF),
    o(OP_DROP), F, o(OP_CHECKSEQUENCEVERIFY),
    o(OP_ELSE), o(OP_DUP), o(OP_2), o(OP_EQUAL), o(OP_IF),
    o(OP_DROP), F, o(OP_2), o(OP_CHECKSETSIG),
    o(OP_ELSE), o(OP_3), o(OP_EQUALVERIFY), F, o(OP_CHECKSETDORMANT), o(OP_VERIFY), F, o(OP_CHECKSIG),
    o(OP_ENDIF), o(OP_ENDIF),
];

fn matches_skeleton(spk: &[u8], skel: &[Option<u8>]) -> bool {
    let Ok(ops) = get_ops(spk) else {
        return false;
    };
    ops.len() == skel.len()
        && ops.iter().zip(skel).all(|(op, want)| match want {
            None => op.opcode <= OP_16 && op.opcode != OP_RESERVED,
            Some(w) => op.opcode == *w,
        })
}

/// Classify `spk` as an exact V, an exact I, a malformed template, or (`None`) anything else
/// (the C++ `MatchVault` / `MatchIntent`).
pub fn template_shape(spk: &[u8]) -> Option<TemplateShape> {
    if matches_skeleton(spk, &V_SKELETON) {
        return Some(parse_vault(spk).map_or(TemplateShape::Malformed, TemplateShape::Vault));
    }
    if matches_skeleton(spk, &I_SKELETON) {
        return Some(parse_intent(spk).map_or(TemplateShape::Malformed, TemplateShape::Intent));
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Bond B

/// The bond redeem script `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <memberKey:33> OP_CHECKSIG`.
pub fn bond_redeem(member_key: &PubKey33, locktime: u32) -> Vec<u8> {
    let mut s = push_int(i64::from(locktime));
    s.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
    push_to(&mut s, member_key);
    s.push(OP_CHECKSIG);
    s
}

/// The bond's P2SH scriptPubKey.
pub fn bond_spk(member_key: &PubKey33, locktime: u32) -> Vec<u8> {
    p2sh_of(&bond_redeem(member_key, locktime))
}

/// `(memberKey, locktime)` if `redeem` is exactly a bond redeem script.
pub fn parse_bond(redeem: &[u8]) -> Result<(PubKey33, u32)> {
    let ops = get_ops(redeem).map_err(|_| Error::Template("shape"))?;
    if ops.len() != 5 {
        return Err(Error::Template("shape"));
    }
    let key: PubKey33 = data_field(&ops[3], "memberKey")?;
    let locktime = ranged::<u32>(num_field(&ops[0], "locktime")?, "locktime out of range")?;
    if bond_redeem(&key, locktime) != redeem {
        return Err(Error::Template("not the canonical bond bytes"));
    }
    Ok((key, locktime))
}

// ---------------------------------------------------------------------------------------------
// Selectors (S-1)

/// Which template an input spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// A vault V (selectors 1..4).
    Vault,
    /// An intent I (selectors 1..3).
    Intent,
}

/// A parsed template scriptSig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorSpend {
    /// The selector, 1..4 (V) or 1..3 (I).
    pub selector: u8,
    /// The values pushed before it (set signatures, or the owner signature), in order.
    pub args: Vec<Vec<u8>>,
}

/// S-1: a scriptSig is push-only and its last op is the opcode `OP_1`..`OP_4` (`OP_3` for an
/// I); a selector pushed as data does not count.
pub fn parse_selector(kind: TemplateKind, script_sig: &[u8]) -> Result<SelectorSpend> {
    let ops = get_ops(script_sig).map_err(|_| Error::Selector("truncated push"))?;
    let Some(last) = ops.last() else {
        return Err(Error::Selector("empty"));
    };
    let mut args = Vec::with_capacity(ops.len() - 1);
    for op in &ops[..ops.len() - 1] {
        args.push(
            op.push_value()
                .ok_or(Error::Selector("not push-only"))?
                .into_owned(),
        );
    }
    let top = match kind {
        TemplateKind::Vault => SEL_APP,
        TemplateKind::Intent => SEL_OWNER_RELEASED,
    };
    if last.data.is_some() || !(OP_1..OP_1 + top).contains(&last.opcode) {
        return Err(Error::Selector("last op is not a selector opcode"));
    }
    Ok(SelectorSpend {
        selector: last.opcode - OP_1 + 1,
        args,
    })
}

/// A template scriptSig: each argument pushed canonically, then the selector opcode.
pub fn selector_script_sig(args: &[&[u8]], selector: u8) -> Result<Vec<u8>> {
    if !(1..=SEL_APP).contains(&selector) {
        return Err(Error::Selector("selector out of range"));
    }
    let mut s = Vec::new();
    for a in args {
        push_to(&mut s, a);
    }
    s.push(OP_1 + selector - 1);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vp() -> VaultParams {
        VaultParams {
            tag: TAG_WYEC,
            set_id: [0x11; 32],
            cancel_set_id: [0x22; 32],
            delay: 6,
            owner_height: 1000,
            app_height: 0,
            owner_key: [2; 33],
        }
    }

    #[test]
    fn vault_round_trip_and_ranges() {
        for (delay, oh, ah) in [
            (1, 1, 0),
            (16, 16, 16),
            (17, 17, 17),
            (65535, 499_999_999, 499_999_999),
        ] {
            let p = VaultParams {
                delay,
                owner_height: oh,
                app_height: ah,
                ..vp()
            };
            let s = p.script().unwrap();
            assert_eq!(parse_vault(&s).unwrap(), p);
            assert_eq!(template_shape(&s), Some(TemplateShape::Vault(p)));
        }
        assert!(VaultParams { delay: 0, ..vp() }.script().is_err());
        assert!(
            VaultParams {
                owner_height: 0,
                ..vp()
            }
            .script()
            .is_err()
        );
        assert!(
            VaultParams {
                owner_height: 500_000_000,
                ..vp()
            }
            .script()
            .is_err()
        );
        assert!(
            VaultParams {
                app_height: 500_000_000,
                ..vp()
            }
            .script()
            .is_err()
        );
        assert!(
            VaultParams {
                owner_key: [4; 33],
                ..vp()
            }
            .script()
            .is_err()
        );
        assert!(parse_intent(&vp().script().unwrap()).is_err());
    }

    #[test]
    fn intent_for_and_round_trip() {
        let recipient = p2pkh_script(&[9; 20]);
        let i = intent_for(&vp(), &recipient).unwrap();
        assert_eq!(i.recipient_hash, sha256(&recipient));
        assert_eq!(i.vault_hash, sha256(&vp().script().unwrap()));
        let s = i.script().unwrap();
        assert_eq!(parse_intent(&s).unwrap(), i);
        assert_eq!(template_shape(&s), Some(TemplateShape::Intent(i)));
        assert!(parse_vault(&s).is_err());
        assert!(IntentParams { delay: 0, ..i }.script().is_err());
    }

    #[test]
    fn malformed_shapes() {
        let mut s = vp().script().unwrap();
        // the second setId copy (op 30) differs: skeleton matches, fields do not
        let pos = s.windows(32).rposition(|w| w == [0x11; 32]).unwrap();
        s[pos] = 0x12;
        assert!(parse_vault(&s).is_err());
        assert_eq!(template_shape(&s), Some(TemplateShape::Malformed));
        assert_eq!(template_shape(&p2pkh_script(&[0; 20])), None);
        assert_eq!(template_shape(&[]), None);
    }

    #[test]
    fn bond_round_trip() {
        let key = [3u8; 33];
        for lt in [0, 1, 16, 17, 1300, 499_999_999, u32::MAX] {
            let r = bond_redeem(&key, lt);
            assert_eq!(parse_bond(&r).unwrap(), (key, lt));
        }
        let mut r = bond_redeem(&key, 1300);
        r.push(OP_DROP);
        assert!(parse_bond(&r).is_err());
        // locktime 5 written as a data push is not minimal
        let mut nm = vec![1, 5];
        nm.extend_from_slice(&bond_redeem(&key, 5)[1..]);
        assert!(parse_bond(&nm).is_err());
        assert_eq!(bond_spk(&key, 1300), p2sh_of(&bond_redeem(&key, 1300)));
    }

    #[test]
    fn selectors() {
        let sig = [0x1f; 65];
        let ss = selector_script_sig(&[&sig, &sig], SEL_UNLOCK).unwrap();
        let p = parse_selector(TemplateKind::Vault, &ss).unwrap();
        assert_eq!(p.selector, 1);
        assert_eq!(p.args, vec![sig.to_vec(), sig.to_vec()]);
        assert_eq!(
            parse_selector(TemplateKind::Vault, &[OP_4])
                .unwrap()
                .selector,
            4
        );
        assert!(parse_selector(TemplateKind::Intent, &[OP_4]).is_err());
        assert!(parse_selector(TemplateKind::Vault, &[1, 1]).is_err());
        assert!(parse_selector(TemplateKind::Vault, &[OP_DUP, OP_1]).is_err());
        assert!(selector_script_sig(&[], 5).is_err());
        assert!(selector_script_sig(&[], 0).is_err());
    }
}
