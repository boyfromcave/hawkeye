//! Set signatures (upgrade plan §15.2 step 4, §15.5) and the 65-byte recoverable compact
//! signature they use (`header ‖ r ‖ s`, header 31..34: Bitcoin `signmessage`'s compressed-key
//! format).
//!
//! Hawkeye signs on Ycash through the node wallet (plan §3.5), so [`sign_compact`] is here for
//! tests, simulations and evidence checks; [`recover_compact`] is what attribution (§4.5) uses.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::bytes::{Hash32, OutPoint, sha256d};
use crate::error::{Error, Result, array};
use crate::keys::{PubKey33, SecretKey, compress, uncompress};

/// The set-signature domain, 11 ASCII bytes.
pub const SETSIG_DOMAIN: &[u8; 11] = b"YcashSetSig";
/// The act domain, 11 ASCII bytes.
pub const ACT_DOMAIN: &[u8; 11] = b"YcashSetAct";
/// A recoverable compact signature's size.
pub const SIG_LEN: usize = 65;

/// The role a set signature is given in (`OP_CHECKSETSIG`'s `role` byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    /// Unlocking a vault into an intent (V selector 1).
    Unlock = 1,
    /// Cancelling an intent back into a vault (I selector 2).
    Cancel = 2,
}

impl Role {
    /// The role byte.
    pub fn byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Role {
    type Error = Error;
    fn try_from(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Unlock),
            2 => Ok(Self::Cancel),
            _ => Err(Error::Signature("role must be 1 or 2")),
        }
    }
}

/// `SHA256d("YcashSetSig" ‖ setId (32) ‖ role (1) ‖ prevout (36) ‖ sighash (32))`: the 32
/// digest bytes `CKey::SignCompact` signs. `role` is a raw byte so evidence can be recomputed
/// for any value seen on chain.
pub fn set_sig_msg(set_id: &Hash32, role: u8, prevout: &OutPoint, sighash: &Hash32) -> Hash32 {
    let mut m = Vec::with_capacity(11 + 32 + 1 + 36 + 32);
    m.extend_from_slice(SETSIG_DOMAIN);
    m.extend_from_slice(set_id);
    m.push(role);
    m.extend_from_slice(&prevout.to_bytes());
    m.extend_from_slice(sighash);
    sha256d(&m)
}

/// `SHA256d("YcashSetAct" ‖ P ‖ vin[0].prevout (36))` for an act payload `P` (§15.5).
pub fn act_msg(payload: &[u8], prevout: &OutPoint) -> Hash32 {
    let mut m = Vec::with_capacity(11 + payload.len() + 36);
    m.extend_from_slice(ACT_DOMAIN);
    m.extend_from_slice(payload);
    m.extend_from_slice(&prevout.to_bytes());
    sha256d(&m)
}

/// True if the big-endian 32-byte `s` is at most n/2.
pub fn is_low_s(s: &[u8; 32]) -> bool {
    // n/2 = 7fffffff ffffffff ffffffff ffffffff 5d576e73 57a4501d dfe92f46 681b20a0
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    *s <= HALF_N
}

/// Sign `msg` (32 bytes) with RFC 6979 and low S, returning `(r ‖ s, recid)` — byte-identical
/// to libsecp256k1's `secp256k1_ecdsa_sign_recoverable` with the default nonce.
pub(crate) fn sign_rec(key: &SecretKey, msg: &Hash32) -> Result<([u8; 64], RecoveryId)> {
    let (sig, recid) = key
        .signing_key()
        .sign_prehash_recoverable(msg)
        .map_err(|_| Error::Signature("signing failed"))?;
    Ok((sig.to_bytes().into(), recid))
}

/// `CKey::SignCompact`: 65 bytes `(31 + recid) ‖ r ‖ s`, low S.
pub fn sign_compact(key: &SecretKey, msg: &Hash32) -> Result<[u8; 65]> {
    let (rs, recid) = sign_rec(key, msg)?;
    let mut out = [0u8; 65];
    out[0] = 31 + recid.to_byte();
    out[1..].copy_from_slice(&rs);
    Ok(out)
}

fn split(sig: &[u8]) -> Result<(u8, [u8; 32], [u8; 32])> {
    let sig: [u8; 65] = array("signature", sig)?;
    let r: [u8; 32] = sig[1..33].try_into().expect("32");
    let s: [u8; 32] = sig[33..].try_into().expect("32");
    Ok((sig[0], r, s))
}

fn recover_key(r: &[u8; 32], s: &[u8; 32], recid: u8, msg: &Hash32) -> Result<VerifyingKey> {
    let sig =
        Signature::from_scalars(*r, *s).map_err(|_| Error::Signature("r or s out of range"))?;
    // Recovery verifies with the recovered key, which (k256) refuses a high S: normalise first;
    // negating s negates R, so the y-parity bit flips and the key is the same.
    let (sig, recid) = match sig.normalize_s() {
        Some(low) => (low, recid ^ 1),
        None => (sig, recid),
    };
    let recid = RecoveryId::from_byte(recid).ok_or(Error::Signature("recovery id"))?;
    VerifyingKey::recover_from_prehash(msg, &sig, recid)
        .map_err(|_| Error::Signature("does not recover"))
}

/// The set-signature rule (§15.2 step 3): a 65-byte signature with header 31..34 and low S that
/// recovers over `msg`; the compressed key it recovers to.
pub fn recover_compact(sig: &[u8], msg: &Hash32) -> Result<PubKey33> {
    let (header, r, s) = split(sig)?;
    if !(31..=34).contains(&header) {
        return Err(Error::Signature("header not 31..34"));
    }
    if !is_low_s(&s) {
        return Err(Error::Signature("high S"));
    }
    Ok(compress(&recover_key(&r, &s, header - 31, msg)?))
}

/// `CPubKey::RecoverCompact`: any header and any S; `recid = (header − 27) & 3`, and the key
/// comes back compressed (33 bytes) when `(header − 27) & 4`, else uncompressed (65 bytes).
/// For evidence and vector checks only — consensus uses [`recover_compact`].
pub fn recover_compact_lenient(sig: &[u8], msg: &Hash32) -> Result<Vec<u8>> {
    let (header, r, s) = split(sig)?;
    let h = header.wrapping_sub(27);
    let key = recover_key(&r, &s, h & 3, msg)?;
    Ok(if h & 4 != 0 {
        compress(&key).to_vec()
    } else {
        uncompress(&key).to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_bytes() {
        assert_eq!(Role::try_from(1).unwrap(), Role::Unlock);
        assert_eq!(Role::try_from(2).unwrap().byte(), 2);
        assert!(Role::try_from(0).is_err());
        assert!(Role::try_from(3).is_err());
    }

    #[test]
    fn sign_recover_round_trip() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        for i in 0u8..16 {
            let msg = crate::bytes::sha256(&[i]);
            let sig = sign_compact(&key, &msg).unwrap();
            assert!((31..=32).contains(&sig[0]));
            assert!(is_low_s(sig[33..].try_into().unwrap()));
            assert_eq!(recover_compact(&sig, &msg).unwrap(), key.public_key());
            // a different message recovers a different key or nothing
            let other = crate::bytes::sha256(&[i, i]);
            assert_ne!(recover_compact(&sig, &other).ok(), Some(key.public_key()));
            assert_eq!(
                recover_compact_lenient(&sig, &msg).unwrap(),
                key.public_key().to_vec()
            );
        }
        assert!(recover_compact(&[0x1f; 64], &[0; 32]).is_err());
    }

    #[test]
    fn low_s_boundary() {
        let mut half = [0xffu8; 32];
        half[0] = 0x7f;
        half[16..].copy_from_slice(&hex::decode("5d576e7357a4501ddfe92f46681b20a0").unwrap());
        assert!(is_low_s(&half));
        half[31] += 1;
        assert!(!is_low_s(&half));
        assert!(is_low_s(&[0; 32]));
    }
}
