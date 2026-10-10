//! Post-quantum vault owners (quantum spec §1.1, §4, §6.2): the owner of every vault — bridge
//! vaults included — is a post-quantum key named by its key id `scheme ‖ SHA256(scheme ‖ pk)`
//! (the node's `CPQKeyID`, the RPCs' `pqkeyid`). Hawkeye never holds or uses the key: the
//! depositor's node draws it (`vault_getnewowner`) and signs the owner spends
//! (`vault_ownerspend`). So this module needs no post-quantum signature code, only the id.

use crate::bytes::{Hash32, from_hex_array, sha256};
use crate::error::{Error, Result};

/// SLH-DSA-SHA2-128s (FIPS 205, pure mode, empty context): the bridge's owner scheme.
pub const SCHEME_SLH_DSA_SHA2_128S: u8 = 0x01;
/// FN-DSA-512 (padded Falcon); a valid template owner, gated on the node by `pqFalconHeight`.
pub const SCHEME_FN_DSA_512: u8 = 0x02;

/// A scheme in the node's registry (`pq::IsKnownScheme`): 1 or 2. Whether it is active is the
/// node's business; Hawkeye's lock policy accepts scheme 1 only (plan §4.1).
pub fn is_known_scheme(scheme: u8) -> bool {
    scheme == SCHEME_SLH_DSA_SHA2_128S || scheme == SCHEME_FN_DSA_512
}

/// A post-quantum owner: the scheme and the 32-byte key hash exactly as the template pushes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PqKeyId {
    /// The scheme byte (1 or 2).
    pub scheme: u8,
    /// `SHA256(scheme ‖ pk)`, in the order the V and I push it.
    pub hash: Hash32,
}

impl PqKeyId {
    /// An id from its parts; fails for a scheme outside the registry.
    pub fn new(scheme: u8, hash: Hash32) -> Result<Self> {
        if !is_known_scheme(scheme) {
            return Err(Error::Key("unknown post-quantum scheme"));
        }
        Ok(Self { scheme, hash })
    }

    /// The id of public key `pk` under `scheme`: `SHA256(scheme ‖ pk)`.
    pub fn of_public_key(scheme: u8, pk: &[u8]) -> Result<Self> {
        let mut b = Vec::with_capacity(1 + pk.len());
        b.push(scheme);
        b.extend_from_slice(pk);
        Self::new(scheme, sha256(&b))
    }

    /// The 33 bytes `scheme ‖ hash` (the `pqkeyid` and the PQ address payload).
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut b = [0u8; 33];
        b[0] = self.scheme;
        b[1..].copy_from_slice(&self.hash);
        b
    }

    /// Parse `scheme ‖ hash` (33 bytes, a registered scheme).
    pub fn from_bytes(b: &[u8; 33]) -> Result<Self> {
        let hash: Hash32 = b[1..].try_into().expect("32 bytes");
        Self::new(b[0], hash)
    }

    /// The RPC form: 66 hex digits.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Parse the RPC form (66 hex digits, scheme `01` or `02`).
    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&from_hex_array::<33>("pqkeyid", s)?)
    }
}

impl core::fmt::Display for PqKeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects() {
        let id = PqKeyId::new(1, [0xab; 32]).unwrap();
        assert_eq!(id.to_bytes()[0], 1);
        assert_eq!(PqKeyId::from_hex(&id.to_hex()).unwrap(), id);
        assert_eq!(id.to_string().len(), 66);
        assert!(PqKeyId::new(0, [0; 32]).is_err());
        assert!(PqKeyId::new(3, [0; 32]).is_err());
        // a compressed secp256k1 key with prefix 03 is no owner id (02… would be a Falcon id:
        // the RPC type `pqkeyid` is new for that reason, quantum spec §6.2)
        assert!(PqKeyId::from_hex(&format!("03{}", "11".repeat(32))).is_err());
        assert!(PqKeyId::from_hex("01").is_err());
        assert_eq!(
            PqKeyId::of_public_key(1, &[7; 32]).unwrap().hash,
            sha256(&[&[1u8][..], &[7; 32]].concat())
        );
    }
}
