//! secp256k1 keys: the member key (one key on both chains, plan §3.5).

use k256::ecdsa::{SigningKey, VerifyingKey};

use crate::error::{Error, Result};

/// A compressed public key (33 bytes, prefix 02/03).
pub type PubKey33 = [u8; 33];

/// A secp256k1 secret key. `Debug` never prints the scalar.
#[derive(Clone)]
pub struct SecretKey(SigningKey);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey")
            .field(&hex::encode(self.public_key()))
            .finish()
    }
}

impl SecretKey {
    /// A key from its 32 big-endian bytes; fails for 0 and values ≥ n.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self> {
        SigningKey::from_slice(secret)
            .map(Self)
            .map_err(|_| Error::Key("secret out of range"))
    }

    /// A key from 64 hex digits.
    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&crate::bytes::from_hex_array("secret key", s)?)
    }

    /// The 32 secret bytes (for keystores; handle with care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// The compressed public key: the Ycash set member key.
    pub fn public_key(&self) -> PubKey33 {
        compress(self.0.verifying_key())
    }

    /// The Ethereum guardian address of this key.
    pub fn eth_address(&self) -> crate::eth::EthAddress {
        crate::eth::address_of(self.0.verifying_key())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

/// 33 bytes with prefix 02/03, **no curve check** — the upgrade plan's "compressed" for
/// template and act keys (`VAULT_VECTORS.md` A-2: an off-curve key parses; it can never sign).
pub fn is_compressed_pubkey(b: &[u8]) -> bool {
    b.len() == 33 && (b[0] == 2 || b[0] == 3)
}

/// A SEC1 public key (33-byte compressed or 65-byte uncompressed) that lies on the curve.
pub fn parse_pubkey(b: &[u8]) -> Result<VerifyingKey> {
    if !(is_compressed_pubkey(b) || (b.len() == 65 && b[0] == 4)) {
        return Err(Error::Key("not a SEC1 public key"));
    }
    VerifyingKey::from_sec1_bytes(b).map_err(|_| Error::Key("not on the curve"))
}

/// The compressed encoding of a public key.
pub fn compress(key: &VerifyingKey) -> PubKey33 {
    let p = key.to_encoded_point(true);
    p.as_bytes()
        .try_into()
        .expect("compressed point is 33 bytes")
}

/// The uncompressed encoding (`04 ‖ x ‖ y`) of a public key.
pub fn uncompress(key: &VerifyingKey) -> [u8; 65] {
    let p = key.to_encoded_point(false);
    p.as_bytes()
        .try_into()
        .expect("uncompressed point is 65 bytes")
}

/// Sort member keys in the set's canonical order (ascending bytes of the compressed key) and
/// drop duplicates; the leader schedule (plan §5.2) indexes this order.
pub fn sort_members(keys: &mut Vec<PubKey33>) {
    keys.sort_unstable();
    keys.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trip() {
        let k =
            SecretKey::from_hex("3d8a317c3648b14aa03ba7742ebdcd286285f6972d6a100cb316042ad9e51a85")
                .unwrap();
        assert_eq!(
            hex::encode(k.public_key()),
            "03eca519f9711ff449df0cb37815ede9e8b0771186312e12e928ea1b8845996837"
        );
        assert_eq!(
            SecretKey::from_bytes(&k.to_bytes()).unwrap().public_key(),
            k.public_key()
        );
        let vk = parse_pubkey(&k.public_key()).unwrap();
        let full = uncompress(&vk);
        assert_eq!(compress(&parse_pubkey(&full).unwrap()), k.public_key());
        assert!(format!("{k:?}").contains("03eca519"));
        assert!(!format!("{k:?}").contains("3d8a317c"));
    }

    #[test]
    fn bad_keys() {
        assert!(SecretKey::from_bytes(&[0; 32]).is_err());
        assert!(SecretKey::from_bytes(&[0xff; 32]).is_err());
        assert!(SecretKey::from_hex("00").is_err());
        let mut off = [0u8; 33];
        off[0] = 2;
        off[1..].copy_from_slice(&[0xff; 32]); // x >= p: not on the curve
        assert!(is_compressed_pubkey(&off));
        assert!(parse_pubkey(&off).is_err());
        assert!(!is_compressed_pubkey(&[4; 33]));
        assert!(parse_pubkey(&[2; 32]).is_err());
    }

    #[test]
    fn member_order() {
        let mut v = vec![[3u8; 33], [2u8; 33], [3u8; 33]];
        sort_members(&mut v);
        assert_eq!(v, vec![[2u8; 33], [3u8; 33]]);
    }
}
