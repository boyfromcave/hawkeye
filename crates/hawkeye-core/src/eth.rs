//! Ethereum keys and signatures: the guardian address of a member key, 65-byte `r ‖ s ‖ v`
//! signatures over a 32-byte digest (what OpenZeppelin's `ECDSA.recover` accepts: v 27/28, low
//! S), and the contract's ascending-signer order (plan §4.4).

use k256::ecdsa::VerifyingKey;

use crate::bytes::{Hash32, keccak256};
use crate::error::{Error, Result, array};
use crate::keys::{SecretKey, parse_pubkey, uncompress};
use crate::setsig::{is_low_s, sign_rec};

/// A 20-byte Ethereum address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    /// The zero address.
    pub const ZERO: Self = Self([0; 20]);

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Parse `0x`-prefixed (or bare) hex. All-lowercase and all-uppercase are accepted as is;
    /// mixed case must be a valid EIP-55 checksum.
    pub fn parse(s: &str) -> Result<Self> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        let a = Self(crate::bytes::from_hex_array("address", body)?);
        let mixed = body.chars().any(|c| c.is_ascii_uppercase())
            && body.chars().any(|c| c.is_ascii_lowercase());
        if mixed && a.to_checksum()[2..] != *body {
            return Err(Error::Hex("bad EIP-55 checksum"));
        }
        Ok(a)
    }

    /// The EIP-55 mixed-case checksum form, `0x`-prefixed.
    pub fn to_checksum(&self) -> String {
        let lower = hex::encode(self.0);
        let h = keccak256(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower.chars().enumerate() {
            let nibble = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
        out
    }

    /// The ABI word of the address: 12 zero bytes, then the address.
    pub fn to_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.0);
        w
    }
}

impl core::fmt::Display for EthAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

impl core::str::FromStr for EthAddress {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

pub(crate) fn address_of(key: &VerifyingKey) -> EthAddress {
    let full = uncompress(key);
    let h = keccak256(&full[1..]);
    EthAddress(h[12..].try_into().expect("20 bytes"))
}

/// `keccak256(uncompressed pubkey without the 04 prefix)[12..]` of a SEC1 key, compressed (a
/// Ycash member key) or uncompressed.
pub fn address_from_pubkey(pubkey: &[u8]) -> Result<EthAddress> {
    Ok(address_of(&parse_pubkey(pubkey)?))
}

/// Sign a 32-byte digest (an EIP-712 digest): `r ‖ s ‖ v`, low S, v = 27 + y-parity.
pub fn sign_digest(key: &SecretKey, digest: &Hash32) -> Result<[u8; 65]> {
    let (rs, recid) = sign_rec(key, digest)?;
    if recid.is_x_reduced() {
        // R.x ≥ n: probability ~2^-128 and not expressible in v.
        return Err(Error::Signature("x-reduced recovery id"));
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&rs);
    out[64] = 27 + u8::from(recid.is_y_odd());
    Ok(out)
}

/// The signer of a 65-byte `r ‖ s ‖ v` signature over `digest`, under OpenZeppelin `ECDSA`'s
/// rules: v ∈ {27, 28}, 0 < r, s < n, s ≤ n/2.
pub fn recover_address(digest: &Hash32, sig: &[u8]) -> Result<EthAddress> {
    let sig: [u8; 65] = array("signature", sig)?;
    let v = sig[64];
    if v != 27 && v != 28 {
        return Err(Error::Signature("v not 27 or 28"));
    }
    let s: [u8; 32] = sig[32..64].try_into().expect("32");
    if !is_low_s(&s) {
        return Err(Error::Signature("high S"));
    }
    let mut compact = [0u8; 65];
    compact[0] = 31 + (v - 27);
    compact[1..].copy_from_slice(&sig[..64]);
    let key = crate::setsig::recover_compact(&compact, digest)?;
    address_from_pubkey(&key)
}

/// Order signatures for the contract's `sigs[]`: by recovered signer, strictly ascending
/// (`_checkThreshold`'s distinctness rule). Fails if any signature does not recover or two
/// recover to the same signer.
pub fn sort_signatures(digest: &Hash32, sigs: &[[u8; 65]]) -> Result<Vec<[u8; 65]>> {
    let mut keyed = sigs
        .iter()
        .map(|s| Ok((recover_address(digest, s)?, *s)))
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by_key(|k| k.0);
    if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::Signature("two signatures by one signer"));
    }
    Ok(keyed.into_iter().map(|(_, s)| s).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_addresses() {
        // Foundry / Hardhat default account 0 (also checked against `cast wallet address`).
        let k =
            SecretKey::from_hex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        assert_eq!(
            k.eth_address().to_checksum(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            address_from_pubkey(&k.public_key()).unwrap(),
            k.eth_address()
        );
        // secret 1: the generator
        let one = SecretKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .unwrap();
        assert_eq!(
            one.eth_address().to_checksum(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn address_parsing() {
        let s = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
        let a = EthAddress::parse(s).unwrap();
        assert_eq!(a.to_string(), s);
        assert_eq!(EthAddress::parse(&s.to_lowercase()).unwrap(), a);
        assert_eq!(EthAddress::parse(&s[2..].to_uppercase()).unwrap(), a);
        assert!(EthAddress::parse("0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266").is_err());
        assert!(EthAddress::parse("0x1234").is_err());
        assert_eq!(&a.to_word()[..12], &[0; 12]);
    }

    #[test]
    fn sign_recover_sort() {
        let digest = crate::bytes::keccak256(b"digest");
        let keys: Vec<SecretKey> = (1u8..=5)
            .map(|i| SecretKey::from_bytes(&[i; 32]).unwrap())
            .collect();
        let sigs: Vec<[u8; 65]> = keys
            .iter()
            .map(|k| sign_digest(k, &digest).unwrap())
            .collect();
        for (k, s) in keys.iter().zip(&sigs) {
            assert!(s[64] == 27 || s[64] == 28);
            assert_eq!(recover_address(&digest, s).unwrap(), k.eth_address());
        }
        let sorted = sort_signatures(&digest, &sigs).unwrap();
        let addrs: Vec<EthAddress> = sorted
            .iter()
            .map(|s| recover_address(&digest, s).unwrap())
            .collect();
        assert!(addrs.windows(2).all(|w| w[0] < w[1]));
        assert!(sort_signatures(&digest, &[sigs[0], sigs[0]]).is_err());

        let mut bad_v = sigs[0];
        bad_v[64] = 1;
        assert!(recover_address(&digest, &bad_v).is_err());
        let mut high = sigs[0];
        high[32] = 0xff;
        assert!(recover_address(&digest, &high).is_err());
        assert!(recover_address(&digest, &sigs[0][..64]).is_err());
    }
}
