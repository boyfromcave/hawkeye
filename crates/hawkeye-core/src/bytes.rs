//! Byte-order helpers and hashes.
//!
//! Every Ycash hash and outpoint inside Hawkeye is in **internal byte order**
//! (`uint256::begin()..end()`); the node's RPCs print txids reversed ("display order"). Convert
//! once, at the RPC boundary, with [`txid_from_display`] / [`txid_to_display`] (plan §4,
//! upgrade finding (59)).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::{Error, Result, array};

/// A 32-byte hash or id in internal byte order.
pub type Hash32 = [u8; 32];

/// SHA-256.
pub fn sha256(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

/// SHA-256 applied twice (Bitcoin's `Hash` / `SHA256d`).
pub fn sha256d(data: &[u8]) -> Hash32 {
    sha256(&sha256(data))
}

/// RIPEMD-160 of SHA-256 (Bitcoin's `Hash160`).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// Keccak-256 (Ethereum's hash, not NIST SHA3-256).
pub fn keccak256(data: &[u8]) -> Hash32 {
    Keccak256::digest(data).into()
}

/// Decode lowercase or uppercase hex, any length.
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| Error::Hex("not hex"))
}

/// Decode hex of exactly `N` bytes (an optional `0x` prefix is accepted).
pub fn from_hex_array<const N: usize>(what: &'static str, s: &str) -> Result<[u8; N]> {
    array(what, &from_hex(s)?)
}

/// The 32 internal bytes of a txid printed by an RPC (display order, 64 hex digits).
pub fn txid_from_display(display: &str) -> Result<Hash32> {
    let mut b: Hash32 = from_hex_array("txid", display)?;
    b.reverse();
    Ok(b)
}

/// The RPC (display-order) hex of a txid held in internal byte order.
pub fn txid_to_display(internal: &Hash32) -> String {
    let mut b = *internal;
    b.reverse();
    hex::encode(b)
}

/// A transaction output reference, the txid in internal byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    /// The txid, internal byte order.
    pub txid: Hash32,
    /// The output index.
    pub vout: u32,
}

impl OutPoint {
    /// Serialised length: 32-byte hash, u32 LE index.
    pub const LEN: usize = 36;

    /// An outpoint from an internal-order txid.
    pub fn new(txid: Hash32, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// An outpoint from an RPC (display-order) txid.
    pub fn from_display(txid: &str, vout: u32) -> Result<Self> {
        Ok(Self::new(txid_from_display(txid)?, vout))
    }

    /// The `COutPoint` serialisation: txid (internal) ‖ vout (u32 LE).
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.txid);
        out[32..].copy_from_slice(&self.vout.to_le_bytes());
        out
    }

    /// Parse the 36-byte `COutPoint` serialisation.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let b: [u8; 36] = array("outpoint", b)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&b[..32]);
        Ok(Self::new(
            txid,
            u32::from_le_bytes([b[32], b[33], b[34], b[35]]),
        ))
    }

    /// The txid in RPC display order.
    pub fn txid_display(&self) -> String {
        txid_to_display(&self.txid)
    }
}

impl core::fmt::Display for OutPoint {
    /// `txid:vout` with the txid in display order (the RPCs' `outpoint` strings).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.txid_display(), self.vout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_answers() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256d(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
        // hash160 of the secp256k1 generator's compressed encoding (Bitcoin's key 1).
        let g =
            from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(
            hex::encode(hash160(&g)),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn txid_round_trip() {
        let display = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let internal = txid_from_display(display).unwrap();
        assert_eq!(internal[0], 0xff);
        assert_eq!(internal[31], 0x00);
        assert_eq!(txid_to_display(&internal), display);
        assert!(txid_from_display("00").is_err());
        assert!(txid_from_display("zz").is_err());
    }

    #[test]
    fn outpoint_round_trip() {
        let display = "596ab86d7298e5870a59c1d76aa2f618f9c0f20fbdc31961537393589dd79abc";
        let op = OutPoint::from_display(display, 3).unwrap();
        let b = op.to_bytes();
        assert_eq!(
            hex::encode(b),
            "bc9ad79d589373536119c3bd0ff2c0f918f6a26ad7c1590a87e598726db86a5903000000"
        );
        assert_eq!(OutPoint::from_bytes(&b).unwrap(), op);
        assert_eq!(op.to_string(), format!("{display}:3"));
        assert!(OutPoint::from_bytes(&b[..35]).is_err());
    }
}
