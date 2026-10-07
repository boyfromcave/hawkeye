//! Typed hex values of the RPC interface.
//!
//! Byte order (plan §4, upgrade finding (59)): the node prints a `uint256` (txid, set id, block
//! hash, `statehash`) with `GetHex()`, i.e. **reversed**; [`Hash256`] keeps the internal bytes and
//! converts at the (de)serialization boundary. Raw 32-byte values printed with `HexStr` (sighash,
//! `recipienthash`, `vaulthash`) are [`Bytes32`], kept in the printed order.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A hex value that does not decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid {what}: {text:?}")]
pub struct HexError {
    pub what: &'static str,
    pub text: String,
}

fn decode_fixed<const N: usize>(what: &'static str, s: &str) -> Result<[u8; N], HexError> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| HexError {
        what,
        text: s.to_owned(),
    })?;
    Ok(out)
}

macro_rules! string_serde {
    ($t:ty, $what:literal) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = $t;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($what)
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<$t, E> {
                        v.parse().map_err(E::custom)
                    }
                }
                d.deserialize_str(V)
            }
        }
    };
}

/// A `uint256` the node prints reversed (`GetHex`): txids, set ids, block hashes, `statehash`.
/// The field holds the **internal** byte order (what hashes and prevouts commit to).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

/// A transaction id (display order on the wire, internal order in memory).
pub type Txid = Hash256;
/// A signer set id: the txid of its `SET_CREATE`.
pub type SetId = Hash256;
/// A block hash.
pub type BlockHash = Hash256;

impl Hash256 {
    pub const fn from_internal(b: [u8; 32]) -> Self {
        Hash256(b)
    }

    /// From the 32 bytes in display (RPC) order.
    pub fn from_display(mut b: [u8; 32]) -> Self {
        b.reverse();
        Hash256(b)
    }

    pub const fn internal(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn display_bytes(&self) -> [u8; 32] {
        let mut b = self.0;
        b.reverse();
        b
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.display_bytes()))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({self})")
    }
}

impl FromStr for Hash256 {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, HexError> {
        decode_fixed::<32>("256-bit hash", s).map(Hash256::from_display)
    }
}
string_serde!(Hash256, "a 64-digit hex uint256 in RPC (reversed) order");

/// 32 raw bytes printed in order (`HexStr`): sighashes, `recipienthash`, `vaulthash`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes32(pub [u8; 32]);

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes32({self})")
    }
}

impl FromStr for Bytes32 {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, HexError> {
        decode_fixed::<32>("32-byte hex", s).map(Bytes32)
    }
}
string_serde!(Bytes32, "64 hex digits");

/// A 33-byte compressed secp256k1 public key (`key` in the contract).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub [u8; 33]);

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PubKey({self})")
    }
}

impl FromStr for PubKey {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, HexError> {
        let k = decode_fixed::<33>("compressed public key", s)?;
        if k[0] != 2 && k[0] != 3 {
            return Err(HexError {
                what: "compressed public key",
                text: s.to_owned(),
            });
        }
        Ok(PubKey(k))
    }
}
string_serde!(PubKey, "a 66-digit hex compressed public key");

/// Arbitrary hex bytes (`hex` in the contract): transactions, scripts, signatures, tags.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(v: Vec<u8>) -> Self {
        HexBytes(v)
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 48 {
            write!(f, "HexBytes({self})")
        } else {
            write!(
                f,
                "HexBytes({}…, {} bytes)",
                hex::encode(&self.0[..32]),
                self.0.len()
            )
        }
    }
}

impl FromStr for HexBytes {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, HexError> {
        hex::decode(s).map(HexBytes).map_err(|_| HexError {
            what: "hex",
            text: s.to_owned(),
        })
    }
}
string_serde!(HexBytes, "a hex string");

/// A transaction output reference: `"txid:n"` in results; parameters also accept
/// `{"txid", "vout"}` (deserialization takes both, serialization writes the string).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub const fn new(txid: Txid, vout: u32) -> Self {
        OutPoint { txid, vout }
    }

    /// The 36-byte serialization (`txid internal ‖ n u32 LE`), as set-signature messages and
    /// `lockId` use it.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[..32].copy_from_slice(&self.txid.0);
        b[32..].copy_from_slice(&self.vout.to_le_bytes());
        b
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutPoint({self})")
    }
}

impl FromStr for OutPoint {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, HexError> {
        let bad = || HexError {
            what: "outpoint \"txid:n\"",
            text: s.to_owned(),
        };
        let (t, n) = s.rsplit_once(':').ok_or_else(bad)?;
        Ok(OutPoint {
            txid: t.parse().map_err(|_| bad())?,
            vout: n.parse().map_err(|_| bad())?,
        })
    }
}

impl Serialize for OutPoint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for OutPoint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            S(String),
            O { txid: Hash256, vout: u32 },
        }
        match Form::deserialize(d)? {
            Form::S(s) => s.parse().map_err(de::Error::custom),
            Form::O { txid, vout } => Ok(OutPoint { txid, vout }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_byte_order() {
        let h: Hash256 = "00000000000000000000000000000000000000000000000000000000000000ff"
            .parse()
            .unwrap();
        assert_eq!(
            h.0[0], 0xff,
            "internal order is the reverse of the printed order"
        );
        assert_eq!(
            h.to_string(),
            "00000000000000000000000000000000000000000000000000000000000000ff"
        );
        let b: Bytes32 = "ff00000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        assert_eq!(b.0[0], 0xff);
    }

    #[test]
    fn outpoints() {
        let t = "6d5b7a31".repeat(8);
        let o: OutPoint = format!("{t}:7").parse().unwrap();
        assert_eq!(o.vout, 7);
        assert_eq!(o.to_string(), format!("{t}:7"));
        let j: OutPoint = serde_json::from_str(&format!(r#"{{"txid":"{t}","vout":3}}"#)).unwrap();
        assert_eq!(j.vout, 3);
        assert_eq!(serde_json::to_string(&j).unwrap(), format!("\"{t}:3\""));
        assert!("nope".parse::<OutPoint>().is_err());
        assert!(format!("{t}:-1").parse::<OutPoint>().is_err());
        let b = o.to_bytes();
        assert_eq!(&b[32..], &[7, 0, 0, 0]);
        assert_eq!(&b[..32], o.txid.internal());
    }

    #[test]
    fn keys() {
        let k = format!("02{}", "11".repeat(32));
        assert!(k.parse::<PubKey>().is_ok());
        assert!(format!("04{}", "11".repeat(32)).parse::<PubKey>().is_err());
        assert!("02".parse::<PubKey>().is_err());
    }
}
