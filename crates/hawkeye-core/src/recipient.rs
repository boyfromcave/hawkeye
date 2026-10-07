//! `ycashRecipient` — the `bytes32` a burner passes to `WyecBridge.burn` (plan §4.2, HK-5):
//!
//! ```text
//! byte 0      version = 0x01
//! byte 1      kind    = 0x00 P2PKH | 0x01 P2SH
//! bytes 2..11 zero
//! bytes 12..31 hash160
//! ```
//!
//! Transparent recipients only. A burn whose recipient does not decode is **orphaned** (§3.4).

use crate::bytes::{Hash32, sha256};
use crate::error::{Error, Result, array};
use crate::script::{p2pkh_script, p2sh_script, parse_p2pkh, parse_p2sh};

/// The only recipient encoding version.
pub const RECIPIENT_VERSION: u8 = 0x01;

/// The kind of a transparent recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecipientKind {
    /// Pay to public key hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
}

impl RecipientKind {
    /// The §4.2 kind byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::P2pkh => 0x00,
            Self::P2sh => 0x01,
        }
    }
}

/// A transparent Ycash recipient: kind and hash160.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct YcashRecipient {
    /// P2PKH or P2SH.
    pub kind: RecipientKind,
    /// The 20-byte hash.
    pub hash: [u8; 20],
}

impl YcashRecipient {
    /// A P2PKH recipient.
    pub fn p2pkh(hash: [u8; 20]) -> Self {
        Self {
            kind: RecipientKind::P2pkh,
            hash,
        }
    }

    /// A P2SH recipient.
    pub fn p2sh(hash: [u8; 20]) -> Self {
        Self {
            kind: RecipientKind::P2sh,
            hash,
        }
    }

    /// The §4.2 `bytes32`.
    pub fn to_bytes32(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = RECIPIENT_VERSION;
        b[1] = self.kind.byte();
        b[12..].copy_from_slice(&self.hash);
        b
    }

    /// Strictly decode a §4.2 `bytes32` (version 1, kind 0 or 1, bytes 2..11 zero).
    pub fn from_bytes32(b: &[u8]) -> Result<Self> {
        let b: [u8; 32] = array("ycashRecipient", b)?;
        if b[0] != RECIPIENT_VERSION {
            return Err(Error::Recipient("unknown version"));
        }
        let kind = match b[1] {
            0x00 => RecipientKind::P2pkh,
            0x01 => RecipientKind::P2sh,
            _ => return Err(Error::Recipient("unknown kind")),
        };
        if b[2..12].iter().any(|&x| x != 0) {
            return Err(Error::Recipient("non-zero padding"));
        }
        Ok(Self {
            kind,
            hash: b[12..].try_into().expect("20 bytes"),
        })
    }

    /// The recipient scriptPubKey.
    pub fn script(&self) -> Vec<u8> {
        match self.kind {
            RecipientKind::P2pkh => p2pkh_script(&self.hash),
            RecipientKind::P2sh => p2sh_script(&self.hash),
        }
    }

    /// `SHA256(script)`: the intent's `recipientHash`.
    pub fn recipient_hash(&self) -> Hash32 {
        sha256(&self.script())
    }

    /// The recipient of an exact P2PKH or P2SH scriptPubKey.
    pub fn from_script(spk: &[u8]) -> Result<Self> {
        if let Some(h) = parse_p2pkh(spk) {
            Ok(Self::p2pkh(h))
        } else if let Some(h) = parse_p2sh(spk) {
            Ok(Self::p2sh(h))
        } else {
            Err(Error::Recipient("not a P2PKH or P2SH script"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for r in [
            YcashRecipient::p2pkh([0xab; 20]),
            YcashRecipient::p2sh([0x01; 20]),
        ] {
            let b = r.to_bytes32();
            assert_eq!(YcashRecipient::from_bytes32(&b).unwrap(), r);
            assert_eq!(YcashRecipient::from_script(&r.script()).unwrap(), r);
            assert_eq!(r.recipient_hash(), sha256(&r.script()));
        }
        let b = YcashRecipient::p2pkh([0xab; 20]).to_bytes32();
        assert_eq!(
            hex::encode(b),
            "010000000000000000000000abababababababababababababababababababab"
        );
        assert_eq!(
            hex::encode(YcashRecipient::p2sh([0xab; 20]).to_bytes32())[..4],
            *"0101"
        );
    }

    #[test]
    fn rejects() {
        let good = YcashRecipient::p2pkh([0xab; 20]).to_bytes32();
        let mut b = good;
        b[0] = 0;
        assert_eq!(
            YcashRecipient::from_bytes32(&b),
            Err(Error::Recipient("unknown version"))
        );
        let mut b = good;
        b[1] = 2;
        assert!(YcashRecipient::from_bytes32(&b).is_err());
        let mut b = good;
        b[11] = 1;
        assert!(YcashRecipient::from_bytes32(&b).is_err());
        assert!(YcashRecipient::from_bytes32(&good[..31]).is_err());
        // an Ethereum-style left-padded address is not a recipient
        let mut eth = [0u8; 32];
        eth[12..].copy_from_slice(&[0x11; 20]);
        assert!(YcashRecipient::from_bytes32(&eth).is_err());
        assert!(YcashRecipient::from_script(&[0x6a]).is_err());
    }
}
