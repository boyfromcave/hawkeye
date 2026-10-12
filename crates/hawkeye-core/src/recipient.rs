//! `ycashRecipient` — the bytes a burner passes to `WyecBridge.burn(uint256, bytes)` and
//! `wyec-near::burn` (plan §4.2 revision 2, HK-5; owner decision 2026-10-11, Q-7):
//!
//! ```text
//! byte 0      version = 0x02
//! byte 1      kind    = 0x00 P2PKH | 0x01 P2SH | 0x02 PQPKH
//! bytes 2..   kind 0x00 / 0x01: hash160 (20 bytes)                       → 22 bytes in all
//!             kind 0x02:        scheme (1 byte: 0x01 SLH-DSA-SHA2-128s |
//!                               0x02 FN-DSA-512) ‖ keyHash (32 bytes)      → 35 bytes in all
//! ```
//!
//! The recipient script is P2PKH, P2SH or the node's `TX_PQPKH` `<keyHash:32> OP_1|OP_2
//! OP_CHECKPQSIG` (`20 <hash> 51|52 c2`, 35 bytes: the scheme as a script number, never the
//! data push `01 01` — quantum spec F-1; ycash-dd `src/script/standard.cpp:338` at `d41026209`,
//! `GetScriptForPQKey`); `recipientHash = SHA256(script)` is what the intent commits and
//! `vault_release` takes the script, so the node needs no change. Both contracts validate the
//! field strictly; Hawkeye decodes it again ([`YcashRecipient::from_bytes`]) and a burn whose
//! recipient does not decode is **orphaned** (§3.4). Transparent or `TX_PQPKH` recipients only,
//! never shielded.
//!
//! Version 1 (the former `bytes32`: `0x01`, kind, 10 zero bytes, hash160) is retired: no
//! deployment carries it, [`YcashRecipient::from_bytes`] refuses it, and a ledger written under
//! it migrates its rows to the 22-byte form (`hawkeye-store` schema v5).
//!
//! Golden vectors: `tests/data/recipient_vectors.json` (`tests/recipient_vectors.rs`).

use crate::bytes::{Hash32, sha256};
use crate::error::{Error, Result};
use crate::pq::{PqKeyId, is_known_scheme};
use crate::script::{
    OP_1, OP_CHECKPQSIG, p2pkh_script, p2sh_script, parse_p2pkh, parse_p2sh, push_int_to,
};

/// The only recipient encoding version (version 1, the `bytes32`, is retired).
pub const RECIPIENT_VERSION: u8 = 0x02;

/// The kind byte of a P2PKH recipient.
pub const KIND_P2PKH: u8 = 0x00;
/// The kind byte of a P2SH recipient.
pub const KIND_P2SH: u8 = 0x01;
/// The kind byte of a `TX_PQPKH` recipient.
pub const KIND_PQPKH: u8 = 0x02;

/// The length of a kind-0 / kind-1 recipient: version, kind, hash160.
pub const LEN_TRANSPARENT: usize = 22;
/// The length of a kind-2 recipient: version, kind, scheme, keyHash.
pub const LEN_PQPKH: usize = 35;

/// The length of the `TX_PQPKH` script: `20 <hash:32> OP_n OP_CHECKPQSIG`.
pub const PQPKH_SCRIPT_LEN: usize = 35;

/// The kind of a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecipientKind {
    /// Pay to public key hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to a post-quantum key hash (`TX_PQPKH`, quantum plan D-Q-20).
    Pqpkh,
}

impl RecipientKind {
    /// The §4.2 kind byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::P2pkh => KIND_P2PKH,
            Self::P2sh => KIND_P2SH,
            Self::Pqpkh => KIND_PQPKH,
        }
    }

    /// The kind of a §4.2 kind byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            KIND_P2PKH => Ok(Self::P2pkh),
            KIND_P2SH => Ok(Self::P2sh),
            KIND_PQPKH => Ok(Self::Pqpkh),
            _ => Err(Error::Recipient("unknown kind")),
        }
    }

    /// The §4.2 field length of this kind (22 or 35).
    pub fn field_len(self) -> usize {
        match self {
            Self::P2pkh | Self::P2sh => LEN_TRANSPARENT,
            Self::Pqpkh => LEN_PQPKH,
        }
    }

    /// The lowercase name (`p2pkh`, `p2sh`, `pqpkh`): status and logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::Pqpkh => "pqpkh",
        }
    }
}

/// A Ycash recipient: a transparent hash160 under P2PKH or P2SH, or a post-quantum key under
/// `TX_PQPKH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YcashRecipient {
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
    P2pkh([u8; 20]),
    /// `OP_HASH160 <20> OP_EQUAL`.
    P2sh([u8; 20]),
    /// `<keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`: the plain-YEC post-quantum address
    /// (`sq…`/`tq…`/`rq…`).
    Pqpkh(PqKeyId),
}

impl YcashRecipient {
    /// A P2PKH recipient.
    pub fn p2pkh(hash: [u8; 20]) -> Self {
        Self::P2pkh(hash)
    }

    /// A P2SH recipient.
    pub fn p2sh(hash: [u8; 20]) -> Self {
        Self::P2sh(hash)
    }

    /// A `TX_PQPKH` recipient under `scheme` (1 or 2); fails for a scheme outside the registry.
    pub fn pqpkh(scheme: u8, hash: Hash32) -> Result<Self> {
        PqKeyId::new(scheme, hash)
            .map(Self::Pqpkh)
            .map_err(|_| Error::Recipient("unknown scheme"))
    }

    /// The kind.
    pub fn kind(&self) -> RecipientKind {
        match self {
            Self::P2pkh(_) => RecipientKind::P2pkh,
            Self::P2sh(_) => RecipientKind::P2sh,
            Self::Pqpkh(_) => RecipientKind::Pqpkh,
        }
    }

    /// The 20-byte hash of a transparent recipient, `None` for `TX_PQPKH`.
    pub fn hash160(&self) -> Option<&[u8; 20]> {
        match self {
            Self::P2pkh(h) | Self::P2sh(h) => Some(h),
            Self::Pqpkh(_) => None,
        }
    }

    /// The post-quantum key id of a `TX_PQPKH` recipient, `None` otherwise.
    pub fn pq_key(&self) -> Option<&PqKeyId> {
        match self {
            Self::Pqpkh(id) => Some(id),
            _ => None,
        }
    }

    /// The §4.2 bytes (22 or 35).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LEN_PQPKH);
        b.push(RECIPIENT_VERSION);
        b.push(self.kind().byte());
        match self {
            Self::P2pkh(h) | Self::P2sh(h) => b.extend_from_slice(h),
            Self::Pqpkh(id) => b.extend_from_slice(&id.to_bytes()),
        }
        b
    }

    /// Strictly decode the §4.2 bytes: exactly 22 or 35 bytes, version 2, a known kind, the
    /// length of that kind, and for kind 2 a scheme of 1 or 2. The length is checked first, so
    /// a 32-byte version-1 blob and an Ethereum-style padded address fail as `wrong length`
    /// before their version byte is read; a 22-byte blob under version 1 fails as `unknown
    /// version`.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != LEN_TRANSPARENT && b.len() != LEN_PQPKH {
            return Err(Error::Recipient("wrong length"));
        }
        if b[0] != RECIPIENT_VERSION {
            return Err(Error::Recipient("unknown version"));
        }
        let kind = RecipientKind::from_byte(b[1])?;
        if b.len() != kind.field_len() {
            return Err(Error::Recipient("wrong length"));
        }
        match kind {
            RecipientKind::P2pkh => Ok(Self::P2pkh(b[2..].try_into().expect("20 bytes"))),
            RecipientKind::P2sh => Ok(Self::P2sh(b[2..].try_into().expect("20 bytes"))),
            RecipientKind::Pqpkh => {
                if !is_known_scheme(b[2]) {
                    return Err(Error::Recipient("unknown scheme"));
                }
                Self::pqpkh(b[2], b[3..].try_into().expect("32 bytes"))
            }
        }
    }

    /// The recipient scriptPubKey: P2PKH, P2SH or the node's `TX_PQPKH` (`GetScriptForPQKey`:
    /// `<keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`, the scheme pushed as a script number).
    pub fn script(&self) -> Vec<u8> {
        match self {
            Self::P2pkh(h) => p2pkh_script(h),
            Self::P2sh(h) => p2sh_script(h),
            Self::Pqpkh(id) => pqpkh_script(id),
        }
    }

    /// `SHA256(script)`: the intent's `recipientHash`.
    pub fn recipient_hash(&self) -> Hash32 {
        sha256(&self.script())
    }

    /// The recipient of an exact P2PKH, P2SH or `TX_PQPKH` scriptPubKey.
    pub fn from_script(spk: &[u8]) -> Result<Self> {
        if let Some(h) = parse_p2pkh(spk) {
            Ok(Self::P2pkh(h))
        } else if let Some(h) = parse_p2sh(spk) {
            Ok(Self::P2sh(h))
        } else if let Some(id) = parse_pqpkh(spk) {
            Ok(Self::Pqpkh(id))
        } else {
            Err(Error::Recipient("not a P2PKH, P2SH or TX_PQPKH script"))
        }
    }
}

/// The node's `TX_PQPKH` script of `id`: `20 <hash> OP_n OP_CHECKPQSIG` (35 bytes).
pub fn pqpkh_script(id: &PqKeyId) -> Vec<u8> {
    let mut s = Vec::with_capacity(PQPKH_SCRIPT_LEN);
    s.push(32);
    s.extend_from_slice(&id.hash);
    push_int_to(&mut s, i64::from(id.scheme));
    s.push(OP_CHECKPQSIG);
    s
}

/// The key id of an exact `TX_PQPKH` scriptPubKey (35 bytes, the scheme an `OP_1`/`OP_2`), the
/// node's `Solver` for the template: a data-push scheme (`01 01`), `OP_0`, `OP_3`.. are not it.
pub fn parse_pqpkh(spk: &[u8]) -> Option<PqKeyId> {
    if spk.len() != PQPKH_SCRIPT_LEN || spk[0] != 32 || spk[34] != OP_CHECKPQSIG {
        return None;
    }
    let scheme = spk[33].checked_sub(OP_1)? + 1;
    if !is_known_scheme(scheme) {
        return None;
    }
    let hash: Hash32 = spk[1..33].try_into().ok()?;
    PqKeyId::new(scheme, hash).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PQ: Hash32 = [0xc5; 32];

    fn all() -> [YcashRecipient; 4] {
        [
            YcashRecipient::p2pkh([0xab; 20]),
            YcashRecipient::p2sh([0x01; 20]),
            YcashRecipient::pqpkh(1, PQ).unwrap(),
            YcashRecipient::pqpkh(2, [0xff; 32]).unwrap(),
        ]
    }

    #[test]
    fn round_trip() {
        for r in all() {
            let b = r.to_bytes();
            assert_eq!(b.len(), r.kind().field_len());
            assert_eq!(YcashRecipient::from_bytes(&b).unwrap(), r);
            assert_eq!(YcashRecipient::from_script(&r.script()).unwrap(), r);
            assert_eq!(r.recipient_hash(), sha256(&r.script()));
            assert_eq!(RecipientKind::from_byte(b[1]).unwrap(), r.kind());
        }
        assert_eq!(
            hex::encode(YcashRecipient::p2pkh([0xab; 20]).to_bytes()),
            "0200abababababababababababababababababababab"
        );
        assert_eq!(
            &hex::encode(YcashRecipient::p2sh([0xab; 20]).to_bytes())[..4],
            "0201"
        );
        let pq = YcashRecipient::pqpkh(2, PQ).unwrap();
        assert_eq!(
            hex::encode(pq.to_bytes()),
            format!("020202{}", "c5".repeat(32))
        );
        assert_eq!(pq.kind().name(), "pqpkh");
        assert_eq!(pq.pq_key().unwrap().scheme, 2);
        assert_eq!(pq.hash160(), None);
        assert_eq!(YcashRecipient::p2sh([7; 20]).hash160(), Some(&[7u8; 20]));
        assert_eq!(YcashRecipient::p2sh([7; 20]).pq_key(), None);
    }

    /// The node's `GetScriptForPQKey` (`standard.cpp:338`): `20 <hash> OP_n OP_CHECKPQSIG`.
    #[test]
    fn pqpkh_script_shape() {
        let s = YcashRecipient::pqpkh(1, PQ).unwrap().script();
        assert_eq!(s.len(), 35);
        assert_eq!(s[0], 32);
        assert_eq!(&s[1..33], &PQ);
        assert_eq!(&s[33..], &[OP_1, OP_CHECKPQSIG]);
        let s2 = YcashRecipient::pqpkh(2, PQ).unwrap().script();
        assert_eq!(&s2[33..], &[0x52, OP_CHECKPQSIG]);
        // the scheme as a data push (01 01, quantum spec F-1) is not the template
        let mut data_push = s.clone();
        data_push.splice(33..34, [0x01, 0x01]);
        assert_eq!(data_push.len(), 36);
        assert!(YcashRecipient::from_script(&data_push).is_err());
        for bad_scheme in [0x00u8, 0x53, 0x60, 0x4f] {
            let mut t = s.clone();
            t[33] = bad_scheme;
            assert_eq!(parse_pqpkh(&t), None, "{bad_scheme:#x}");
        }
        let mut t = s.clone();
        t[34] = 0xac;
        assert_eq!(parse_pqpkh(&t), None);
        assert_eq!(parse_pqpkh(&s[..34]), None);
        let mut longer = s.clone();
        longer.push(0);
        assert_eq!(parse_pqpkh(&longer), None);
        let mut t = s.clone();
        t[0] = 31;
        assert_eq!(parse_pqpkh(&t), None);
    }

    #[test]
    fn rejects() {
        let good = YcashRecipient::p2pkh([0xab; 20]).to_bytes();
        let mut b = good.clone();
        b[0] = 1;
        assert_eq!(
            YcashRecipient::from_bytes(&b),
            Err(Error::Recipient("unknown version"))
        );
        b[0] = 3;
        assert_eq!(
            YcashRecipient::from_bytes(&b),
            Err(Error::Recipient("unknown version"))
        );
        let mut b = good.clone();
        b[1] = 3;
        assert_eq!(
            YcashRecipient::from_bytes(&b),
            Err(Error::Recipient("unknown kind"))
        );
        b[1] = 2; // the PQ kind with a 22-byte body
        assert_eq!(
            YcashRecipient::from_bytes(&b),
            Err(Error::Recipient("wrong length"))
        );
        for n in [0, 1, 2, 21, 23, 32, 34, 36] {
            let v = vec![0x02u8; n];
            assert_eq!(
                YcashRecipient::from_bytes(&v),
                Err(Error::Recipient("wrong length")),
                "{n}"
            );
        }
        let pq = YcashRecipient::pqpkh(1, PQ).unwrap().to_bytes();
        for kind in [0u8, 1] {
            let mut b = pq.clone();
            b[1] = kind;
            assert_eq!(
                YcashRecipient::from_bytes(&b),
                Err(Error::Recipient("wrong length"))
            );
        }
        for scheme in [0u8, 3, 0xff] {
            let mut b = pq.clone();
            b[2] = scheme;
            assert_eq!(
                YcashRecipient::from_bytes(&b),
                Err(Error::Recipient("unknown scheme")),
                "{scheme}"
            );
            assert!(YcashRecipient::pqpkh(scheme, PQ).is_err());
        }
        assert!(RecipientKind::from_byte(0xff).is_err());
        assert!(YcashRecipient::from_script(&[0x6a]).is_err());
        assert!(YcashRecipient::from_script(&[]).is_err());
    }

    /// Version 1 (the retired 32-byte form: `01`, kind, 10 zero bytes, hash160) is refused.
    #[test]
    fn version_1_blob_is_refused() {
        let mut v1 = [0u8; 32];
        v1[0] = 0x01;
        v1[12..].copy_from_slice(&[0xab; 20]);
        assert_eq!(
            YcashRecipient::from_bytes(&v1),
            Err(Error::Recipient("wrong length"))
        );
        // an Ethereum-style left-padded address is not a recipient either
        let mut eth = [0u8; 32];
        eth[12..].copy_from_slice(&[0x11; 20]);
        assert!(YcashRecipient::from_bytes(&eth).is_err());
    }
}
