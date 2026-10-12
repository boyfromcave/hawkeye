//! The lock side's encodings (plan §1.2, §4.1; NEAR plan §2.1): `lockId` and the destination
//! `OP_RETURN` — an Ethereum address (`WYEC` locks) or `"NR1"` ‖ a NEAR account id (`NYEC`
//! locks).

use crate::bridge::BridgeKind;
use crate::bytes::{Hash32, OutPoint, sha256};
use crate::error::{Error, Result};
use crate::eth::EthAddress;
use crate::near::AccountId;
use crate::script::{is_op_return, op_return_script, op_return_single_push};

/// The NEAR destination's prefix, `"NR1"` (0x4E 0x52 0x31, NEAR plan N-3).
pub const NEAR_DESTINATION_PREFIX: [u8; 3] = *b"NR1";
/// The longest NEAR destination push: `"NR1"` and a 64-byte account id.
pub const NEAR_DESTINATION_MAX_LEN: usize = 3 + crate::near::ACCOUNT_ID_MAX_LEN;

/// Where a lock mints: the recipient its destination `OP_RETURN` names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    /// A `WYEC` lock: the Ethereum address `WyecBridge` mints to.
    Ethereum(EthAddress),
    /// An `NYEC` lock: the NEAR account `wyec-near` mints to.
    Near(AccountId),
}

impl Destination {
    /// The bridge this destination belongs to.
    pub fn kind(&self) -> BridgeKind {
        match self {
            Self::Ethereum(_) => BridgeKind::Ethereum,
            Self::Near(_) => BridgeKind::Near,
        }
    }

    /// The destination `OP_RETURN`.
    pub fn script(&self) -> Vec<u8> {
        match self {
            Self::Ethereum(a) => destination_script(a),
            Self::Near(a) => near_destination_script(a),
        }
    }

    /// Parse the destination `OP_RETURN` of a `kind` lock.
    pub fn parse(kind: BridgeKind, spk: &[u8]) -> Result<Self> {
        match kind {
            BridgeKind::Ethereum => parse_destination(spk).map(Self::Ethereum),
            BridgeKind::Near => parse_near_destination(spk).map(Self::Near),
        }
    }

    /// The Ethereum address, if this is an Ethereum destination.
    pub fn ethereum(&self) -> Option<&EthAddress> {
        match self {
            Self::Ethereum(a) => Some(a),
            Self::Near(_) => None,
        }
    }

    /// The NEAR account, if this is a NEAR destination.
    pub fn near(&self) -> Option<&AccountId> {
        match self {
            Self::Near(a) => Some(a),
            Self::Ethereum(_) => None,
        }
    }
}

impl core::fmt::Display for Destination {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ethereum(a) => a.fmt(f),
            Self::Near(a) => a.fmt(f),
        }
    }
}

/// `lockId = SHA256(txid_internal (32) ‖ vout (u32 LE))` — the 36-byte outpoint serialisation
/// of the lock's V output (wyec design E-5, plan §4.1).
pub fn lock_id(lock: &OutPoint) -> Hash32 {
    sha256(&lock.to_bytes())
}

/// The destination `OP_RETURN` of a lock: `OP_RETURN <32>` with the ABI `bytes32` of the
/// Ethereum address (12 zero bytes, then the address).
pub fn destination_script(to: &EthAddress) -> Vec<u8> {
    op_return_script(&to.to_word())
}

/// Parse a destination `OP_RETURN` (plan §4.1 rule 3): exactly `OP_RETURN` and one canonical
/// 32-byte push whose first 12 bytes are zero and which does not begin `0x5956` ("YV", an act).
pub fn parse_destination(spk: &[u8]) -> Result<EthAddress> {
    if !is_op_return(spk) {
        return Err(Error::Destination("not an OP_RETURN"));
    }
    let data = op_return_single_push(spk).ok_or(Error::Destination("not one canonical push"))?;
    if data.len() != 32 {
        return Err(Error::Destination("push is not 32 bytes"));
    }
    if data.starts_with(b"YV") {
        return Err(Error::Destination("begins 0x5956"));
    }
    if data[..12].iter().any(|&b| b != 0) {
        return Err(Error::Destination("first 12 bytes not zero"));
    }
    Ok(EthAddress(data[12..].try_into().expect("20 bytes")))
}

/// The destination `OP_RETURN` of a NEAR lock: `OP_RETURN <"NR1" ‖ account id>` (one direct
/// push of 5–67 bytes).
pub fn near_destination_script(to: &AccountId) -> Vec<u8> {
    let mut data = Vec::with_capacity(NEAR_DESTINATION_MAX_LEN);
    data.extend_from_slice(&NEAR_DESTINATION_PREFIX);
    data.extend_from_slice(to.as_bytes());
    op_return_script(&data)
}

/// Parse a NEAR destination `OP_RETURN` (NEAR plan §2.1): exactly `OP_RETURN` and one canonical
/// push of `"NR1"` followed by a valid NEAR account id.
pub fn parse_near_destination(spk: &[u8]) -> Result<AccountId> {
    if !is_op_return(spk) {
        return Err(Error::Destination("not an OP_RETURN"));
    }
    let data = op_return_single_push(spk).ok_or(Error::Destination("not one canonical push"))?;
    let Some(id) = data.strip_prefix(&NEAR_DESTINATION_PREFIX) else {
        return Err(Error::Destination("does not begin \"NR1\""));
    };
    AccountId::from_bytes(id).map_err(|_| Error::Destination("not a valid NEAR account id"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{OP_PUSHDATA1, OP_RETURN};

    #[test]
    fn lock_id_is_sha256_of_outpoint() {
        let op = OutPoint::new([0xaa; 32], 1);
        let mut pre = vec![0xaa; 32];
        pre.extend_from_slice(&[1, 0, 0, 0]);
        assert_eq!(lock_id(&op), sha256(&pre));
        assert_ne!(lock_id(&op), lock_id(&OutPoint::new([0xaa; 32], 0)));
    }

    #[test]
    fn destination_round_trip_and_rejects() {
        let to = EthAddress([0x11; 20]);
        let s = destination_script(&to);
        assert_eq!(s.len(), 34);
        assert_eq!(&s[..2], &[OP_RETURN, 0x20]);
        assert_eq!(parse_destination(&s).unwrap(), to);

        let mut not_zero = s.clone();
        not_zero[2] = 1;
        assert!(parse_destination(&not_zero).is_err());
        let mut yv = s.clone();
        yv[2..4].copy_from_slice(b"YV");
        assert_eq!(
            parse_destination(&yv),
            Err(Error::Destination("begins 0x5956"))
        );
        assert!(parse_destination(&op_return_script(&[0; 20])).is_err());
        let mut nc = vec![OP_RETURN, OP_PUSHDATA1, 32];
        nc.extend_from_slice(&to.to_word());
        assert!(parse_destination(&nc).is_err());
        let mut extra = s.clone();
        extra.push(0x00);
        assert!(parse_destination(&extra).is_err());
        assert!(parse_destination(&s[1..]).is_err());
    }

    #[test]
    fn near_destination_round_trip_and_rejects() {
        let to = AccountId::parse("alice.near").unwrap();
        let s = near_destination_script(&to);
        assert_eq!(
            hex::encode(&s),
            format!("6a0d4e5231{}", hex::encode("alice.near"))
        );
        assert_eq!(parse_near_destination(&s).unwrap(), to);
        let d = Destination::Near(to.clone());
        assert_eq!(d.script(), s);
        assert_eq!(d.kind(), BridgeKind::Near);
        assert_eq!(Destination::parse(BridgeKind::Near, &s).unwrap(), d);
        assert_eq!(d.near(), Some(&to));
        assert_eq!(d.ethereum(), None);
        assert_eq!(d.to_string(), "alice.near");
        // an NR1 destination is not an Ethereum one, and vice versa
        assert!(Destination::parse(BridgeKind::Ethereum, &s).is_err());
        let e = Destination::Ethereum(EthAddress([0x11; 20]));
        assert_eq!(e.kind(), BridgeKind::Ethereum);
        assert_eq!(e.script(), destination_script(&EthAddress([0x11; 20])));
        assert_eq!(
            Destination::parse(BridgeKind::Ethereum, &e.script()).unwrap(),
            e
        );
        assert!(Destination::parse(BridgeKind::Near, &e.script()).is_err());
        assert_eq!(e.ethereum(), Some(&EthAddress([0x11; 20])));
        assert_eq!(e.near(), None);
        assert!(e.to_string().starts_with("0x1111"));

        // the longest id: 67-byte push, still a direct push
        let long = AccountId::parse(&"a".repeat(64)).unwrap();
        let ls = near_destination_script(&long);
        assert_eq!(&ls[..2], &[OP_RETURN, 67]);
        assert_eq!(parse_near_destination(&ls).unwrap(), long);

        let bad = |data: &[u8]| parse_near_destination(&op_return_script(data)).unwrap_err();
        assert_eq!(
            bad(b"NR2alice.near"),
            Error::Destination("does not begin \"NR1\"")
        );
        assert_eq!(
            bad(b"NR1"),
            Error::Destination("not a valid NEAR account id")
        );
        assert_eq!(
            bad(b"NR1a"),
            Error::Destination("not a valid NEAR account id")
        );
        assert_eq!(
            bad(b"NR1Alice.near"),
            Error::Destination("not a valid NEAR account id")
        );
        assert_eq!(
            bad(&[&b"NR1"[..], &[b'a'; 65]].concat()),
            Error::Destination("not a valid NEAR account id")
        );
        assert_eq!(
            bad(b"YValice"),
            Error::Destination("does not begin \"NR1\"")
        );
        let mut nc = vec![OP_RETURN, OP_PUSHDATA1, 13];
        nc.extend_from_slice(b"NR1alice.near");
        assert_eq!(
            parse_near_destination(&nc),
            Err(Error::Destination("not one canonical push"))
        );
        let mut two = s.clone();
        two.push(0x00);
        assert!(parse_near_destination(&two).is_err());
        assert_eq!(
            parse_near_destination(&s[1..]),
            Err(Error::Destination("not an OP_RETURN"))
        );
    }
}
