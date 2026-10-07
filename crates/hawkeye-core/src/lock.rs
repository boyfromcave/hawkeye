//! The lock side's encodings (plan §1.2, §4.1): `lockId` and the destination `OP_RETURN`.

use crate::bytes::{Hash32, OutPoint, sha256};
use crate::error::{Error, Result};
use crate::eth::EthAddress;
use crate::script::{is_op_return, op_return_script, op_return_single_push};

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
}
