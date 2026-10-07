//! A minimal parser for Overwinter v3 and Sapling v4 transactions: exactly the fields
//! [`crate::sighash`] needs (ZIP-143 / ZIP-243), with shielded and Sprout components kept as raw
//! fixed-size records. Not a validator — the node is; this only has to read what the node
//! serialised and write the same bytes back.
//!
//! Layout (ycash-dd `src/primitives/transaction.h`, `CTransaction::SerializationOp`):
//!
//! ```text
//! header u32 (fOverwintered << 31 | nVersion) ‖ nVersionGroupId u32
//! vin  (compact size, then prevout 36 ‖ scriptSig (compact size ‖ bytes) ‖ nSequence u32)
//! vout (compact size, then value i64 ‖ scriptPubKey (compact size ‖ bytes))
//! nLockTime u32 ‖ nExpiryHeight u32
//! v4 only: valueBalance i64 ‖ vShieldedSpend (384 bytes each) ‖ vShieldedOutput (948 each)
//! vJoinSplit (1802 bytes each in v3, 1698 in v4) [‖ joinSplitPubKey 32 ‖ joinSplitSig 64]
//! v4 with spends or outputs: bindingSig 64
//! ```
//!
//! Sprout (v1/v2, not overwintered) and future-format transactions are rejected.

use crate::bytes::{Hash32, OutPoint, sha256d};
use crate::error::{Error, Result};

/// `nVersionGroupId` of an Overwinter v3 transaction (ZIP 202).
pub const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
/// `nVersionGroupId` of a Sapling v4 transaction (ZIP 243).
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
/// `nVersion` of an Overwinter transaction.
pub const OVERWINTER_TX_VERSION: u32 = 3;
/// `nVersion` of a Sapling transaction.
pub const SAPLING_TX_VERSION: u32 = 4;

/// A Sapling spend description's size: `cv ‖ anchor ‖ nullifier ‖ rk ‖ zkproof ‖ spendAuthSig`.
pub const SPEND_LEN: usize = 384;
/// The prefix of a spend description that ZIP-243's `hashShieldedSpends` covers (everything but
/// `spendAuthSig`).
pub const SPEND_HASHED_LEN: usize = 32 * 4 + 192;
/// A Sapling output description's size (all of it is hashed).
pub const OUTPUT_LEN: usize = 948;
/// A JoinSplit description's size in a v3 transaction (PHGR proof, 296 bytes).
pub const JOINSPLIT_LEN_V3: usize = 1802;
/// A JoinSplit description's size in a v4 transaction (Groth proof, 192 bytes).
pub const JOINSPLIT_LEN_V4: usize = 1698;

/// Bitcoin's `MAX_SIZE`: the largest compact size a vector length may take.
const MAX_SIZE: u64 = 0x0200_0000;

/// Which of the two supported formats a transaction is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxFormat {
    /// Overwinter v3 (sighash ZIP-143).
    OverwinterV3,
    /// Sapling v4 (sighash ZIP-243).
    SaplingV4,
}

/// A transparent input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The coin spent.
    pub prevout: OutPoint,
    /// The scriptSig bytes.
    pub script_sig: Vec<u8>,
    /// `nSequence`.
    pub sequence: u32,
}

/// A transparent output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// The value in zatoshi (`CAmount`, signed on the wire).
    pub value: i64,
    /// The scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    /// `CTxOut` serialisation: value i64 LE ‖ compact size ‖ script.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.script_pubkey.len());
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        write_bytes(out, &self.script_pubkey);
    }
}

/// An Overwinter v3 or Sapling v4 transaction.
///
/// Shielded spends and outputs and Sprout JoinSplits are kept as their raw serialisations; the
/// parser checks only their sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// v3 or v4 (implies `nVersion` and `nVersionGroupId`).
    pub format: TxFormat,
    /// The transparent inputs.
    pub vin: Vec<TxIn>,
    /// The transparent outputs.
    pub vout: Vec<TxOut>,
    /// `nLockTime`.
    pub lock_time: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// Sapling `valueBalance` (0 and not serialised in v3).
    pub value_balance: i64,
    /// Sapling spend descriptions, [`SPEND_LEN`] bytes each (v4 only).
    pub shielded_spends: Vec<Vec<u8>>,
    /// Sapling output descriptions, [`OUTPUT_LEN`] bytes each (v4 only).
    pub shielded_outputs: Vec<Vec<u8>>,
    /// JoinSplit descriptions, [`JOINSPLIT_LEN_V3`] / [`JOINSPLIT_LEN_V4`] bytes each.
    pub joinsplits: Vec<Vec<u8>>,
    /// `joinSplitPubKey`, present iff there are JoinSplits.
    pub joinsplit_pubkey: Option<[u8; 32]>,
    /// `joinSplitSig`, present iff there are JoinSplits.
    pub joinsplit_sig: Option<[u8; 64]>,
    /// `bindingSig`, present iff a v4 transaction has spends or outputs.
    pub binding_sig: Option<[u8; 64]>,
}

impl Transaction {
    /// `nVersion` (3 or 4).
    pub fn version(&self) -> u32 {
        match self.format {
            TxFormat::OverwinterV3 => OVERWINTER_TX_VERSION,
            TxFormat::SaplingV4 => SAPLING_TX_VERSION,
        }
    }

    /// The 4-byte header, `fOverwintered << 31 | nVersion`.
    pub fn header(&self) -> u32 {
        (1 << 31) | self.version()
    }

    /// `nVersionGroupId`.
    pub fn version_group_id(&self) -> u32 {
        match self.format {
            TxFormat::OverwinterV3 => OVERWINTER_VERSION_GROUP_ID,
            TxFormat::SaplingV4 => SAPLING_VERSION_GROUP_ID,
        }
    }

    /// The JoinSplit description size for this format.
    pub fn joinsplit_len(&self) -> usize {
        joinsplit_len(self.format)
    }

    /// Parse a whole serialised transaction; trailing bytes are an error.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, pos: 0 };
        let header = r.u32()?;
        if header >> 31 == 0 {
            return Err(Error::Tx(
                "not overwintered (Sprout v1/v2 is not supported)",
            ));
        }
        let version = header & 0x7fff_ffff;
        let group = r.u32()?;
        let format = match (version, group) {
            (OVERWINTER_TX_VERSION, OVERWINTER_VERSION_GROUP_ID) => TxFormat::OverwinterV3,
            (SAPLING_TX_VERSION, SAPLING_VERSION_GROUP_ID) => TxFormat::SaplingV4,
            _ => return Err(Error::Tx("unknown transaction format")),
        };
        let n = r.count()?;
        let mut vin = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let prevout = OutPoint::from_bytes(r.take(OutPoint::LEN)?)?;
            let script_sig = r.var_bytes()?;
            let sequence = r.u32()?;
            vin.push(TxIn {
                prevout,
                script_sig,
                sequence,
            });
        }
        let n = r.count()?;
        let mut vout = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let value = r.i64()?;
            let script_pubkey = r.var_bytes()?;
            vout.push(TxOut {
                value,
                script_pubkey,
            });
        }
        let lock_time = r.u32()?;
        let expiry_height = r.u32()?;
        let (mut value_balance, mut shielded_spends, mut shielded_outputs) = (0, vec![], vec![]);
        if format == TxFormat::SaplingV4 {
            value_balance = r.i64()?;
            shielded_spends = r.records(SPEND_LEN)?;
            shielded_outputs = r.records(OUTPUT_LEN)?;
        }
        let joinsplits = r.records(joinsplit_len(format))?;
        let (mut joinsplit_pubkey, mut joinsplit_sig) = (None, None);
        if !joinsplits.is_empty() {
            joinsplit_pubkey = Some(r.array()?);
            joinsplit_sig = Some(r.array()?);
        }
        let mut binding_sig = None;
        if format == TxFormat::SaplingV4
            && !(shielded_spends.is_empty() && shielded_outputs.is_empty())
        {
            binding_sig = Some(r.array()?);
        }
        if r.pos != bytes.len() {
            return Err(Error::Tx("trailing bytes"));
        }
        Ok(Self {
            format,
            vin,
            vout,
            lock_time,
            expiry_height,
            value_balance,
            shielded_spends,
            shielded_outputs,
            joinsplits,
            joinsplit_pubkey,
            joinsplit_sig,
            binding_sig,
        })
    }

    /// Serialise. For a transaction that came from [`Transaction::parse`] this is the input
    /// bytes. Fails if a raw record has the wrong size or an optional field's presence does not
    /// match the rules above.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let v4 = self.format == TxFormat::SaplingV4;
        if !v4 && (self.value_balance != 0 || self.has_sapling() || self.binding_sig.is_some()) {
            return Err(Error::Tx("Sapling fields in a v3 transaction"));
        }
        if self.joinsplits.is_empty()
            != (self.joinsplit_pubkey.is_none() && self.joinsplit_sig.is_none())
            || self.joinsplit_pubkey.is_some() != self.joinsplit_sig.is_some()
        {
            return Err(Error::Tx("joinSplitPubKey/Sig present iff JoinSplits"));
        }
        if v4 && self.has_sapling() != self.binding_sig.is_some() {
            return Err(Error::Tx("bindingSig present iff spends or outputs"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.header().to_le_bytes());
        out.extend_from_slice(&self.version_group_id().to_le_bytes());
        write_compact(&mut out, self.vin.len() as u64);
        for i in &self.vin {
            out.extend_from_slice(&i.prevout.to_bytes());
            write_bytes(&mut out, &i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_compact(&mut out, self.vout.len() as u64);
        for o in &self.vout {
            o.write(&mut out);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        if v4 {
            out.extend_from_slice(&self.value_balance.to_le_bytes());
            write_records(&mut out, &self.shielded_spends, SPEND_LEN)?;
            write_records(&mut out, &self.shielded_outputs, OUTPUT_LEN)?;
        }
        write_records(&mut out, &self.joinsplits, self.joinsplit_len())?;
        if let (Some(pk), Some(sig)) = (&self.joinsplit_pubkey, &self.joinsplit_sig) {
            out.extend_from_slice(pk);
            out.extend_from_slice(sig);
        }
        if let Some(sig) = &self.binding_sig {
            out.extend_from_slice(sig);
        }
        Ok(out)
    }

    /// The txid (internal byte order): SHA256d of the serialisation.
    pub fn txid(&self) -> Result<Hash32> {
        Ok(sha256d(&self.to_bytes()?))
    }

    fn has_sapling(&self) -> bool {
        !(self.shielded_spends.is_empty() && self.shielded_outputs.is_empty())
    }
}

fn joinsplit_len(format: TxFormat) -> usize {
    match format {
        TxFormat::OverwinterV3 => JOINSPLIT_LEN_V3,
        TxFormat::SaplingV4 => JOINSPLIT_LEN_V4,
    }
}

/// Bitcoin's `WriteCompactSize`.
pub fn write_compact(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// A compact size followed by the bytes (`CScriptBase` / `std::vector<unsigned char>`).
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_compact(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn write_records(out: &mut Vec<u8>, recs: &[Vec<u8>], len: usize) -> Result<()> {
    write_compact(out, recs.len() as u64);
    for r in recs {
        if r.len() != len {
            return Err(Error::Length {
                what: "shielded or JoinSplit record",
                expected: len,
                got: r.len(),
            });
        }
        out.extend_from_slice(r);
    }
    Ok(())
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(Error::Tx("truncated"))?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returns N bytes"))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// Bitcoin's `ReadCompactSize`: canonical encodings only, at most `MAX_SIZE`.
    fn compact(&mut self) -> Result<u64> {
        let first = self.array::<1>()?[0];
        let n = match first {
            0xfd => {
                let n = u64::from(u16::from_le_bytes(self.array()?));
                if n < 0xfd {
                    return Err(Error::Tx("non-canonical compact size"));
                }
                n
            }
            0xfe => {
                let n = u64::from(u32::from_le_bytes(self.array()?));
                if n < 0x1_0000 {
                    return Err(Error::Tx("non-canonical compact size"));
                }
                n
            }
            0xff => {
                let n = u64::from_le_bytes(self.array()?);
                if n < 0x1_0000_0000 {
                    return Err(Error::Tx("non-canonical compact size"));
                }
                n
            }
            n => u64::from(n),
        };
        if n > MAX_SIZE {
            return Err(Error::Tx("compact size too large"));
        }
        Ok(n)
    }

    fn count(&mut self) -> Result<usize> {
        Ok(self.compact()? as usize)
    }

    fn var_bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.count()?;
        Ok(self.take(n)?.to_vec())
    }

    fn records(&mut self, len: usize) -> Result<Vec<Vec<u8>>> {
        let n = self.count()?;
        // A count larger than the remaining bytes can hold is truncated input: fail before
        // allocating.
        if n.saturating_mul(len) > self.b.len() - self.pos {
            return Err(Error::Tx("truncated"));
        }
        (0..n).map(|_| Ok(self.take(len)?.to_vec())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Transaction {
        Transaction {
            format: TxFormat::SaplingV4,
            vin: vec![
                TxIn {
                    prevout: OutPoint::new([1; 32], 0),
                    script_sig: vec![0x51],
                    sequence: 0xffff_ffff,
                },
                TxIn {
                    prevout: OutPoint::new([2; 32], 7),
                    script_sig: vec![0xab; 300],
                    sequence: 5,
                },
            ],
            vout: vec![TxOut {
                value: 2_500_000_000,
                script_pubkey: vec![0x6a],
            }],
            lock_time: 17,
            expiry_height: 1234,
            value_balance: 0,
            shielded_spends: vec![],
            shielded_outputs: vec![],
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        }
    }

    #[test]
    fn transparent_round_trip() {
        let tx = sample();
        let b = tx.to_bytes().unwrap();
        assert_eq!(&b[..8], &hex::decode("0400008085202f89").unwrap()[..]);
        assert_eq!(Transaction::parse(&b).unwrap(), tx);
        let mut v3 = tx.clone();
        v3.format = TxFormat::OverwinterV3;
        let b3 = v3.to_bytes().unwrap();
        assert_eq!(&b3[..8], &hex::decode("030000807082c403").unwrap()[..]);
        assert_eq!(Transaction::parse(&b3).unwrap(), v3);
        assert_eq!(b3.len() + 8 + 2, b.len()); // valueBalance + two empty Sapling vectors
    }

    #[test]
    fn shielded_round_trip() {
        let mut tx = sample();
        tx.value_balance = -5;
        tx.shielded_spends = vec![vec![3; SPEND_LEN]];
        tx.shielded_outputs = vec![vec![4; OUTPUT_LEN], vec![5; OUTPUT_LEN]];
        tx.joinsplits = vec![vec![6; JOINSPLIT_LEN_V4]];
        tx.joinsplit_pubkey = Some([7; 32]);
        tx.joinsplit_sig = Some([8; 64]);
        tx.binding_sig = Some([9; 64]);
        let b = tx.to_bytes().unwrap();
        assert_eq!(Transaction::parse(&b).unwrap(), tx);
        // missing bindingSig, wrong record size
        let mut bad = tx.clone();
        bad.binding_sig = None;
        assert!(bad.to_bytes().is_err());
        let mut bad = tx.clone();
        bad.joinsplits = vec![vec![6; JOINSPLIT_LEN_V3]];
        assert!(bad.to_bytes().is_err());
        let mut bad = tx;
        bad.format = TxFormat::OverwinterV3;
        assert!(bad.to_bytes().is_err());
    }

    #[test]
    fn rejects() {
        let b = sample().to_bytes().unwrap();
        // truncation at every length, and a trailing byte
        for n in 0..b.len() {
            assert!(Transaction::parse(&b[..n]).is_err(), "prefix {n}");
        }
        let mut long = b.clone();
        long.push(0);
        assert_eq!(Transaction::parse(&long), Err(Error::Tx("trailing bytes")));
        // Sprout and unknown formats
        let mut sprout = b.clone();
        sprout[3] = 0;
        assert!(Transaction::parse(&sprout).is_err());
        let mut v5 = b.clone();
        v5[0] = 5;
        assert!(Transaction::parse(&v5).is_err());
        let mut group = b.clone();
        group[4] ^= 1;
        assert!(Transaction::parse(&group).is_err());
        // non-canonical compact size for the vin count (2 written as fd 02 00)
        let mut nc = b[..8].to_vec();
        nc.extend_from_slice(&[0xfd, 0x02, 0x00]);
        nc.extend_from_slice(&b[9..]);
        assert_eq!(
            Transaction::parse(&nc),
            Err(Error::Tx("non-canonical compact size"))
        );
        // a huge record count fails without allocating
        let mut huge = b[..8].to_vec();
        huge.extend_from_slice(&[0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]); // no vin/vout, times
        huge.extend_from_slice(&[0; 8]); // valueBalance
        huge.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff, 0x01]); // spends count > MAX_SIZE
        assert!(Transaction::parse(&huge).is_err());
    }

    #[test]
    fn compact_sizes() {
        for (n, want) in [
            (0u64, "00"),
            (0xfc, "fc"),
            (0xfd, "fdfd00"),
            (0xffff, "fdffff"),
            (0x1_0000, "fe00000100"),
        ] {
            let mut out = vec![];
            write_compact(&mut out, n);
            assert_eq!(hex::encode(&out), want);
            let mut r = Reader { b: &out, pos: 0 };
            assert_eq!(r.compact().unwrap(), n);
        }
    }
}
