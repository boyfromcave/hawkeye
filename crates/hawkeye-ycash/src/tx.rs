//! The transaction codec: decode, re-encode byte-exactly, txid, and memo insertion.
//!
//! The format is `CTransaction::SerializationOp` (ycash-dd `src/primitives/transaction.h:586`):
//!
//! ```text
//! header u32 LE (bit 31 fOverwintered, bits 0..30 nVersion)
//! [nVersionGroupId u32]                         overwintered
//! vin  CompactSize ‖ (prevout 36 ‖ scriptSig ‖ nSequence u32)*
//! vout CompactSize ‖ (nValue i64 ‖ scriptPubKey)*
//! nLockTime u32
//! [nExpiryHeight u32]                           Overwinter v3 / Sapling v4
//! [valueBalance i64 ‖ vShieldedSpend ‖ vShieldedOutput]   Sapling v4
//! [vJoinSplit ‖ (joinSplitPubKey 32 ‖ joinSplitSig 64 if any)]   nVersion >= 2
//! [bindingSig 64]                               v4 with a spend or an output
//! ```
//!
//! Spend descriptions are 384 bytes, output descriptions 948, joinsplits 1698 (Groth16, v4) or
//! 1802 (PHGR, earlier); they are kept as opaque bytes. Every transaction the vault RPCs build is
//! a transparent-only v4. The txid is SHA256d of the serialization, printed reversed.

use sha2::{Digest, Sha256};

use crate::primitives::{OutPoint, Txid};

pub const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
pub const OVERWINTER_TX_VERSION: u32 = 3;
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
pub const SAPLING_TX_VERSION: u32 = 4;

pub const SPEND_DESCRIPTION_SIZE: usize = 32 + 32 + 32 + 32 + 192 + 64;
pub const OUTPUT_DESCRIPTION_SIZE: usize = 32 + 32 + 32 + 580 + 80 + 192;
/// `JOINSPLIT_SIZE(v)`, `src/primitives/transaction.h:78`.
pub const fn joinsplit_size(groth: bool) -> usize {
    if groth { 1698 } else { 1802 }
}

/// `MAX_SIZE` of `ReadCompactSize` (`src/serialize.h`).
pub const MAX_COMPACT_SIZE: u64 = 0x0200_0000;
/// Data bytes in one standard `OP_RETURN` (`MAX_OP_RETURN_RELAY` 83 = 80 + OP_RETURN + push
/// opcode(s), `src/script/standard.h:35`).
pub const MAX_OP_RETURN_DATA: usize = 80;

pub const OP_RETURN: u8 = 0x6a;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;

/// Why bytes are not a transaction, or why an edit was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("not hex: {0}")]
    Hex(String),
    #[error("truncated at byte {0}")]
    Truncated(usize),
    #[error("non-canonical CompactSize at byte {0}")]
    NonCanonicalSize(usize),
    #[error("CompactSize {0} exceeds MAX_SIZE")]
    SizeTooLarge(u64),
    #[error("unknown overwintered format: version {version}, group id {group:#010x}")]
    UnknownFormat { version: u32, group: u32 },
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("the transaction already has an OP_RETURN output (vout {0})")]
    AlreadyHasOpReturn(usize),
    #[error("input {0} already carries a signature; insert the memo before signing")]
    InputSigned(usize),
    #[error("the transaction has shielded components (signatures over the sighash)")]
    Shielded,
    #[error("OP_RETURN data must be 1..={MAX_OP_RETURN_DATA} bytes, got {0}")]
    DataSize(usize),
}

/// A transparent input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxIn {
    /// A coinbase input: null prevout hash, index `0xffffffff`.
    pub fn is_coinbase(&self) -> bool {
        self.prevout.vout == u32::MAX && self.prevout.txid.0 == [0u8; 32]
    }

    /// The scriptSig carries a signature, i.e. anything but nothing or a bare small-integer
    /// selector (`OP_1`..`OP_16`, as `set_signunlock` writes when this wallet holds no member
    /// key, or a RELEASE's `OP_1`).
    pub fn has_signature(&self) -> bool {
        match self.script_sig.as_slice() {
            [] => false,
            [op] => !(OP_1..=OP_16).contains(op),
            _ => true,
        }
    }
}

/// A transparent output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Zatoshi.
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn is_op_return(&self) -> bool {
        self.script_pubkey.first() == Some(&OP_RETURN)
    }

    /// The single push of an `OP_RETURN <push>` output (any push form; `OP_0` gives empty data).
    pub fn op_return_data(&self) -> Option<&[u8]> {
        let s = self.script_pubkey.as_slice();
        if s.first() != Some(&OP_RETURN) {
            return None;
        }
        let (data, rest) = read_push(&s[1..])?;
        rest.is_empty().then_some(data)
    }

    /// `OP_RETURN` followed by the minimal push of `data` (`CScript() << OP_RETURN << data`).
    pub fn op_return(data: &[u8]) -> Self {
        let mut s = Vec::with_capacity(data.len() + 3);
        s.push(OP_RETURN);
        push_data(&mut s, data);
        TxOut {
            value: 0,
            script_pubkey: s,
        }
    }
}

/// Append the minimal push of `data` (`CScript << std::vector<unsigned char>`).
pub fn push_data(s: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < OP_PUSHDATA1 as usize {
        s.push(n as u8);
    } else if n <= 0xff {
        s.extend([OP_PUSHDATA1, n as u8]);
    } else if n <= 0xffff {
        s.push(0x4d);
        s.extend((n as u16).to_le_bytes());
    } else {
        s.push(0x4e);
        s.extend((n as u32).to_le_bytes());
    }
    s.extend_from_slice(data);
}

/// One push at the start of `s`: (data, rest).
fn read_push(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&op, s) = s.split_first()?;
    let (n, s) = match op {
        0 => (0usize, s),
        1..=0x4b => (op as usize, s),
        0x4c => (*s.first()? as usize, &s[1..]),
        0x4d => (
            u16::from_le_bytes(s.get(..2)?.try_into().ok()?) as usize,
            &s[2..],
        ),
        0x4e => (
            u32::from_le_bytes(s.get(..4)?.try_into().ok()?) as usize,
            &s[4..],
        ),
        _ => return None,
    };
    (s.len() >= n).then(|| (&s[..n], &s[n..]))
}

/// A Sprout JoinSplit description (opaque; 1698 or 1802 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinSplit(pub Vec<u8>);

/// The JoinSplits of a transaction with `nVersion >= 2`, and their signing key and signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinSplits {
    pub descriptions: Vec<JoinSplit>,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

/// The Sapling part of a v4 transaction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SaplingBundle {
    pub value_balance: i64,
    /// 384-byte spend descriptions.
    pub spends: Vec<Vec<u8>>,
    /// 948-byte output descriptions.
    pub outputs: Vec<Vec<u8>>,
    /// Present iff there is a spend or an output.
    pub binding_sig: Option<[u8; 64]>,
}

/// A decoded transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub overwintered: bool,
    /// `nVersion` (31 bits).
    pub version: u32,
    /// `nVersionGroupId` (0 unless overwintered).
    pub version_group_id: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    /// `nExpiryHeight` (Overwinter v3 / Sapling v4; 0 otherwise).
    pub expiry_height: u32,
    /// Sapling v4 only.
    pub sapling: Option<SaplingBundle>,
    /// `nVersion >= 2` only. `Some` with no descriptions encodes the empty vector.
    pub joinsplits: Option<JoinSplits>,
}

/// The serialized formats this codec reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Not overwintered, `nVersion` 0 or 1: no JoinSplits.
    Sprout,
    /// Not overwintered, `nVersion >= 2`: PHGR JoinSplits.
    SproutJoinSplit,
    OverwinterV3,
    SaplingV4,
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .i
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(CodecError::Truncated(self.i))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn i64(&mut self) -> Result<i64, CodecError> {
        Ok(i64::from_le_bytes(self.arr()?))
    }
    /// `ReadCompactSize`: canonical encodings only, at most `MAX_SIZE`.
    fn compact(&mut self) -> Result<usize, CodecError> {
        let at = self.i;
        let first = self.take(1)?[0];
        let v: u64 = match first {
            0..=252 => u64::from(first),
            253 => {
                let v = u64::from(u16::from_le_bytes(self.arr()?));
                if v < 253 {
                    return Err(CodecError::NonCanonicalSize(at));
                }
                v
            }
            254 => {
                let v = u64::from(u32::from_le_bytes(self.arr()?));
                if v < 0x1_0000 {
                    return Err(CodecError::NonCanonicalSize(at));
                }
                v
            }
            255 => {
                let v = u64::from_le_bytes(self.arr()?);
                if v < 0x1_0000_0000 {
                    return Err(CodecError::NonCanonicalSize(at));
                }
                v
            }
        };
        if v > MAX_COMPACT_SIZE {
            return Err(CodecError::SizeTooLarge(v));
        }
        Ok(v as usize)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.compact()?;
        Ok(self.take(n)?.to_vec())
    }
    fn fixed_vec(&mut self, size: usize) -> Result<Vec<Vec<u8>>, CodecError> {
        let n = self.compact()?;
        // bound the allocation by what is actually there
        if n.saturating_mul(size) > self.b.len() - self.i {
            return Err(CodecError::Truncated(self.i));
        }
        (0..n)
            .map(|_| self.take(size).map(<[u8]>::to_vec))
            .collect()
    }
}

fn write_compact(out: &mut Vec<u8>, n: usize) {
    let n = n as u64;
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend((n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(254);
        out.extend((n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend(n.to_le_bytes());
    }
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_compact(out, b.len());
    out.extend_from_slice(b);
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

impl Transaction {
    /// A transparent-only Sapling v4 transaction, the shape every vault RPC builds.
    pub fn new_v4(
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u32,
        expiry_height: u32,
    ) -> Self {
        Transaction {
            overwintered: true,
            version: SAPLING_TX_VERSION,
            version_group_id: SAPLING_VERSION_GROUP_ID,
            inputs,
            outputs,
            lock_time,
            expiry_height,
            sapling: Some(SaplingBundle::default()),
            joinsplits: Some(JoinSplits {
                descriptions: vec![],
                pubkey: [0; 32],
                sig: [0; 64],
            }),
        }
    }

    pub fn format(&self) -> Result<Format, CodecError> {
        format_of(self.overwintered, self.version, self.version_group_id)
    }

    pub fn decode_hex(hex_str: &str) -> Result<Self, CodecError> {
        let b = hex::decode(hex_str.trim()).map_err(|e| CodecError::Hex(e.to_string()))?;
        Self::decode(&b)
    }

    /// Decode exactly `b` (trailing bytes are an error, as the node's `DecodeHexTx`).
    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader { b, i: 0 };
        let header = r.u32()?;
        let overwintered = header >> 31 == 1;
        let version = header & 0x7fff_ffff;
        let version_group_id = if overwintered { r.u32()? } else { 0 };
        let format = format_of(overwintered, version, version_group_id)?;

        let n_in = r.compact()?;
        let mut inputs = Vec::with_capacity(n_in.min(b.len() / 41));
        for _ in 0..n_in {
            let txid = Txid::from_internal(r.arr()?);
            let vout = r.u32()?;
            let script_sig = r.bytes()?;
            let sequence = r.u32()?;
            inputs.push(TxIn {
                prevout: OutPoint { txid, vout },
                script_sig,
                sequence,
            });
        }
        let n_out = r.compact()?;
        let mut outputs = Vec::with_capacity(n_out.min(b.len() / 9));
        for _ in 0..n_out {
            let value = r.i64()?;
            let script_pubkey = r.bytes()?;
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        let lock_time = r.u32()?;
        let expiry_height = match format {
            Format::OverwinterV3 | Format::SaplingV4 => r.u32()?,
            _ => 0,
        };
        let mut sapling = None;
        if format == Format::SaplingV4 {
            let value_balance = r.i64()?;
            let spends = r.fixed_vec(SPEND_DESCRIPTION_SIZE)?;
            let outputs = r.fixed_vec(OUTPUT_DESCRIPTION_SIZE)?;
            sapling = Some(SaplingBundle {
                value_balance,
                spends,
                outputs,
                binding_sig: None,
            });
        }
        let mut joinsplits = None;
        if version >= 2 {
            let groth = format == Format::SaplingV4;
            let descriptions: Vec<JoinSplit> = r
                .fixed_vec(joinsplit_size(groth))?
                .into_iter()
                .map(JoinSplit)
                .collect();
            let (pubkey, sig) = if descriptions.is_empty() {
                ([0; 32], [0; 64])
            } else {
                (r.arr()?, r.arr()?)
            };
            joinsplits = Some(JoinSplits {
                descriptions,
                pubkey,
                sig,
            });
        }
        if let Some(s) = sapling.as_mut()
            && !(s.spends.is_empty() && s.outputs.is_empty())
        {
            s.binding_sig = Some(r.arr()?);
        }
        if r.i != b.len() {
            return Err(CodecError::Trailing(b.len() - r.i));
        }
        Ok(Transaction {
            overwintered,
            version,
            version_group_id,
            inputs,
            outputs,
            lock_time,
            expiry_height,
            sapling,
            joinsplits,
        })
    }

    /// Serialize. A decoded transaction re-encodes to exactly the bytes it came from.
    pub fn encode(&self) -> Vec<u8> {
        let format = self
            .format()
            .expect("a Transaction is built with a known format");
        let mut out = Vec::with_capacity(256);
        let header = self.version | if self.overwintered { 1 << 31 } else { 0 };
        out.extend(header.to_le_bytes());
        if self.overwintered {
            out.extend(self.version_group_id.to_le_bytes());
        }
        write_compact(&mut out, self.inputs.len());
        for i in &self.inputs {
            out.extend(i.prevout.txid.0);
            out.extend(i.prevout.vout.to_le_bytes());
            write_bytes(&mut out, &i.script_sig);
            out.extend(i.sequence.to_le_bytes());
        }
        write_compact(&mut out, self.outputs.len());
        for o in &self.outputs {
            out.extend(o.value.to_le_bytes());
            write_bytes(&mut out, &o.script_pubkey);
        }
        out.extend(self.lock_time.to_le_bytes());
        if matches!(format, Format::OverwinterV3 | Format::SaplingV4) {
            out.extend(self.expiry_height.to_le_bytes());
        }
        let empty = SaplingBundle::default();
        let sapling =
            (format == Format::SaplingV4).then(|| self.sapling.as_ref().unwrap_or(&empty));
        if let Some(s) = sapling {
            out.extend(s.value_balance.to_le_bytes());
            write_compact(&mut out, s.spends.len());
            s.spends.iter().for_each(|d| out.extend(d));
            write_compact(&mut out, s.outputs.len());
            s.outputs.iter().for_each(|d| out.extend(d));
        }
        if self.version >= 2 {
            match &self.joinsplits {
                Some(js) if !js.descriptions.is_empty() => {
                    write_compact(&mut out, js.descriptions.len());
                    js.descriptions.iter().for_each(|d| out.extend(&d.0));
                    out.extend(js.pubkey);
                    out.extend(js.sig);
                }
                _ => write_compact(&mut out, 0),
            }
        }
        if let Some(s) = sapling
            && !(s.spends.is_empty() && s.outputs.is_empty())
        {
            out.extend(s.binding_sig.unwrap_or([0; 64]));
        }
        out
    }

    pub fn encode_hex(&self) -> String {
        hex::encode(self.encode())
    }

    /// SHA256d of the serialization (internal order; `Display` prints it the RPC way).
    pub fn txid(&self) -> Txid {
        Txid::from_internal(sha256d(&self.encode()))
    }

    /// Any Sprout or Sapling component (whose signatures would commit to the sighash).
    pub fn has_shielded(&self) -> bool {
        self.sapling
            .as_ref()
            .is_some_and(|s| !s.spends.is_empty() || !s.outputs.is_empty() || s.value_balance != 0)
            || self
                .joinsplits
                .as_ref()
                .is_some_and(|j| !j.descriptions.is_empty())
    }

    /// The single push of each `OP_RETURN` output: (vout, data).
    pub fn op_returns(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.outputs
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.op_return_data().map(|d| (i, d)))
    }

    /// Append `OP_RETURN <data>` (value 0) as the last output, under the rules of
    /// [`insert_op_return`].
    pub fn insert_op_return(&mut self, data: &[u8]) -> Result<usize, CodecError> {
        if data.is_empty() || data.len() > MAX_OP_RETURN_DATA {
            return Err(CodecError::DataSize(data.len()));
        }
        if let Some(i) = self.outputs.iter().position(TxOut::is_op_return) {
            return Err(CodecError::AlreadyHasOpReturn(i));
        }
        if let Some(i) = self.inputs.iter().position(TxIn::has_signature) {
            return Err(CodecError::InputSigned(i));
        }
        if self.has_shielded() {
            return Err(CodecError::Shielded);
        }
        self.outputs.push(TxOut::op_return(data));
        Ok(self.outputs.len() - 1)
    }
}

fn format_of(overwintered: bool, version: u32, group: u32) -> Result<Format, CodecError> {
    if !overwintered {
        return Ok(if version >= 2 {
            Format::SproutJoinSplit
        } else {
            Format::Sprout
        });
    }
    match (version, group) {
        (OVERWINTER_TX_VERSION, OVERWINTER_VERSION_GROUP_ID) => Ok(Format::OverwinterV3),
        (SAPLING_TX_VERSION, SAPLING_VERSION_GROUP_ID) => Ok(Format::SaplingV4),
        _ => Err(CodecError::UnknownFormat { version, group }),
    }
}

/// Insert Hawkeye's memo (or any data) as an `OP_RETURN` output into an **unsigned** transaction
/// in hex, as `vault_buildunlock` returns it (plan §3.2: until CR-N2 gives the RPC a `"data"`
/// parameter). The output is appended last, value 0, one minimal push of 1–80 bytes.
///
/// Refused when the transaction already has an `OP_RETURN` output (one per transaction is
/// standard: `multi-op-return`), when any input carries a signature (a set signature or a fee
/// input's signature commits to the outputs — SIGHASH_ALL — so the memo must go in before
/// `set_signunlock`; an empty scriptSig or a bare selector such as `OP_1` is not a signature), or
/// when the transaction has shielded components.
pub fn insert_op_return(tx_hex: &str, data: &[u8]) -> Result<String, CodecError> {
    let mut tx = Transaction::decode_hex(tx_hex)?;
    tx.insert_op_return(data)?;
    Ok(tx.encode_hex())
}

/// The txid of a raw transaction in hex.
pub fn txid_of_hex(tx_hex: &str) -> Result<Txid, CodecError> {
    Transaction::decode_hex(tx_hex).map(|t| t.txid())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> Transaction {
        let p = OutPoint::new(Txid::from_internal([7; 32]), 1);
        Transaction::new_v4(
            vec![TxIn {
                prevout: p,
                script_sig: vec![],
                sequence: u32::MAX,
            }],
            vec![TxOut {
                value: 5,
                script_pubkey: vec![0x51],
            }],
            0,
            0,
        )
    }

    #[test]
    fn empty_v4_layout() {
        let b = tx().encode();
        assert_eq!(&b[..8], &hex::decode("0400008085202f89").unwrap()[..]);
        // ... vin, vout, locktime 0, expiry 0, valueBalance 0, 0 spends, 0 outputs, 0 joinsplits
        assert_eq!(
            &b[b.len() - 19..],
            &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]
        );
        assert_eq!(Transaction::decode(&b).unwrap(), tx());
    }

    #[test]
    fn rejects_malformed() {
        let b = tx().encode();
        assert!(matches!(
            Transaction::decode(&b[..b.len() - 1]),
            Err(CodecError::Truncated(_))
        ));
        let mut t = b.clone();
        t.push(0);
        assert_eq!(Transaction::decode(&t), Err(CodecError::Trailing(1)));
        // vin count 1 as 0xfd 0x01 0x00: non-canonical
        let mut nc = b[..8].to_vec();
        nc.extend([0xfd, 0x01, 0x00]);
        nc.extend(&b[9..]);
        assert_eq!(
            Transaction::decode(&nc),
            Err(CodecError::NonCanonicalSize(8))
        );
        let mut unk = b.clone();
        unk[4] ^= 1;
        assert!(matches!(
            Transaction::decode(&unk),
            Err(CodecError::UnknownFormat { .. })
        ));
        let mut huge = b[..8].to_vec();
        huge.extend([0xfe, 0, 0, 0, 0x10]);
        assert_eq!(
            Transaction::decode(&huge),
            Err(CodecError::SizeTooLarge(0x1000_0000))
        );
        assert!(matches!(
            Transaction::decode_hex("zz"),
            Err(CodecError::Hex(_))
        ));
    }

    #[test]
    fn op_return_pushes() {
        for (n, prefix) in [
            (1usize, vec![0x6a, 1]),
            (75, vec![0x6a, 75]),
            (76, vec![0x6a, 0x4c, 76]),
            (80, vec![0x6a, 0x4c, 80]),
        ] {
            let d = vec![0xab; n];
            let o = TxOut::op_return(&d);
            assert_eq!(&o.script_pubkey[..prefix.len()], &prefix[..]);
            assert_eq!(o.op_return_data(), Some(&d[..]));
        }
        assert_eq!(
            TxOut {
                value: 0,
                script_pubkey: vec![0x6a]
            }
            .op_return_data(),
            None
        );
        assert_eq!(
            TxOut {
                value: 0,
                script_pubkey: vec![0x6a, 0x00]
            }
            .op_return_data(),
            Some(&[][..])
        );
        assert_eq!(
            TxOut {
                value: 0,
                script_pubkey: vec![0x6a, 2, 1]
            }
            .op_return_data(),
            None
        );
        assert_eq!(
            TxOut {
                value: 0,
                script_pubkey: vec![0x6a, 1, 1, 1]
            }
            .op_return_data(),
            None
        );
    }

    #[test]
    fn insert_rules() {
        let mut t = tx();
        assert_eq!(t.insert_op_return(&[]), Err(CodecError::DataSize(0)));
        assert_eq!(t.insert_op_return(&[0; 81]), Err(CodecError::DataSize(81)));
        assert_eq!(t.insert_op_return(b"HKB1"), Ok(1));
        assert_eq!(
            t.insert_op_return(b"HKB1"),
            Err(CodecError::AlreadyHasOpReturn(1))
        );
        let mut s = tx();
        s.inputs[0].script_sig = vec![0x51];
        assert_eq!(
            s.insert_op_return(b"x"),
            Ok(1),
            "a bare selector is not a signature"
        );
        let mut s = tx();
        s.inputs[0].script_sig = vec![0x02, 0xaa, 0xbb, 0x51];
        assert_eq!(s.insert_op_return(b"x"), Err(CodecError::InputSigned(0)));
        let mut s = tx();
        s.sapling.as_mut().unwrap().value_balance = 1;
        assert_eq!(s.insert_op_return(b"x"), Err(CodecError::Shielded));
    }
}
