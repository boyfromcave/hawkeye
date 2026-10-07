//! Script primitives: opcodes, `CScriptNum`, canonical pushes, op iteration, standard scripts.
//!
//! These follow `CScript` in the node exactly (and `test_framework/vault.py`, which the golden
//! vectors were written from): [`push`] is `CScript << std::vector<unsigned char>`,
//! [`push_int`] is `CScript << int64_t`, [`ops`] is `CScript::GetOp` over a whole script.

use crate::bytes::hash160;
use crate::error::{Error, Result};

/// `OP_0` / `OP_FALSE`.
pub const OP_0: u8 = 0x00;
/// One-byte length follows.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// Two-byte LE length follows.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// Four-byte LE length follows.
pub const OP_PUSHDATA4: u8 = 0x4e;
/// Pushes -1.
pub const OP_1NEGATE: u8 = 0x4f;
/// Not a push (it fails if executed).
pub const OP_RESERVED: u8 = 0x50;
/// Pushes 1.
pub const OP_1: u8 = 0x51;
/// Pushes 2.
pub const OP_2: u8 = 0x52;
/// Pushes 3.
pub const OP_3: u8 = 0x53;
/// Pushes 4.
pub const OP_4: u8 = 0x54;
/// Pushes 16.
pub const OP_16: u8 = 0x60;
/// `OP_IF`.
pub const OP_IF: u8 = 0x63;
/// `OP_ELSE`.
pub const OP_ELSE: u8 = 0x67;
/// `OP_ENDIF`.
pub const OP_ENDIF: u8 = 0x68;
/// `OP_VERIFY`.
pub const OP_VERIFY: u8 = 0x69;
/// `OP_RETURN`.
pub const OP_RETURN: u8 = 0x6a;
/// `OP_2DROP`.
pub const OP_2DROP: u8 = 0x6d;
/// `OP_DROP`.
pub const OP_DROP: u8 = 0x75;
/// `OP_DUP`.
pub const OP_DUP: u8 = 0x76;
/// `OP_EQUAL`.
pub const OP_EQUAL: u8 = 0x87;
/// `OP_EQUALVERIFY`.
pub const OP_EQUALVERIFY: u8 = 0x88;
/// `OP_HASH160`.
pub const OP_HASH160: u8 = 0xa9;
/// `OP_CHECKSIG`.
pub const OP_CHECKSIG: u8 = 0xac;
/// `OP_CHECKLOCKTIMEVERIFY` (BIP65).
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
/// `OP_CHECKSEQUENCEVERIFY` (BIP112's byte; `OP_NOP3` before the vault upgrade).
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
/// `OP_CHECKSETSIG` (upgrade plan §15.2).
pub const OP_CHECKSETSIG: u8 = 0xc0;
/// `OP_CHECKSETDORMANT` (upgrade plan §15.2).
pub const OP_CHECKSETDORMANT: u8 = 0xc1;

/// The default maximum size of a script number operand (`CScriptNum`'s `nMaxNumSize`).
pub const DEFAULT_MAX_NUM_SIZE: usize = 5;

/// `CScriptNum::serialize`: minimal little-endian sign-magnitude; 0 is the empty vector.
pub fn script_num_encode(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut a = n.unsigned_abs();
    let mut out = Vec::with_capacity(9);
    while a != 0 {
        out.push((a & 0xff) as u8);
        a >>= 8;
    }
    let last = *out.last().expect("non-zero has a byte");
    if last & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().expect("non-empty") |= 0x80;
    }
    out
}

/// `CScriptNum(vch, fRequireMinimal = true, max_size)`: the value, or an error if `b` is longer
/// than `max_size` (at most 8) or not minimally encoded.
pub fn script_num_decode(b: &[u8], max_size: usize) -> Result<i64> {
    if b.len() > max_size || b.len() > 8 {
        return Err(Error::Script("script number too long"));
    }
    let Some(&last) = b.last() else {
        return Ok(0);
    };
    if last & 0x7f == 0 && (b.len() <= 1 || b[b.len() - 2] & 0x80 == 0) {
        return Err(Error::Script("non-minimal script number"));
    }
    let mut v: u64 = 0;
    for (i, byte) in b.iter().enumerate() {
        v |= u64::from(*byte) << (8 * i);
    }
    if last & 0x80 != 0 {
        let mask = !(0x80u64 << (8 * (b.len() - 1)));
        Ok(-((v & mask) as i64))
    } else {
        Ok(v as i64)
    }
}

/// The canonical (smallest) push of `data`, appended to `out`.
pub fn push_to(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < usize::from(OP_PUSHDATA1) {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[OP_PUSHDATA1, n as u8]);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// The canonical push of `data` (`CScript << std::vector<unsigned char>`).
pub fn push(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    push_to(&mut out, data);
    out
}

/// `CScript << int64_t`, appended to `out`: `OP_0`, `OP_1NEGATE`, `OP_1`..`OP_16`, else the
/// minimal `CScriptNum` push.
pub fn push_int_to(out: &mut Vec<u8>, n: i64) {
    match n {
        0 => out.push(OP_0),
        -1 => out.push(OP_1NEGATE),
        1..=16 => out.push(OP_1 + (n as u8) - 1),
        _ => push_to(out, &script_num_encode(n)),
    }
}

/// `CScript << int64_t`.
pub fn push_int(n: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    push_int_to(&mut out, n);
    out
}

/// One decoded operation: the opcode byte as written (so a non-minimal push is visible) and,
/// for a data push (`0x00..=OP_PUSHDATA4`), its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Op<'a> {
    /// The opcode byte that introduced the operation.
    pub opcode: u8,
    /// The pushed bytes for `0x00..=OP_PUSHDATA4`, `None` for every other opcode.
    pub data: Option<&'a [u8]>,
}

impl<'a> Op<'a> {
    /// The value this op pushes on the stack: a data push's bytes, `OP_1NEGATE` → `0x81`,
    /// `OP_1..OP_16` → `1..16`; `None` for a non-push (including `OP_RESERVED`).
    pub fn push_value(&self) -> Option<std::borrow::Cow<'a, [u8]>> {
        use std::borrow::Cow;
        match (self.data, self.opcode) {
            (Some(d), _) => Some(Cow::Borrowed(d)),
            (None, OP_1NEGATE) => Some(Cow::Owned(vec![0x81])),
            (None, op @ OP_1..=OP_16) => Some(Cow::Owned(vec![op - OP_1 + 1])),
            _ => None,
        }
    }

    /// The small integer this op denotes when written by [`push_int`]: `OP_0` → 0,
    /// `OP_1NEGATE` → -1, `OP_n` → n, a data push → its `CScriptNum` (minimal, at most
    /// `max_size` bytes). Minimality of the *form* (a data push of 5 instead of `OP_5`) is not
    /// checked here; template parsers rebuild and compare bytes.
    pub fn script_num(&self, max_size: usize) -> Result<i64> {
        match (self.data, self.opcode) {
            (Some(d), _) => script_num_decode(d, max_size),
            (None, OP_1NEGATE) => Ok(-1),
            (None, op @ OP_1..=OP_16) => Ok(i64::from(op - OP_1 + 1)),
            _ => Err(Error::Script("not a number push")),
        }
    }
}

/// An iterator over a script's operations (`CScript::GetOp`). Yields an error, once, for a push
/// that runs past the end of the script, then stops.
#[derive(Debug, Clone)]
pub struct Ops<'a> {
    script: &'a [u8],
    pos: usize,
    failed: bool,
}

/// Iterate over the operations of `script`.
pub fn ops(script: &[u8]) -> Ops<'_> {
    Ops {
        script,
        pos: 0,
        failed: false,
    }
}

impl<'a> Iterator for Ops<'a> {
    type Item = Result<Op<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.script.len() {
            return None;
        }
        let s = self.script;
        let op = s[self.pos];
        self.pos += 1;
        if op > OP_PUSHDATA4 {
            return Some(Ok(Op {
                opcode: op,
                data: None,
            }));
        }
        let mut read_len = |width: usize| -> Option<usize> {
            let end = self.pos.checked_add(width)?;
            let b = s.get(self.pos..end)?;
            self.pos = end;
            let mut v = 0usize;
            for (i, byte) in b.iter().enumerate() {
                v |= usize::from(*byte) << (8 * i);
            }
            Some(v)
        };
        let size = match op {
            OP_PUSHDATA1 => read_len(1),
            OP_PUSHDATA2 => read_len(2),
            OP_PUSHDATA4 => read_len(4),
            n => Some(usize::from(n)),
        };
        let data = size
            .and_then(|size| self.pos.checked_add(size))
            .and_then(|end| s.get(self.pos..end).map(|d| (d, end)));
        match data {
            Some((d, end)) => {
                self.pos = end;
                Some(Ok(Op {
                    opcode: op,
                    data: Some(d),
                }))
            }
            None => {
                self.failed = true;
                Some(Err(Error::Script("push past end of script")))
            }
        }
    }
}

/// All operations of `script`, or an error if a push runs past the end.
pub fn get_ops(script: &[u8]) -> Result<Vec<Op<'_>>> {
    ops(script).collect()
}

/// The stack values of a push-only script (`IsPushOnly`, `OP_RESERVED` excluded).
pub fn push_values(script: &[u8]) -> Result<Vec<Vec<u8>>> {
    ops(script)
        .map(|op| {
            op?.push_value()
                .map(|v| v.into_owned())
                .ok_or(Error::Script("not push-only"))
        })
        .collect()
}

/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[OP_DUP, OP_HASH160, 20]);
    s.extend_from_slice(hash);
    s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    s
}

/// `OP_HASH160 <20> OP_EQUAL`.
pub fn p2sh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.extend_from_slice(&[OP_HASH160, 20]);
    s.extend_from_slice(hash);
    s.push(OP_EQUAL);
    s
}

/// The P2SH scriptPubKey of a redeem script.
pub fn p2sh_of(redeem: &[u8]) -> Vec<u8> {
    p2sh_script(&hash160(redeem))
}

/// The hash of an exact P2PKH scriptPubKey.
pub fn parse_p2pkh(spk: &[u8]) -> Option<[u8; 20]> {
    if spk.len() == 25
        && spk[..3] == [OP_DUP, OP_HASH160, 20]
        && spk[23..] == [OP_EQUALVERIFY, OP_CHECKSIG]
    {
        spk[3..23].try_into().ok()
    } else {
        None
    }
}

/// The hash of an exact P2SH scriptPubKey.
pub fn parse_p2sh(spk: &[u8]) -> Option<[u8; 20]> {
    if spk.len() == 23 && spk[..2] == [OP_HASH160, 20] && spk[22] == OP_EQUAL {
        spk[2..22].try_into().ok()
    } else {
        None
    }
}

/// `OP_RETURN <data>` with the canonical push.
pub fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut s = vec![OP_RETURN];
    push_to(&mut s, data);
    s
}

/// True if `spk` begins with `OP_RETURN` (a provably unspendable data carrier).
pub fn is_op_return(spk: &[u8]) -> bool {
    spk.first() == Some(&OP_RETURN)
}

/// The data of an `OP_RETURN` carrying exactly one canonical push and nothing else, or `None`.
pub fn op_return_single_push(spk: &[u8]) -> Option<&[u8]> {
    if !is_op_return(spk) {
        return None;
    }
    let mut it = ops(&spk[1..]);
    let data = it.next()?.ok()?.data?;
    if it.next().is_some() || op_return_script(data) != spk {
        return None;
    }
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_num_round_trip() {
        let cases: &[(i64, &str)] = &[
            (0, ""),
            (1, "01"),
            (-1, "81"),
            (127, "7f"),
            (128, "8000"),
            (-128, "8080"),
            (255, "ff00"),
            (256, "0001"),
            (1000, "e803"),
            (65535, "ffff00"),
            (499_999_999, "ff64cd1d"),
            (0x7fff_ffff, "ffffff7f"),
            (0x8000_0000, "0000008000"),
            (-0x8000_0000, "0000008080"),
        ];
        for (n, h) in cases {
            assert_eq!(hex::encode(script_num_encode(*n)), *h, "{n}");
            assert_eq!(
                script_num_decode(&hex::decode(h).unwrap(), 5).unwrap(),
                *n,
                "{n}"
            );
        }
        assert_eq!(
            script_num_decode(&script_num_encode(i64::MAX), 8).unwrap(),
            i64::MAX
        );
        assert_eq!(
            script_num_decode(&[1; 9], 9).unwrap_err(),
            Error::Script("script number too long")
        );
        assert_eq!(
            script_num_decode(&script_num_encode(-0x7f_ffff_ffff_ffff), 8).unwrap(),
            -0x7f_ffff_ffff_ffff
        );
    }

    #[test]
    fn script_num_rejects_non_minimal_and_long() {
        for h in ["00", "80", "0100", "ff0000", "0080"] {
            assert!(
                script_num_decode(&hex::decode(h).unwrap(), 5).is_err(),
                "{h}"
            );
        }
        assert!(script_num_decode(&[1, 2, 3, 4, 5, 6], 5).is_err());
        assert!(script_num_decode(&[1, 2, 3, 4, 5, 6], 6).is_ok());
    }

    #[test]
    fn push_forms() {
        assert_eq!(push(&[]), vec![0x00]);
        assert_eq!(push(&[7; 75])[0], 75);
        assert_eq!(&push(&[7; 76])[..2], &[OP_PUSHDATA1, 76]);
        assert_eq!(&push(&[7; 256])[..3], &[OP_PUSHDATA2, 0, 1]);
        assert_eq!(&push(&vec![7; 65536])[..5], &[OP_PUSHDATA4, 0, 0, 1, 0]);
        assert_eq!(push_int(0), vec![OP_0]);
        assert_eq!(push_int(-1), vec![OP_1NEGATE]);
        assert_eq!(push_int(16), vec![OP_16]);
        assert_eq!(push_int(17), vec![1, 17]);
        assert_eq!(push_int(-2), vec![1, 0x82]);
        assert_eq!(push_int(144), vec![2, 0x90, 0x00]);
    }

    #[test]
    fn op_iteration() {
        let mut s = push(&[1, 2, 3]);
        s.push(OP_DUP);
        s.extend_from_slice(&push(&[9; 80]));
        s.push(OP_5_FOR_TEST);
        let ops = get_ops(&s).unwrap();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].data, Some(&[1u8, 2, 3][..]));
        assert_eq!(ops[1].opcode, OP_DUP);
        assert_eq!(ops[2].opcode, OP_PUSHDATA1);
        assert_eq!(ops[3].script_num(5).unwrap(), 5);
        // truncated pushes in every width
        for bad in [
            &[0x05, 1, 2][..],
            &[OP_PUSHDATA1],
            &[OP_PUSHDATA2, 1],
            &[OP_PUSHDATA4, 1, 0, 0, 0],
        ] {
            assert!(get_ops(bad).is_err());
        }
        assert_eq!(get_ops(&[]).unwrap().len(), 0);
        assert_eq!(
            push_values(&[OP_1NEGATE, OP_16, 0]).unwrap(),
            vec![vec![0x81], vec![16], vec![]]
        );
        assert!(push_values(&[OP_RESERVED]).is_err());
        assert!(push_values(&[OP_DUP]).is_err());
    }

    const OP_5_FOR_TEST: u8 = 0x55;

    #[test]
    fn standard_scripts() {
        let h = [0x11; 20];
        assert_eq!(parse_p2pkh(&p2pkh_script(&h)), Some(h));
        assert_eq!(parse_p2sh(&p2sh_script(&h)), Some(h));
        assert_eq!(parse_p2pkh(&p2sh_script(&h)), None);
        assert_eq!(parse_p2sh(&p2pkh_script(&h)), None);
        let r = op_return_script(&[0xab; 32]);
        assert_eq!(&r[..2], &[OP_RETURN, 32]);
        assert_eq!(op_return_single_push(&r), Some(&[0xab; 32][..]));
        // two pushes, a non-canonical push, or no OP_RETURN are not single-push carriers
        let mut two = r.clone();
        two.extend_from_slice(&push(&[1]));
        assert_eq!(op_return_single_push(&two), None);
        let mut nc = vec![OP_RETURN, OP_PUSHDATA1, 32];
        nc.extend_from_slice(&[0xab; 32]);
        assert_eq!(op_return_single_push(&nc), None);
        assert_eq!(op_return_single_push(&r[1..]), None);
        assert_eq!(op_return_single_push(&[OP_RETURN]), None);
    }
}
