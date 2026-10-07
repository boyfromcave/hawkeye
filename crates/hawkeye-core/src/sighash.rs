//! Transparent signature hashing for Overwinter v3 (ZIP-143) and Sapling v4 (ZIP-243)
//! transactions: a port of ycash-dd `src/script/interpreter.cpp` `SignatureHash` (the
//! overwintered branch) and its `Get*Hash` helpers.
//!
//! The set signatures of the vault primitive sign `SetSigMsg(…, sighash)` with
//! `sighash = SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL, amount, consensusBranchId)`
//! (upgrade plan §15.2 step 4); for a bare V or I output the `scriptCode` is the whole prev
//! scriptPubKey (the templates have no `OP_CODESEPARATOR`).
//!
//! The result is the 32 BLAKE2b output bytes, which are the node's `uint256` in internal byte
//! order (what `SetSigMsg` hashes); `uint256::GetHex()` prints them reversed.

use blake2b_simd::Params;

use crate::bytes::Hash32;
use crate::error::{Error, Result};
use crate::tx::{SPEND_HASHED_LEN, Transaction, TxFormat, write_bytes};

/// `SIGHASH_ALL`.
pub const SIGHASH_ALL: u32 = 1;
/// `SIGHASH_NONE`.
pub const SIGHASH_NONE: u32 = 2;
/// `SIGHASH_SINGLE`.
pub const SIGHASH_SINGLE: u32 = 3;
/// `SIGHASH_ANYONECANPAY` (a flag on the others).
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

const PREVOUTS: &[u8; 16] = b"ZcashPrevoutHash";
const SEQUENCE: &[u8; 16] = b"ZcashSequencHash";
const OUTPUTS: &[u8; 16] = b"ZcashOutputsHash";
const JOINSPLITS: &[u8; 16] = b"ZcashJSplitsHash";
const SPENDS: &[u8; 16] = b"ZcashSSpendsHash";
const SHIELDED_OUTPUTS: &[u8; 16] = b"ZcashSOutputHash";

fn blake2b(personal: &[u8; 16], data: &[u8]) -> Hash32 {
    let h = Params::new().hash_length(32).personal(personal).hash(data);
    h.as_bytes().try_into().expect("32-byte BLAKE2b")
}

fn prevouts_hash(tx: &Transaction) -> Hash32 {
    let mut d = Vec::with_capacity(36 * tx.vin.len());
    for i in &tx.vin {
        d.extend_from_slice(&i.prevout.to_bytes());
    }
    blake2b(PREVOUTS, &d)
}

fn sequence_hash(tx: &Transaction) -> Hash32 {
    let mut d = Vec::with_capacity(4 * tx.vin.len());
    for i in &tx.vin {
        d.extend_from_slice(&i.sequence.to_le_bytes());
    }
    blake2b(SEQUENCE, &d)
}

fn outputs_hash(outs: &[crate::tx::TxOut]) -> Hash32 {
    let mut d = Vec::new();
    for o in outs {
        d.extend_from_slice(&o.to_bytes());
    }
    blake2b(OUTPUTS, &d)
}

fn joinsplits_hash(tx: &Transaction) -> Hash32 {
    let mut d = Vec::with_capacity(tx.joinsplit_len() * tx.joinsplits.len() + 32);
    for js in &tx.joinsplits {
        d.extend_from_slice(js);
    }
    d.extend_from_slice(&tx.joinsplit_pubkey.unwrap_or_default());
    blake2b(JOINSPLITS, &d)
}

fn spends_hash(tx: &Transaction) -> Hash32 {
    let mut d = Vec::with_capacity(SPEND_HASHED_LEN * tx.shielded_spends.len());
    for s in &tx.shielded_spends {
        // cv ‖ anchor ‖ nullifier ‖ rk ‖ zkproof — not spendAuthSig
        d.extend_from_slice(&s[..SPEND_HASHED_LEN]);
    }
    blake2b(SPENDS, &d)
}

fn shielded_outputs_hash(tx: &Transaction) -> Hash32 {
    blake2b(SHIELDED_OUTPUTS, &tx.shielded_outputs.concat())
}

/// `SignatureHash(scriptCode, tx, nIn, hashType, amount, consensusBranchId)` for a v4 (ZIP-243)
/// or v3 (ZIP-143, chosen by the transaction's format) transaction, for transparent input
/// `input_index`. `hash_type` is the full 32-bit value hashed (the node's `int nHashType`);
/// its low five bits and [`SIGHASH_ANYONECANPAY`] select what is committed, exactly as the node
/// does (any other low-bits value behaves as [`SIGHASH_ALL`]). With [`SIGHASH_SINGLE`] and no
/// output at `input_index`, `hashOutputs` is zero (no error, unlike Sprout).
///
/// Fails only for an `input_index` with no input.
pub fn zip243(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount_zat: u64,
    hash_type: u32,
    branch_id: u32,
) -> Result<Hash32> {
    let input = tx
        .vin
        .get(input_index)
        .ok_or(Error::Tx("input index out of range"))?;
    let anyone = hash_type & SIGHASH_ANYONECANPAY != 0;
    let base = hash_type & 0x1f;
    let zero = [0u8; 32];

    let hash_prevouts = if anyone { zero } else { prevouts_hash(tx) };
    let hash_sequence = if !anyone && base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        sequence_hash(tx)
    } else {
        zero
    };
    let hash_outputs = if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        outputs_hash(&tx.vout)
    } else if base == SIGHASH_SINGLE && input_index < tx.vout.len() {
        outputs_hash(&tx.vout[input_index..=input_index])
    } else {
        zero
    };
    let hash_joinsplits = if tx.joinsplits.is_empty() {
        zero
    } else {
        joinsplits_hash(tx)
    };
    let sapling = tx.format == TxFormat::SaplingV4;

    let mut d = Vec::with_capacity(256 + script_code.len());
    d.extend_from_slice(&tx.header().to_le_bytes());
    d.extend_from_slice(&tx.version_group_id().to_le_bytes());
    d.extend_from_slice(&hash_prevouts);
    d.extend_from_slice(&hash_sequence);
    d.extend_from_slice(&hash_outputs);
    d.extend_from_slice(&hash_joinsplits);
    if sapling {
        d.extend_from_slice(&if tx.shielded_spends.is_empty() {
            zero
        } else {
            spends_hash(tx)
        });
        d.extend_from_slice(&if tx.shielded_outputs.is_empty() {
            zero
        } else {
            shielded_outputs_hash(tx)
        });
    }
    d.extend_from_slice(&tx.lock_time.to_le_bytes());
    d.extend_from_slice(&tx.expiry_height.to_le_bytes());
    if sapling {
        d.extend_from_slice(&tx.value_balance.to_le_bytes());
    }
    d.extend_from_slice(&hash_type.to_le_bytes());
    d.extend_from_slice(&input.prevout.to_bytes());
    write_bytes(&mut d, script_code);
    d.extend_from_slice(&amount_zat.to_le_bytes());
    d.extend_from_slice(&input.sequence.to_le_bytes());

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashSigHash");
    personal[12..].copy_from_slice(&branch_id.to_le_bytes());
    Ok(blake2b(&personal, &d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personalisation_known_answer() {
        // BLAKE2b-256("", personal "ZcashPrevoutHash"): hashPrevouts of no inputs;
        // checks the length and personalisation plumbing.
        let h = blake2b(PREVOUTS, b"");
        assert_eq!(
            hex::encode(h),
            "d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136"
        );
    }

    #[test]
    fn input_out_of_range() {
        let tx = Transaction::parse(
            &hex::decode("0400008085202f89000000000000000000000000000000000000000000").unwrap(),
        )
        .unwrap();
        assert!(zip243(&tx, 0, &[], 0, SIGHASH_ALL, 0).is_err());
    }
}
