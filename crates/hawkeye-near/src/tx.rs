//! NEAR transactions, hand-rolled Borsh (NEAR plan NH4): the subset Hawkeye sends — a
//! `TransactionV0` of `FunctionCall` (and `Transfer`) actions signed with an ed25519 access key.
//!
//! ```text
//! TransactionV0   = signer_id: String ‖ public_key: PublicKey ‖ nonce: u64 ‖ receiver_id: String
//!                   ‖ block_hash: [u8; 32] ‖ actions: Vec<Action>
//! PublicKey       = 0u8 (ED25519) ‖ [u8; 32]
//! Action          = 2u8 FunctionCall { method_name: String, args: Vec<u8>, gas: u64, deposit: u128 }
//!                 | 3u8 Transfer { deposit: u128 }
//! SignedTransaction = TransactionV0 ‖ Signature (0u8 ‖ [u8; 64])
//! hash            = SHA256(borsh(TransactionV0)),  signature = ed25519(hash)
//! ```
//!
//! `near-primitives`' `Transaction::V0` serialises with no version byte (a `V1` starts with byte
//! `1`, which a `V0`'s `u32` length can never begin with on the wire), so a `V0` is accepted by
//! every protocol version Hawkeye targets. The encoding is checked byte for byte against
//! transactions built and signed by `near-primitives` 0.37.4 itself (`near/tests/tx_vectors.rs`
//! writes `crates/hawkeye-near/tests/data/tx_vectors.json`; `tests/codec.rs` reads it) and against
//! the `borsh` crate's derive.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hawkeye_core::AccountId;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The `KeyType::ED25519` tag of a public key and a signature.
pub const ED25519: u8 = 0;
/// Borsh index of `Action::FunctionCall`.
pub const ACTION_FUNCTION_CALL: u8 = 2;
/// Borsh index of `Action::Transfer`.
pub const ACTION_TRANSFER: u8 = 3;
/// 1 TGas.
pub const TGAS: u64 = 1_000_000_000_000;

/// A `FunctionCall` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall {
    /// The method.
    pub method_name: String,
    /// The arguments (JSON bytes for `near-sdk` contracts).
    pub args: Vec<u8>,
    /// Gas attached.
    pub gas: u64,
    /// yoctoNEAR attached.
    pub deposit: u128,
}

/// The actions Hawkeye sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Call a contract method.
    FunctionCall(FunctionCall),
    /// Send yoctoNEAR.
    Transfer {
        /// yoctoNEAR.
        deposit: u128,
    },
}

/// A `TransactionV0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The account that signs (and pays).
    pub signer_id: AccountId,
    /// The ed25519 access key that signs.
    pub public_key: [u8; 32],
    /// The access key's nonce (strictly above its current one).
    pub nonce: u64,
    /// The receiving account (the contract).
    pub receiver_id: AccountId,
    /// A recent block's hash (the transaction expires ~a day of blocks later).
    pub block_hash: [u8; 32],
    /// The actions, in order.
    pub actions: Vec<Action>,
}

/// A signed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The transaction.
    pub transaction: Transaction,
    /// ed25519 over [`Transaction::hash`].
    pub signature: [u8; 64],
}

// ------------------------------------------------------------------------------------- writer

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, u32::try_from(b.len()).expect("under 4 GiB"));
    out.extend_from_slice(b);
}

impl Action {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Action::FunctionCall(f) => {
                out.push(ACTION_FUNCTION_CALL);
                put_bytes(out, f.method_name.as_bytes());
                put_bytes(out, &f.args);
                out.extend_from_slice(&f.gas.to_le_bytes());
                out.extend_from_slice(&f.deposit.to_le_bytes());
            }
            Action::Transfer { deposit } => {
                out.push(ACTION_TRANSFER);
                out.extend_from_slice(&deposit.to_le_bytes());
            }
        }
    }
}

impl Transaction {
    /// `borsh(TransactionV0)`.
    pub fn borsh(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        put_bytes(&mut out, self.signer_id.as_bytes());
        out.push(ED25519);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        put_bytes(&mut out, self.receiver_id.as_bytes());
        out.extend_from_slice(&self.block_hash);
        put_u32(
            &mut out,
            u32::try_from(self.actions.len()).expect("few actions"),
        );
        for a in &self.actions {
            a.write(&mut out);
        }
        out
    }

    /// `SHA256(borsh(self))`: the transaction hash (what is signed, and the id RPC reports).
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.borsh()).into()
    }

    /// Sign with `key`, whose public key must be [`Transaction::public_key`].
    pub fn sign(self, key: &SigningKey) -> Result<SignedTransaction> {
        if key.verifying_key().to_bytes() != self.public_key {
            return Err(Error::Key(
                "the signing key is not the transaction's public key".into(),
            ));
        }
        let signature = key.sign(&self.hash()).to_bytes();
        Ok(SignedTransaction {
            transaction: self,
            signature,
        })
    }

    /// Parse a `TransactionV0` from the front of `b`; returns it and the bytes it used.
    pub fn decode_prefix(b: &[u8]) -> Result<(Self, usize)> {
        let mut r = Reader { b, at: 0 };
        let signer_id = r.account()?;
        r.key_type()?;
        let public_key = r.array::<32>()?;
        let nonce = r.u64()?;
        let receiver_id = r.account()?;
        let block_hash = r.array::<32>()?;
        let n = r.u32()?;
        let mut actions = Vec::new();
        for _ in 0..n {
            actions.push(match r.u8()? {
                ACTION_FUNCTION_CALL => {
                    let method_name = String::from_utf8(r.bytes()?.to_vec())
                        .map_err(|_| Error::Decode("method name is not UTF-8".into()))?;
                    let args = r.bytes()?.to_vec();
                    let gas = r.u64()?;
                    let deposit = r.u128()?;
                    Action::FunctionCall(FunctionCall {
                        method_name,
                        args,
                        gas,
                        deposit,
                    })
                }
                ACTION_TRANSFER => Action::Transfer { deposit: r.u128()? },
                other => return Err(Error::Decode(format!("unsupported action {other}"))),
            });
        }
        Ok((
            Self {
                signer_id,
                public_key,
                nonce,
                receiver_id,
                block_hash,
                actions,
            },
            r.at,
        ))
    }
}

impl SignedTransaction {
    /// `borsh(SignedTransaction)`: what `send_tx` takes (base64).
    pub fn borsh(&self) -> Vec<u8> {
        let mut out = self.transaction.borsh();
        out.push(ED25519);
        out.extend_from_slice(&self.signature);
        out
    }

    /// The transaction hash.
    pub fn hash(&self) -> [u8; 32] {
        self.transaction.hash()
    }

    /// Parse the exact bytes of a signed transaction.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let (transaction, used) = Transaction::decode_prefix(b)?;
        let mut r = Reader { b, at: used };
        r.key_type()?;
        let signature = r.array::<64>()?;
        if r.at != b.len() {
            return Err(Error::Decode("trailing bytes after the signature".into()));
        }
        Ok(Self {
            transaction,
            signature,
        })
    }

    /// Whether the signature verifies under the transaction's public key.
    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.transaction.public_key) else {
            return false;
        };
        vk.verify(
            &self.hash(),
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

// ------------------------------------------------------------------------------------- reader

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.b.len())
            .ok_or_else(|| Error::Decode("truncated transaction".into()))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn account(&mut self) -> Result<AccountId> {
        AccountId::from_bytes(self.bytes()?).map_err(|e| Error::Decode(format!("account id: {e}")))
    }

    fn key_type(&mut self) -> Result<()> {
        match self.u8()? {
            ED25519 => Ok(()),
            other => Err(Error::Decode(format!("key type {other} is not ED25519"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Transaction {
        Transaction {
            signer_id: AccountId::parse("relayer.test.near").unwrap(),
            public_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
            nonce: 7,
            receiver_id: AccountId::parse("wyec.test.near").unwrap(),
            block_hash: [9; 32],
            actions: vec![
                Action::FunctionCall(FunctionCall {
                    method_name: "execute_mint".into(),
                    args: br#"{"lock_id":"00"}"#.to_vec(),
                    gas: 100 * TGAS,
                    deposit: 1,
                }),
                Action::Transfer { deposit: 5 },
            ],
        }
    }

    #[test]
    fn round_trip_and_signature() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let signed = sample().sign(&key).unwrap();
        assert!(signed.verify());
        let bytes = signed.borsh();
        assert_eq!(SignedTransaction::decode(&bytes).unwrap(), signed);
        // a flipped byte breaks the signature (or the decoding)
        let mut bad = bytes.clone();
        let n = bad.len() - 70;
        bad[n] ^= 1;
        assert!(
            SignedTransaction::decode(&bad).is_ok_and(|t| !t.verify())
                || SignedTransaction::decode(&bad).is_err()
        );
        // trailing and truncated bytes are refused
        let mut long = bytes.clone();
        long.push(0);
        assert!(SignedTransaction::decode(&long).is_err());
        assert!(SignedTransaction::decode(&bytes[..bytes.len() - 1]).is_err());
        // another key cannot sign it
        assert!(sample().sign(&SigningKey::from_bytes(&[4; 32])).is_err());
    }
}
