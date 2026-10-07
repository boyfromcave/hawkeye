//! Sign-once records (plan §3.5, HK-7; AGENTS.md rule 7).
//!
//! Two record kinds:
//!
//! - **EIP-712 `Mint`** (`eip712-mint`), keyed by `lockId`: one `(amount, to, digest)` ever.
//!   Hawkeye signs these itself, so this record *is* the guard.
//! - **Ycash set and act signatures** (`ycash-unlock`, `ycash-cancel`, `ycash-act`), keyed by
//!   `(domain, setId, prevout)`: the transaction the node built and the signed bytes it
//!   returned. The node's own guard (upgrade finding (70)) protects the key; this record mirrors
//!   it so a retry re-sends the signed bytes instead of re-building (a rebuilt transaction may
//!   pick other fee inputs, and a second signature over a different spend of one outpoint is
//!   equivocation, §2.3).
//!
//! The signer runs inside the ledger transaction: the record commits before the signature is
//! returned, so a signature never leaves the process unrecorded. If the signer fails nothing is
//! recorded; if the commit fails the signature is dropped (and was never released).

use hawkeye_core::bytes::Hash32;
use hawkeye_core::{EthAddress, OutPoint};
use rusqlite::params;

use crate::state::{LockState, SignDomain};
use crate::{Result, SignerError, StoreError, Tx, hx};

/// A stored EIP-712 `Mint` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintSignRecord {
    /// The `lockId`.
    pub lock_id: Hash32,
    /// The signed amount (zatoshi = wYEC base units).
    pub amount: u64,
    /// The signed recipient.
    pub to: EthAddress,
    /// The EIP-712 digest signed.
    pub digest: Hash32,
    /// The 65-byte `r ‖ s ‖ v` signature.
    pub signature: [u8; 65],
    /// Unix seconds.
    pub signed_at: i64,
}

/// The key of a Ycash sign-once record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct YcashSignKey {
    /// `ycash-unlock`, `ycash-cancel` or `ycash-act`.
    pub domain: SignDomain,
    /// The set signed for.
    pub set_id: Hash32,
    /// The outpoint the signature commits to (the vault for an unlock, the intent for a cancel,
    /// the act's prevout for an act).
    pub prevout: OutPoint,
}

/// A stored Ycash signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YcashSignRecord {
    /// The key.
    pub key: YcashSignKey,
    /// The sighash (or act message) the node reported signing.
    pub sighash: Hash32,
    /// The unsigned transaction / act hex the node built.
    pub built_hex: String,
    /// The signed hex the node returned: what is (re-)broadcast.
    pub signed_hex: String,
    /// Unix seconds.
    pub signed_at: i64,
}

fn key_id(k: &YcashSignKey) -> String {
    format!("{}/{}", hx(&k.set_id), k.prevout)
}

impl Tx<'_> {
    /// Sign `Mint(lockId, amount, to)` at most once.
    ///
    /// - First call: the lock must be stored, `POLICY_OK`, with this `amount` (its value) and
    ///   `to` (its destination); `sign(digest)` is called, the record stored and the lock moved
    ///   `POLICY_OK → SIGNED`, all in this transaction.
    /// - Identical later call (same `amount`, `to`, `digest`): the stored record, `sign` is not
    ///   called.
    /// - Any difference: [`StoreError::SignOnceConflict`], `sign` is not called.
    pub fn sign_once_mint<F, E>(
        &self,
        lock_id: &Hash32,
        amount: u64,
        to: &EthAddress,
        digest: &Hash32,
        sign: F,
    ) -> Result<MintSignRecord>
    where
        F: FnOnce(&Hash32) -> core::result::Result<[u8; 65], E>,
        E: Into<SignerError>,
    {
        if let Some(old) = self.mint_signature(lock_id)? {
            let mut diffs = Vec::new();
            if old.amount != amount {
                diffs.push(format!("amount {} != stored {}", amount, old.amount));
            }
            if old.to != *to {
                diffs.push(format!("to {} != stored {}", to, old.to));
            }
            if old.digest != *digest {
                diffs.push(format!(
                    "digest {} != stored {}",
                    hx(digest),
                    hx(&old.digest)
                ));
            }
            return if diffs.is_empty() {
                Ok(old)
            } else {
                Err(StoreError::SignOnceConflict {
                    domain: SignDomain::Eip712Mint.as_str(),
                    key: hx(lock_id),
                    detail: diffs.join("; "),
                })
            };
        }
        let lock = self.require_lock(lock_id)?;
        if lock.state != LockState::PolicyOk {
            return Err(StoreError::Invalid(format!(
                "lock {} is {}, not POLICY_OK: not signing",
                hx(lock_id),
                lock.state
            )));
        }
        if lock.value_zat != amount || lock.destination != Some(*to) {
            return Err(StoreError::Invalid(format!(
                "lock {}: Mint(amount {amount}, to {to}) does not match the lock \
                 (value {}, destination {:?})",
                hx(lock_id),
                lock.value_zat,
                lock.destination.map(|d| d.to_string())
            )));
        }
        let signature = sign(digest).map_err(|e| StoreError::Signer(e.into()))?;
        self.conn().execute(
            "INSERT INTO sign_once_mint (lock_id, amount, recipient, digest, signature, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![lock_id, amount, to.0, digest, signature, self.now()],
        )?;
        self.transition_lock(
            lock_id,
            LockState::Signed,
            None,
            Some(&format!("Mint(amount {amount}, to {to})")),
        )?;
        self.mint_signature(lock_id)?
            .ok_or_else(|| StoreError::corrupt("sign-once record vanished"))
    }

    /// The stored `Mint` signature for a `lockId`.
    pub fn mint_signature(&self, lock_id: &Hash32) -> Result<Option<MintSignRecord>> {
        self.one(
            "SELECT lock_id, amount, recipient, digest, signature, signed_at
             FROM sign_once_mint WHERE lock_id = ?1",
            [lock_id],
            |r| {
                Ok(MintSignRecord {
                    lock_id: r.get(0)?,
                    amount: r.get(1)?,
                    to: EthAddress(r.get(2)?),
                    digest: r.get(3)?,
                    signature: r.get(4)?,
                    signed_at: r.get(5)?,
                })
            },
        )
    }

    /// Have the node sign `built_hex` at most once per `(domain, set, prevout)`.
    ///
    /// - No record: `sign(built_hex)` is called; it returns the signed hex and the sighash (act
    ///   message) the node reported; both are stored with `built_hex`.
    /// - A record with the same `built_hex`: returned, `sign` is not called (re-broadcast its
    ///   `signed_hex`).
    /// - A record with a different `built_hex`: [`StoreError::SignOnceConflict`], `sign` is not
    ///   called. The engine should look the record up ([`Tx::ycash_signature`]) *before*
    ///   building, and never rebuild.
    pub fn sign_once_ycash<F, E>(
        &self,
        key: &YcashSignKey,
        built_hex: &str,
        sign: F,
    ) -> Result<YcashSignRecord>
    where
        F: FnOnce(&str) -> core::result::Result<(String, Hash32), E>,
        E: Into<SignerError>,
    {
        Self::ycash_domain(key)?;
        if let Some(old) = self.ycash_signature(key)? {
            return if old.built_hex == built_hex {
                Ok(old)
            } else {
                Err(StoreError::SignOnceConflict {
                    domain: key.domain.as_str(),
                    key: key_id(key),
                    detail: "a different transaction was already signed for this prevout".into(),
                })
            };
        }
        let (signed_hex, sighash) = sign(built_hex).map_err(|e| StoreError::Signer(e.into()))?;
        self.conn().execute(
            "INSERT INTO sign_once_ycash (domain, set_id, prevout_txid, prevout_vout, sighash,
                                          built_hex, signed_hex, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key.domain,
                key.set_id,
                key.prevout.txid,
                key.prevout.vout,
                sighash,
                built_hex,
                signed_hex,
                self.now()
            ],
        )?;
        self.ycash_signature(key)?
            .ok_or_else(|| StoreError::corrupt("sign-once record vanished"))
    }

    /// The node guard's check, before asking for a signature whose sighash is already known:
    /// `Ok` if no record exists or the record has this `sighash`, [`StoreError::SignOnceConflict`]
    /// otherwise.
    pub fn check_ycash_sighash(&self, key: &YcashSignKey, sighash: &Hash32) -> Result<()> {
        Self::ycash_domain(key)?;
        match self.ycash_signature(key)? {
            Some(old) if old.sighash != *sighash => Err(StoreError::SignOnceConflict {
                domain: key.domain.as_str(),
                key: key_id(key),
                detail: format!("sighash {} != stored {}", hx(sighash), hx(&old.sighash)),
            }),
            _ => Ok(()),
        }
    }

    /// The stored Ycash signature for `key`.
    pub fn ycash_signature(&self, key: &YcashSignKey) -> Result<Option<YcashSignRecord>> {
        self.one(
            "SELECT sighash, built_hex, signed_hex, signed_at FROM sign_once_ycash
             WHERE domain = ?1 AND set_id = ?2 AND prevout_txid = ?3 AND prevout_vout = ?4",
            params![key.domain, key.set_id, key.prevout.txid, key.prevout.vout],
            |r| {
                Ok(YcashSignRecord {
                    key: *key,
                    sighash: r.get(0)?,
                    built_hex: r.get(1)?,
                    signed_hex: r.get(2)?,
                    signed_at: r.get(3)?,
                })
            },
        )
    }

    fn ycash_domain(key: &YcashSignKey) -> Result<()> {
        if SignDomain::YCASH.contains(&key.domain) {
            Ok(())
        } else {
            Err(StoreError::Invalid(format!(
                "{} is not a Ycash sign-once domain",
                key.domain
            )))
        }
    }
}
