//! Sign-once records (plan §3.5, HK-7; AGENTS.md rule 7).
//!
//! The record kinds:
//!
//! - **`Mint`** (`eip712-mint`: the domain name dates from Ethereum; NEAR's Borsh-SHA256 `Mint`
//!   attestation is recorded the same way), keyed by `lockId`: one `(amount, to, digest)` ever.
//!   Hawkeye signs these itself, so this record *is* the guard.
//! - **EIP-712 `Challenge`** (`eip712-challenge`, schema v3), keyed by `(lockId, proposalId)`: the
//!   optimistic mint's veto. Refused outright when the ledger holds a policy-OK lock matching the
//!   proposal: a matching proposal is never challenged.
//! - **EIP-712 drill `Mint`** (`eip712-drill-mint`, schema v3), keyed by `lockId`: the
//!   `rogue-mint` drill's signature over a lock that does not exist (refused for a known lock).
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

use hawkeye_core::OutPoint;
use hawkeye_core::bytes::Hash32;
use rusqlite::params;

use crate::accounts::{Account, Guardian, SqlAccount, SqlGuardian};
use crate::state::{LockState, SignDomain};

/// Lock states in which a `(amount, to)` match means the lock is a real, policy-OK mint.
const MINTABLE: &[LockState] = &[
    LockState::PolicyOk,
    LockState::Signed,
    LockState::MintSubmitted,
    LockState::Proposed,
    LockState::Challenged,
    LockState::Executed,
    LockState::Minted,
];

/// A stored EIP-712 `Challenge` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSignRecord {
    /// The `lockId` of the proposal.
    pub lock_id: Hash32,
    /// The contract's proposal id.
    pub proposal_id: u128,
    /// The proposal's proposer (its signer).
    pub proposer: Guardian,
    /// The proposal's amount.
    pub amount: u64,
    /// The proposal's recipient.
    pub to: Account,
    /// Why it was challenged.
    pub reason: String,
    /// The EIP-712 digest signed.
    pub digest: Hash32,
    /// The 65-byte `r ‖ s ‖ v` signature.
    pub signature: [u8; 65],
    /// Unix seconds.
    pub signed_at: i64,
}

/// The proposal a challenge is about (what [`Tx::sign_once_challenge`] judges and records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengedProposal {
    /// The `lockId`.
    pub lock_id: Hash32,
    /// The contract's proposal id (non-zero).
    pub proposal_id: u128,
    /// The proposer.
    pub proposer: Guardian,
    /// The proposed amount.
    pub amount: u64,
    /// The proposed recipient.
    pub to: Account,
}
use crate::{Result, SignerError, StoreError, Tx, hx};

/// A stored EIP-712 `Mint` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintSignRecord {
    /// The `lockId`.
    pub lock_id: Hash32,
    /// The signed amount (zatoshi = wYEC base units).
    pub amount: u64,
    /// The signed recipient.
    pub to: Account,
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
        to: &Account,
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
        if lock.value_zat != amount || lock.destination.as_ref() != Some(to) {
            return Err(StoreError::Invalid(format!(
                "lock {}: Mint(amount {amount}, to {to}) does not match the lock \
                 (value {}, destination {:?})",
                hx(lock_id),
                lock.value_zat,
                lock.destination.as_ref().map(|d| d.to_string())
            )));
        }
        let signature = sign(digest).map_err(|e| StoreError::Signer(e.into()))?;
        self.conn().execute(
            "INSERT INTO sign_once_mint (lock_id, amount, recipient, digest, signature, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                lock_id,
                amount,
                SqlAccount(to.clone()),
                digest,
                signature,
                self.now()
            ],
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

    /// Sign `Challenge(lockId, proposalId)` at most once.
    ///
    /// - Refused ([`StoreError::Invalid`], `sign` not called) when the ledger holds this lock in a
    ///   policy-OK state with the proposal's `(amount, to)`: a matching proposal is never
    ///   challenged.
    /// - First call: `sign(digest)` is called and the record stored with the proposal and
    ///   `reason`, in this transaction.
    /// - Later call with the same `digest`: the stored record, `sign` not called.
    /// - A different `digest` for the same `(lockId, proposalId)` (another deployment):
    ///   [`StoreError::SignOnceConflict`].
    pub fn sign_once_challenge<F, E>(
        &self,
        p: &ChallengedProposal,
        reason: &str,
        digest: &Hash32,
        sign: F,
    ) -> Result<ChallengeSignRecord>
    where
        F: FnOnce(&Hash32) -> core::result::Result<[u8; 65], E>,
        E: Into<SignerError>,
    {
        if p.proposal_id == 0 {
            return Err(StoreError::Invalid("proposal id 0 is no proposal".into()));
        }
        if let Some(old) = self.challenge_signature(&p.lock_id, p.proposal_id)? {
            return if old.digest == *digest {
                Ok(old)
            } else {
                Err(StoreError::SignOnceConflict {
                    domain: SignDomain::Eip712Challenge.as_str(),
                    key: format!("{}/{}", hx(&p.lock_id), p.proposal_id),
                    detail: format!("digest {} != stored {}", hx(digest), hx(&old.digest)),
                })
            };
        }
        if let Some(l) = self.lock(&p.lock_id)?
            && MINTABLE.contains(&l.state)
            && l.value_zat == p.amount
            && l.destination.as_ref() == Some(&p.to)
        {
            return Err(StoreError::Invalid(format!(
                "proposal {} of lock {} matches the {} lock ({} to {}): never challenged",
                p.proposal_id,
                hx(&p.lock_id),
                l.state,
                p.amount,
                p.to
            )));
        }
        let signature = sign(digest).map_err(|e| StoreError::Signer(e.into()))?;
        self.conn().execute(
            "INSERT INTO sign_once_challenge (lock_id, proposal_id, proposer, amount, recipient,
                                              reason, digest, signature, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                p.lock_id,
                p.proposal_id.to_string(),
                SqlGuardian(p.proposer),
                p.amount,
                SqlAccount(p.to.clone()),
                reason,
                digest,
                signature,
                self.now()
            ],
        )?;
        self.challenge_signature(&p.lock_id, p.proposal_id)?
            .ok_or_else(|| StoreError::corrupt("sign-once record vanished"))
    }

    /// The stored `Challenge` signature for `(lockId, proposalId)`.
    pub fn challenge_signature(
        &self,
        lock_id: &Hash32,
        proposal_id: u128,
    ) -> Result<Option<ChallengeSignRecord>> {
        self.one(
            "SELECT proposer, amount, recipient, reason, digest, signature, signed_at
             FROM sign_once_challenge WHERE lock_id = ?1 AND proposal_id = ?2",
            params![lock_id, proposal_id.to_string()],
            |r| {
                Ok(ChallengeSignRecord {
                    lock_id: *lock_id,
                    proposal_id,
                    proposer: r.get::<_, SqlGuardian>(0)?.0,
                    amount: r.get(1)?,
                    to: r.get::<_, SqlAccount>(2)?.0,
                    reason: r.get(3)?,
                    digest: r.get(4)?,
                    signature: r.get(5)?,
                    signed_at: r.get(6)?,
                })
            },
        )
    }

    /// Every stored `Challenge` signature, oldest first.
    pub fn challenge_signatures(&self) -> Result<Vec<ChallengeSignRecord>> {
        self.all(
            "SELECT lock_id, proposal_id, proposer, amount, recipient, reason, digest, signature,
                    signed_at
             FROM sign_once_challenge ORDER BY signed_at, lock_id, proposal_id",
            [],
            |r| {
                let id: String = r.get(1)?;
                Ok(ChallengeSignRecord {
                    lock_id: r.get(0)?,
                    proposal_id: id.parse().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            "proposal id".into(),
                        )
                    })?,
                    proposer: r.get::<_, SqlGuardian>(2)?.0,
                    amount: r.get(3)?,
                    to: r.get::<_, SqlAccount>(4)?.0,
                    reason: r.get(5)?,
                    digest: r.get(6)?,
                    signature: r.get(7)?,
                    signed_at: r.get(8)?,
                })
            },
        )
    }

    /// Drill D-5 only (`hawkeye rogue-mint`): sign a `Mint` for a `lockId` this ledger knows
    /// nothing about, at most once. Refused for a known lock; an identical later call returns the
    /// stored record; a different `(amount, to, digest)` is a [`StoreError::SignOnceConflict`].
    pub fn sign_once_drill_mint<F, E>(
        &self,
        lock_id: &Hash32,
        amount: u64,
        to: &Account,
        digest: &Hash32,
        sign: F,
    ) -> Result<MintSignRecord>
    where
        F: FnOnce(&Hash32) -> core::result::Result<[u8; 65], E>,
        E: Into<SignerError>,
    {
        if let Some(old) = self.drill_mint_signature(lock_id)? {
            return if (old.amount, &old.to, old.digest) == (amount, to, *digest) {
                Ok(old)
            } else {
                Err(StoreError::SignOnceConflict {
                    domain: SignDomain::Eip712DrillMint.as_str(),
                    key: hx(lock_id),
                    detail: "a different drill Mint was already signed for this lockId".into(),
                })
            };
        }
        if self.lock(lock_id)?.is_some() || self.mint_signature(lock_id)?.is_some() {
            return Err(StoreError::Invalid(format!(
                "lock {} is in this ledger: the rogue-mint drill signs only unknown lockIds",
                hx(lock_id)
            )));
        }
        let signature = sign(digest).map_err(|e| StoreError::Signer(e.into()))?;
        self.conn().execute(
            "INSERT INTO sign_once_drill_mint (lock_id, amount, recipient, digest, signature,
                                               signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                lock_id,
                amount,
                SqlAccount(to.clone()),
                digest,
                signature,
                self.now()
            ],
        )?;
        self.drill_mint_signature(lock_id)?
            .ok_or_else(|| StoreError::corrupt("sign-once record vanished"))
    }

    /// The stored drill `Mint` signature for a `lockId`.
    pub fn drill_mint_signature(&self, lock_id: &Hash32) -> Result<Option<MintSignRecord>> {
        self.one(
            "SELECT lock_id, amount, recipient, digest, signature, signed_at
             FROM sign_once_drill_mint WHERE lock_id = ?1",
            [lock_id],
            |r| {
                Ok(MintSignRecord {
                    lock_id: r.get(0)?,
                    amount: r.get(1)?,
                    to: r.get::<_, SqlAccount>(2)?.0,
                    digest: r.get(3)?,
                    signature: r.get(4)?,
                    signed_at: r.get(5)?,
                })
            },
        )
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
                    to: r.get::<_, SqlAccount>(2)?.0,
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
