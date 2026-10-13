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

use hawkeye_core::bytes::Hash32;
use hawkeye_core::{Deployment, EthAddress, OutPoint};
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
    /// The bridge deployment whose EIP-712 domain the digest is under (schema v9, audit 05/L-3;
    /// `(0, 0x00…00)` for a pre-v9 row not yet backfilled).
    pub deployment: Deployment,
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

const MINT_COLS: &str =
    "lock_id, chain_id, bridge, amount, recipient, digest, signature, signed_at";

fn mint_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MintSignRecord> {
    Ok(MintSignRecord {
        lock_id: r.get(0)?,
        deployment: Deployment {
            chain_id: r.get(1)?,
            bridge: EthAddress(r.get(2)?),
        },
        amount: r.get(3)?,
        to: r.get::<_, SqlAccount>(4)?.0,
        digest: r.get(5)?,
        signature: r.get(6)?,
        signed_at: r.get(7)?,
    })
}

fn key_id(k: &YcashSignKey) -> String {
    format!("{}/{}", hx(&k.set_id), k.prevout)
}

impl Tx<'_> {
    /// Sign `Mint(lockId, amount, to)` at most once **per deployment** (schema v9, audit 05/L-3).
    ///
    /// - First call for the lock: it must be stored, `POLICY_OK`, with this `amount` (its value)
    ///   and `to` (its destination); `sign(digest)` is called, the record stored and the lock
    ///   moved `POLICY_OK → SIGNED`, all in this transaction.
    /// - Identical later call for the same deployment (same `amount`, `to`, `digest`): the stored
    ///   record, `sign` is not called. Any difference: [`StoreError::SignOnceConflict`].
    /// - Another deployment (a successor bridge after a migration, wyec design §4.6): the lock
    ///   must still be unminted (`POLICY_OK`, `SIGNED`, `MINT_SUBMITTED`, `PROPOSED`,
    ///   `CHALLENGED`) and `(amount, to)` must equal every earlier record's (else
    ///   [`StoreError::SignOnceConflict`]; SQLite enforces the same with a trigger); a new record
    ///   is stored for this deployment, the lock state is left as it is (`POLICY_OK → SIGNED`
    ///   aside).
    pub fn sign_once_mint<F, E>(
        &self,
        deployment: &Deployment,
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
        if let Some(old) = self.mint_signature(deployment, lock_id)? {
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
        let earlier = self.mint_signatures_any(lock_id)?;
        if let Some(e) = earlier.iter().find(|e| e.amount != amount || e.to != *to) {
            return Err(StoreError::SignOnceConflict {
                domain: SignDomain::Eip712Mint.as_str(),
                key: hx(lock_id),
                detail: format!(
                    "Mint(amount {amount}, to {to}) for chain {} bridge {} differs from the \
                     record for chain {} bridge {} (amount {}, to {}): one (amount, to) per lock",
                    deployment.chain_id,
                    hx(&deployment.bridge.0),
                    e.deployment.chain_id,
                    hx(&e.deployment.bridge.0),
                    e.amount,
                    e.to
                ),
            });
        }
        let resignable = !earlier.is_empty()
            && matches!(
                lock.state,
                LockState::Signed
                    | LockState::MintSubmitted
                    | LockState::Proposed
                    | LockState::Challenged
            );
        if lock.state != LockState::PolicyOk && !resignable {
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
            "INSERT INTO sign_once_mint (lock_id, chain_id, bridge, amount, recipient, digest,
                                         signature, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                lock_id,
                deployment.chain_id,
                deployment.bridge.0,
                amount,
                SqlAccount(to.clone()),
                digest,
                signature,
                self.now()
            ],
        )?;
        if lock.state == LockState::PolicyOk {
            self.transition_lock(
                lock_id,
                LockState::Signed,
                None,
                Some(&format!("Mint(amount {amount}, to {to})")),
            )?;
        }
        self.mint_signature(deployment, lock_id)?
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
        if self.lock(lock_id)?.is_some() || self.has_mint_signature(lock_id)? {
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
                    // drill records are not per deployment (devnet only)
                    deployment: Deployment {
                        chain_id: 0,
                        bridge: EthAddress([0; 20]),
                    },
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
    pub fn mint_signature(
        &self,
        deployment: &Deployment,
        lock_id: &Hash32,
    ) -> Result<Option<MintSignRecord>> {
        self.one(
            &format!("SELECT {MINT_COLS} FROM sign_once_mint WHERE lock_id = ?1 AND chain_id = ?2 AND bridge = ?3"),
            params![lock_id, deployment.chain_id, deployment.bridge.0],
            mint_row,
        )
    }

    /// Every `Mint` sign-once record of `lock_id`, whatever the deployment (schema v9).
    pub fn mint_signatures_any(&self, lock_id: &Hash32) -> Result<Vec<MintSignRecord>> {
        self.all(
            &format!("SELECT {MINT_COLS} FROM sign_once_mint WHERE lock_id = ?1 ORDER BY signed_at, chain_id, bridge"),
            [lock_id],
            mint_row,
        )
    }

    /// Whether this attestor ever signed a `Mint` for `lock_id`, on any deployment (a reorged
    /// signed lock is an exposure; the `SIGNED` state needs a record).
    pub fn has_mint_signature(&self, lock_id: &Hash32) -> Result<bool> {
        Ok(!self.mint_signatures_any(lock_id)?.is_empty())
    }

    /// The schema-v9 backfill (audit 05/L-3): pre-v9 `Mint` records carry the placeholder
    /// deployment; they were all made for the deployment configured then, which is the one
    /// configured now unless the operator migrated in between (then they belong to the old
    /// bridge: run once with the old deployment first). Returns the rows set.
    pub fn backfill_mint_deployment(&self, deployment: &Deployment) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE sign_once_mint SET chain_id = ?1, bridge = ?2
             WHERE chain_id = 0 AND bridge = zeroblob(20)",
            params![deployment.chain_id, deployment.bridge.0],
        )?)
    }

    /// `Mint` records per deployment other than `deployment` (start-up log after a migration).
    pub fn mint_signatures_elsewhere(
        &self,
        deployment: &Deployment,
    ) -> Result<Vec<(Deployment, u64)>> {
        self.all(
            "SELECT chain_id, bridge, count(*) FROM sign_once_mint
             WHERE NOT (chain_id = ?1 AND bridge = ?2) GROUP BY chain_id, bridge",
            params![deployment.chain_id, deployment.bridge.0],
            |r| {
                Ok((
                    Deployment {
                        chain_id: r.get(0)?,
                        bridge: EthAddress(r.get(1)?),
                    },
                    r.get(2)?,
                ))
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

    /// Every stored Ycash signature of `set_id`, by domain and prevout (`hawkeye audit-ledger`).
    pub fn ycash_signatures(&self, set_id: &Hash32) -> Result<Vec<YcashSignRecord>> {
        self.all(
            "SELECT domain, prevout_txid, prevout_vout, sighash, built_hex, signed_hex, signed_at
             FROM sign_once_ycash WHERE set_id = ?1
             ORDER BY domain, prevout_txid, prevout_vout",
            params![set_id],
            |r| {
                Ok(YcashSignRecord {
                    key: YcashSignKey {
                        domain: r.get(0)?,
                        set_id: *set_id,
                        prevout: OutPoint::new(r.get(1)?, r.get(2)?),
                    },
                    sighash: r.get(3)?,
                    built_hex: r.get(4)?,
                    signed_hex: r.get(5)?,
                    signed_at: r.get(6)?,
                })
            },
        )
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

/// Who produced an unlock signature recorded per burn (schema v6, remedial report 05/H-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnlockOrigin {
    /// This attestor's own unlock, as the burn's leader: the only kind it ever re-sends.
    Leader,
    /// A peer's unlock co-signed over `POST /unlock/sign` (`unlockThreshold > 1`).
    Cosign,
    /// Drill D-3 (`rogue-unlock --replay-burn`): a deliberate second unlock for a burn.
    Drill,
}

impl UnlockOrigin {
    /// The ledger text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Cosign => "cosign",
            Self::Drill => "drill",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "leader" => Self::Leader,
            "cosign" => Self::Cosign,
            "drill" => Self::Drill,
            _ => return None,
        })
    }
}

impl std::fmt::Display for UnlockOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The burn an unlock signature pays, for [`Tx::sign_once_unlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockBurn {
    /// The burn.
    pub key: crate::BurnKey,
    /// Who signs.
    pub origin: UnlockOrigin,
    /// Drill D-3 only: skip the per-burn check (the drill produces the double release the
    /// watchers must cancel). Refused unless `origin` is [`UnlockOrigin::Drill`].
    pub allow_double: bool,
}

/// One row of the per-burn unlock record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockBurnRecord {
    /// The set.
    pub set_id: Hash32,
    /// The burn.
    pub key: crate::BurnKey,
    /// The vault the signed unlock spends.
    pub prevout: OutPoint,
    /// Who signed.
    pub origin: UnlockOrigin,
    /// Unix seconds.
    pub signed_at: i64,
    /// Why the signed transaction can no longer confirm, once dead.
    pub dead_reason: Option<String>,
    /// The Ycash height the row was marked dead at.
    pub dead_height: Option<u32>,
}

impl UnlockBurnRecord {
    /// Not marked dead.
    pub fn is_live(&self) -> bool {
        self.dead_reason.is_none()
    }
}

const UNLOCK_BURN_COLS: &str = "set_id, chain_id, bridge, nonce, prevout_txid, prevout_vout, \
                                origin, signed_at, dead_reason, dead_height";

fn unlock_burn_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UnlockBurnRecord> {
    let origin: String = r.get(6)?;
    Ok(UnlockBurnRecord {
        set_id: r.get(0)?,
        key: crate::BurnKey::new(
            hawkeye_core::Deployment {
                chain_id: r.get(1)?,
                bridge: hawkeye_core::EthAddress(r.get(2)?),
            },
            r.get(3)?,
        ),
        prevout: OutPoint::new(r.get(4)?, r.get(5)?),
        origin: UnlockOrigin::parse(&origin).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                "unlock origin".into(),
            )
        })?,
        signed_at: r.get(7)?,
        dead_reason: r.get(8)?,
        dead_height: r.get(9)?,
    })
}

impl Tx<'_> {
    /// [`Tx::sign_once_ycash`] for the unlock domain **with the burn dimension** (schema v6,
    /// remedial report 05/H-1 §4.3): one live vault per burn, ever, per attestor.
    ///
    /// 1. A per-vault record with the same `built_hex`: returned, `sign` not called (with a
    ///    burn, its per-burn row must exist and name this vault, else the ledger is corrupt).
    ///    A different `built_hex`: [`StoreError::SignOnceConflict`].
    /// 2. With a burn (and not `allow_double`): a **live** row naming this burn with another
    ///    vault → [`StoreError::SignOnceConflict`] (`key` = `burn <chainId:bridge:nonce>`).
    /// 3. `sign(built_hex)`; 4. the `sign_once_ycash` record, then the per-burn row, in this
    ///    transaction.
    ///
    /// `burn = None` is for rolls (they pay no burn).
    pub fn sign_once_unlock<F, E>(
        &self,
        key: &YcashSignKey,
        burn: Option<&UnlockBurn>,
        built_hex: &str,
        sign: F,
    ) -> Result<YcashSignRecord>
    where
        F: FnOnce(&str) -> core::result::Result<(String, Hash32), E>,
        E: Into<SignerError>,
    {
        if key.domain != SignDomain::YcashUnlock {
            return Err(StoreError::Invalid(format!(
                "{} is not the unlock sign-once domain",
                key.domain
            )));
        }
        if let Some(b) = burn
            && b.allow_double
            && b.origin != UnlockOrigin::Drill
        {
            return Err(StoreError::Invalid(
                "allow_double is for the drill origin only".into(),
            ));
        }
        if let Some(old) = self.ycash_signature(key)? {
            if old.built_hex != built_hex {
                return Err(StoreError::SignOnceConflict {
                    domain: key.domain.as_str(),
                    key: key_id(key),
                    detail: "a different transaction was already signed for this prevout".into(),
                });
            }
            if let Some(b) = burn {
                let rows = self.unlock_burn_rows(&key.set_id, &b.key)?;
                if !rows.iter().any(|r| r.prevout == key.prevout) {
                    return Err(StoreError::corrupt(format!(
                        "unlock of {} is recorded without its burn {} row",
                        key.prevout, b.key
                    )));
                }
            }
            return Ok(old);
        }
        if let Some(b) = burn
            && !b.allow_double
            && let Some(live) = self
                .unlock_burn_rows(&key.set_id, &b.key)?
                .into_iter()
                .find(|r| r.is_live() && r.prevout != key.prevout)
        {
            return Err(StoreError::SignOnceConflict {
                domain: key.domain.as_str(),
                key: format!("burn {}", b.key),
                detail: format!(
                    "a live {} unlock of vault {} already pays this burn",
                    live.origin, live.prevout
                ),
            });
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
        if let Some(b) = burn {
            self.insert_unlock_burn(&key.set_id, &b.key, &key.prevout, b.origin, false)?;
        }
        self.ycash_signature(key)?
            .ok_or_else(|| StoreError::corrupt("sign-once record vanished"))
    }

    fn insert_unlock_burn(
        &self,
        set_id: &Hash32,
        k: &crate::BurnKey,
        prevout: &OutPoint,
        origin: UnlockOrigin,
        or_ignore: bool,
    ) -> Result<usize> {
        Ok(self.conn().execute(
            &format!(
                "INSERT {} INTO sign_once_unlock_burn (set_id, chain_id, bridge, nonce,
                     prevout_txid, prevout_vout, origin, signed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                if or_ignore { "OR IGNORE" } else { "" }
            ),
            params![
                set_id,
                k.deployment.chain_id,
                k.deployment.bridge.0,
                k.nonce,
                prevout.txid,
                prevout.vout,
                origin.as_str(),
                self.now()
            ],
        )?)
    }

    /// Every per-burn unlock row of `burn` under `set_id`, oldest first (live and dead).
    pub fn unlock_burn_rows(
        &self,
        set_id: &Hash32,
        burn: &crate::BurnKey,
    ) -> Result<Vec<UnlockBurnRecord>> {
        self.all(
            &format!(
                "SELECT {UNLOCK_BURN_COLS} FROM sign_once_unlock_burn
                 WHERE set_id = ?1 AND chain_id = ?2 AND bridge = ?3 AND nonce = ?4
                 ORDER BY signed_at, prevout_txid, prevout_vout"
            ),
            params![
                set_id,
                burn.deployment.chain_id,
                burn.deployment.bridge.0,
                burn.nonce
            ],
            unlock_burn_row,
        )
    }

    /// The per-burn rows naming a vault (the burns an unlock of it was signed for).
    pub fn unlock_burns_of_vault(
        &self,
        set_id: &Hash32,
        prevout: &OutPoint,
    ) -> Result<Vec<UnlockBurnRecord>> {
        self.all(
            &format!(
                "SELECT {UNLOCK_BURN_COLS} FROM sign_once_unlock_burn
                 WHERE set_id = ?1 AND prevout_txid = ?2 AND prevout_vout = ?3
                 ORDER BY signed_at"
            ),
            params![set_id, prevout.txid, prevout.vout],
            unlock_burn_row,
        )
    }

    /// The live unlock that pays `burn` here, if any: its vault and origin. A drill row (D-3's
    /// deliberate double) is never it: it is not re-sent, served or judged as the burn's unlock
    /// (review L-3); the per-burn guard of [`Tx::sign_once_unlock`] still counts it.
    pub fn live_unlock_for_burn(
        &self,
        set_id: &Hash32,
        burn: &crate::BurnKey,
    ) -> Result<Option<UnlockBurnRecord>> {
        Ok(self
            .unlock_burn_rows(set_id, burn)?
            .into_iter()
            .find(|r| r.is_live() && r.origin != UnlockOrigin::Drill))
    }

    /// Every live non-drill per-burn row (the orphan check: a row whose burn was paid by another
    /// vault).
    pub fn live_unlock_rows(&self, set_id: &Hash32) -> Result<Vec<UnlockBurnRecord>> {
        self.all(
            &format!(
                "SELECT {UNLOCK_BURN_COLS} FROM sign_once_unlock_burn
                     WHERE set_id = ?1 AND dead_reason IS NULL AND origin != 'drill'
                     ORDER BY signed_at"
            ),
            params![set_id],
            unlock_burn_row,
        )
    }

    /// How many Ycash sign-once records the ledger holds (the restore high-water mark, review
    /// L-2: a ledger restored from a backup holds fewer than it once did).
    pub fn ycash_signature_count(&self) -> Result<u64> {
        Ok(self
            .one("SELECT count(*) FROM sign_once_ycash", [], |r| r.get(0))?
            .unwrap_or(0))
    }

    /// Mark the live row `(burn, prevout)` dead: its transaction can no longer confirm. Only a
    /// live row can be marked, once; an unknown or already dead row is
    /// [`StoreError::Invalid`]. The event log records the reason.
    pub fn mark_unlock_dead(
        &self,
        set_id: &Hash32,
        burn: &crate::BurnKey,
        prevout: &OutPoint,
        reason: &str,
        height: u32,
    ) -> Result<()> {
        let n = self.conn().execute(
            "UPDATE sign_once_unlock_burn SET dead_reason = ?7, dead_height = ?8
             WHERE set_id = ?1 AND chain_id = ?2 AND bridge = ?3 AND nonce = ?4
               AND prevout_txid = ?5 AND prevout_vout = ?6 AND dead_reason IS NULL",
            params![
                set_id,
                burn.deployment.chain_id,
                burn.deployment.bridge.0,
                burn.nonce,
                prevout.txid,
                prevout.vout,
                reason,
                height
            ],
        )?;
        if n != 1 {
            return Err(StoreError::Invalid(format!(
                "no live unlock of {prevout} for burn {burn}"
            )));
        }
        self.log(
            crate::state::ObjectKind::Burn,
            &burn.to_string(),
            None,
            "UNLOCK_DEAD",
            Some(u64::from(height)),
            Some(&format!("vault {prevout}: {reason}")),
        )
    }

    /// A metadata value.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        self.one("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
    }

    /// Set a metadata value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// The V6 backfill (see [`crate::Store::backfill_unlock_burns`]): one `leader` row per
    /// pre-V6 unlock record whose signed transaction names a burn (`decode`). Idempotent.
    pub fn backfill_unlock_burns(
        &self,
        decode: &dyn Fn(&str) -> Option<(hawkeye_core::Deployment, u64)>,
    ) -> Result<usize> {
        let recs: Vec<(Hash32, OutPoint, String)> = self.all(
            "SELECT set_id, prevout_txid, prevout_vout, signed_hex FROM sign_once_ycash
             WHERE domain = 'ycash-unlock' ORDER BY signed_at",
            [],
            |r| Ok((r.get(0)?, OutPoint::new(r.get(1)?, r.get(2)?), r.get(3)?)),
        )?;
        let mut n = 0;
        for (set_id, prevout, hex) in recs {
            let Some((dep, nonce)) = decode(&hex) else {
                continue;
            };
            n += self.insert_unlock_burn(
                &set_id,
                &crate::BurnKey::new(dep, nonce),
                &prevout,
                UnlockOrigin::Leader,
                true,
            )?;
        }
        self.set_meta(BACKFILL_UNLOCK_BURNS, "done")?;
        Ok(n)
    }
}

/// The `meta` key recording the V6 backfill.
pub const BACKFILL_UNLOCK_BURNS: &str = "backfill_unlock_burns";
