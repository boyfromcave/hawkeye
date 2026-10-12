//! Working state a restarted daemon resumes from (schema v2): deferred mint checks (§5.3 step
//! 2), the slash votes a case owner gathered and the votes this attestor gave (§5.3 step 3), and
//! the set signatures seen on Ycash (equivocation detection, §2.3 row 1).
//!
//! None of these rows is a §5.1 state machine: they are idempotent records, written in the same
//! ledger transaction as the action they describe where there is one.

use hawkeye_core::bytes::Hash32;
use hawkeye_core::{OutPoint, PubKey33};
use rusqlite::params;

use crate::accounts::{Account, SqlAccount};
use crate::state::FaultKind;
use crate::{Result, Tx};

/// A `Minted` (or `MintProposed`) event this attestor could not judge yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMintRecord {
    /// The `lockId` minted against.
    pub lock_id: Hash32,
    /// The foreign transaction (Ethereum transaction hash; NEAR receipt id).
    pub tx_hash: Hash32,
    /// The mint recipient.
    pub to: Account,
    /// The amount (base units = zatoshi).
    pub amount: u64,
    /// The foreign block (height).
    pub block: u64,
    /// The Ycash tip when it was first deferred (the grace period counts from here).
    pub since_height: u32,
    /// A `MintProposed` (CR-W1), not a `Minted`.
    pub proposal: bool,
}

/// The case owner's act with the signatures gathered so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashProgress {
    /// The case.
    pub case_id: i64,
    /// The act transaction hex with every signature gathered.
    pub act_hex: String,
    /// `slashThreshold` reached.
    pub complete: bool,
    /// Signatures on the act.
    pub signatures: u32,
    /// Signatures required (`-1` unknown).
    pub required: i32,
}

/// A vote this attestor gave on a peer's act (`POST /slash/sign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteGiven {
    /// The act's first input (its sign-once prevout).
    pub act_prevout: OutPoint,
    /// The fault it was verified as.
    pub fault: FaultKind,
    /// The member removed.
    pub target_key: PubKey33,
    /// The case subject (intent txid, lockId, …).
    pub subject: Vec<u8>,
    /// The act with this attestor's signature.
    pub signed_hex: String,
    /// `slashThreshold` reached with it.
    pub complete: bool,
    /// Signatures on it.
    pub signatures: u32,
    /// Signatures required.
    pub required: i32,
    /// What the independent verification found.
    pub reason: String,
}

/// A set signature seen in a template spend on Ycash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenSetSig {
    /// The set.
    pub set_id: Hash32,
    /// The template coin spent.
    pub prevout: OutPoint,
    /// The signer.
    pub member_key: PubKey33,
    /// 1 unlock, 2 cancel.
    pub role: u8,
    /// The spend's sighash.
    pub sighash: Hash32,
    /// The 65-byte signature.
    pub signature: [u8; 65],
    /// The spending transaction.
    pub txid: Hash32,
}

fn b(v: bool) -> i64 {
    i64::from(v)
}

impl Tx<'_> {
    /// Record a deferred mint check (idempotent: the first record of `(lockId, txHash)` stays).
    /// `true` if it was new.
    pub fn add_pending_mint(&self, r: &PendingMintRecord) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO pending_mints (lock_id, tx_hash, recipient, amount, block,
                                                  since_height, proposal, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                r.lock_id,
                r.tx_hash,
                SqlAccount(r.to.clone()),
                r.amount,
                r.block,
                r.since_height,
                b(r.proposal),
                self.now()
            ],
        )?;
        Ok(n == 1)
    }

    /// Every deferred mint check, oldest first.
    pub fn pending_mints(&self) -> Result<Vec<PendingMintRecord>> {
        self.all(
            "SELECT lock_id, tx_hash, recipient, amount, block, since_height, proposal
             FROM pending_mints ORDER BY created_at, block, lock_id",
            [],
            |r| {
                Ok(PendingMintRecord {
                    lock_id: r.get(0)?,
                    tx_hash: r.get(1)?,
                    to: r.get::<_, SqlAccount>(2)?.0,
                    amount: r.get(3)?,
                    block: r.get(4)?,
                    since_height: r.get(5)?,
                    proposal: r.get::<_, i64>(6)? != 0,
                })
            },
        )
    }

    /// Drop a deferred mint check (judged).
    pub fn remove_pending_mint(&self, lock_id: &Hash32, tx_hash: &Hash32) -> Result<()> {
        self.conn().execute(
            "DELETE FROM pending_mints WHERE lock_id = ?1 AND tx_hash = ?2",
            params![lock_id, tx_hash],
        )?;
        Ok(())
    }

    /// Store the case owner's act with the signatures gathered so far.
    pub fn set_slash_progress(&self, p: &SlashProgress) -> Result<()> {
        self.conn().execute(
            "INSERT INTO slash_progress (case_id, act_hex, complete, signatures, required,
                                         updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (case_id) DO UPDATE SET act_hex = ?2, complete = ?3, signatures = ?4,
                                                 required = ?5, updated_at = ?6",
            params![
                p.case_id,
                p.act_hex,
                b(p.complete),
                p.signatures,
                p.required,
                self.now()
            ],
        )?;
        Ok(())
    }

    /// The case owner's act with the signatures gathered so far.
    pub fn slash_progress(&self, case_id: i64) -> Result<Option<SlashProgress>> {
        self.one(
            "SELECT case_id, act_hex, complete, signatures, required FROM slash_progress
             WHERE case_id = ?1",
            [case_id],
            |r| {
                Ok(SlashProgress {
                    case_id: r.get(0)?,
                    act_hex: r.get(1)?,
                    complete: r.get::<_, i64>(2)? != 0,
                    signatures: r.get(3)?,
                    required: r.get(4)?,
                })
            },
        )
    }

    /// Record that `peer` signed the case's act.
    pub fn record_slash_vote(
        &self,
        case_id: i64,
        peer: &str,
        signatures: u32,
        complete: bool,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO slash_votes (case_id, peer, signatures, complete, at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![case_id, peer, signatures, b(complete), self.now()],
        )?;
        Ok(())
    }

    /// The peers that signed the case's act.
    pub fn slash_voters(&self, case_id: i64) -> Result<Vec<String>> {
        self.all(
            "SELECT peer FROM slash_votes WHERE case_id = ?1 ORDER BY at, peer",
            [case_id],
            |r| r.get(0),
        )
    }

    /// Record a vote given (peer side); the first record for an act prevout stays.
    pub fn record_vote_given(&self, v: &VoteGiven) -> Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO slash_votes_given (act_txid, act_vout, fault, target_key,
                     subject, signed_hex, complete, signatures, required, reason, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                v.act_prevout.txid,
                v.act_prevout.vout,
                v.fault,
                v.target_key,
                v.subject,
                v.signed_hex,
                b(v.complete),
                v.signatures,
                v.required,
                v.reason,
                self.now()
            ],
        )?;
        Ok(())
    }

    /// The vote given on the act spending `act_prevout`.
    pub fn vote_given(&self, act_prevout: &OutPoint) -> Result<Option<VoteGiven>> {
        self.one(
            "SELECT fault, target_key, subject, signed_hex, complete, signatures, required, reason
             FROM slash_votes_given WHERE act_txid = ?1 AND act_vout = ?2",
            params![act_prevout.txid, act_prevout.vout],
            |r| {
                Ok(VoteGiven {
                    act_prevout: *act_prevout,
                    fault: r.get(0)?,
                    target_key: r.get(1)?,
                    subject: r.get(2)?,
                    signed_hex: r.get(3)?,
                    complete: r.get::<_, i64>(4)? != 0,
                    signatures: r.get(5)?,
                    required: r.get(6)?,
                    reason: r.get(7)?,
                })
            },
        )
    }

    /// Record a set signature seen on Ycash. Returns the signatures by the same key over the
    /// same `(set, prevout)` with a **different** `(role, sighash)` already recorded: each one is
    /// an equivocation with `s`.
    pub fn note_set_sig(&self, s: &SeenSetSig) -> Result<Vec<SeenSetSig>> {
        let conflicts = self.all(
            "SELECT role, sighash, signature, txid FROM set_sigs_seen
             WHERE set_id = ?1 AND prevout_txid = ?2 AND prevout_vout = ?3 AND member_key = ?4
               AND NOT (role = ?5 AND sighash = ?6)
             ORDER BY at, txid",
            params![
                s.set_id,
                s.prevout.txid,
                s.prevout.vout,
                s.member_key,
                s.role,
                s.sighash
            ],
            |r| {
                Ok(SeenSetSig {
                    set_id: s.set_id,
                    prevout: s.prevout,
                    member_key: s.member_key,
                    role: r.get(0)?,
                    sighash: r.get(1)?,
                    signature: r.get(2)?,
                    txid: r.get(3)?,
                })
            },
        )?;
        self.conn().execute(
            "INSERT OR IGNORE INTO set_sigs_seen (set_id, prevout_txid, prevout_vout, member_key,
                     role, sighash, signature, txid, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                s.set_id,
                s.prevout.txid,
                s.prevout.vout,
                s.member_key,
                s.role,
                s.sighash,
                s.signature,
                s.txid,
                self.now()
            ],
        )?;
        Ok(conflicts)
    }

    /// Claim the one `SET_EQUIVOCATION` submission for `(prevout, key)`: `true` if this call
    /// claimed it (nobody had).
    pub fn claim_equivocation(&self, prevout: &OutPoint, key: &PubKey33) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO equivocations_sent (prevout_txid, prevout_vout, member_key, at)
             VALUES (?1, ?2, ?3, ?4)",
            params![prevout.txid, prevout.vout, key, self.now()],
        )?;
        Ok(n == 1)
    }

    /// Record the txid of a submitted `SET_EQUIVOCATION`.
    pub fn equivocation_sent(
        &self,
        prevout: &OutPoint,
        key: &PubKey33,
        txid: &Hash32,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE equivocations_sent SET txid = ?4
             WHERE prevout_txid = ?1 AND prevout_vout = ?2 AND member_key = ?3",
            params![prevout.txid, prevout.vout, key, txid],
        )?;
        Ok(())
    }

    /// Release a claim whose submission failed (it is retried on the next sighting).
    pub fn unclaim_equivocation(&self, prevout: &OutPoint, key: &PubKey33) -> Result<()> {
        self.conn().execute(
            "DELETE FROM equivocations_sent
             WHERE prevout_txid = ?1 AND prevout_vout = ?2 AND member_key = ?3 AND txid IS NULL",
            params![prevout.txid, prevout.vout, key],
        )?;
        Ok(())
    }
}
