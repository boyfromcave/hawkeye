//! `WYEC` locks (plan §1.2, §4.1; the Lock machine of §5.1).

use hawkeye_core::bytes::Hash32;
use hawkeye_core::lock::lock_id;
use hawkeye_core::{EthAddress, OutPoint};
use rusqlite::{Row, params};

use crate::state::{LockState, ObjectKind, check_forward};
use crate::{Result, StoreError, Tx, hx};

/// A lock as first observed in a Ycash block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLock {
    /// The vault output.
    pub outpoint: OutPoint,
    /// The V's value in zatoshi (the mint `amount`).
    pub value_zat: u64,
    /// The V's `ownerHeight`.
    pub owner_height: u32,
    /// The destination `OP_RETURN`'s address, when it decodes (a lock whose destination does not
    /// decode is still recorded, and rejected by policy).
    pub destination: Option<EthAddress>,
    /// The block that contains it.
    pub block_hash: Hash32,
    /// That block's height.
    pub block_height: u32,
}

/// A lock row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRecord {
    /// `SHA256(txid ‖ vout LE)` (§4.1).
    pub lock_id: Hash32,
    /// The vault output.
    pub outpoint: OutPoint,
    /// Value in zatoshi.
    pub value_zat: u64,
    /// The V's `ownerHeight`.
    pub owner_height: u32,
    /// The mint recipient, if the destination decodes.
    pub destination: Option<EthAddress>,
    /// The containing block (the latest one, if the lock was re-mined after a reorg).
    pub block_hash: Hash32,
    /// The containing block's height.
    pub block_height: u32,
    /// The machine state.
    pub state: LockState,
    /// Why the policy refused it (`POLICY_REJECTED`).
    pub rejection_reason: Option<String>,
    /// The lock left the active chain after this attestor signed its mint (§5.4 alarm).
    pub exposure: bool,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

const COLS: &str = "lock_id, txid, vout, value_zat, owner_height, destination, block_hash, \
                    block_height, state, rejection_reason, exposure, created_at, updated_at";

fn row(r: &Row<'_>) -> rusqlite::Result<LockRecord> {
    Ok(LockRecord {
        lock_id: r.get(0)?,
        outpoint: OutPoint::new(r.get(1)?, r.get(2)?),
        value_zat: r.get(3)?,
        owner_height: r.get(4)?,
        destination: r.get::<_, Option<[u8; 20]>>(5)?.map(EthAddress),
        block_hash: r.get(6)?,
        block_height: r.get(7)?,
        state: r.get(8)?,
        rejection_reason: r.get(9)?,
        exposure: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

/// The event-log id of a lock.
pub fn lock_object_id(lock_id: &Hash32) -> String {
    hx(lock_id)
}

impl Tx<'_> {
    /// Record a lock seen in a block (state `SEEN`), or return the existing row.
    ///
    /// Re-observing an existing lock is idempotent; if it is `REORGED` (its transaction is back
    /// on the active chain) the block is updated and it returns to `SEEN`. A different value,
    /// owner height or destination for the same outpoint is [`StoreError::Duplicate`].
    pub fn insert_lock(&self, new: &NewLock) -> Result<LockRecord> {
        let id = lock_id(&new.outpoint);
        if let Some(old) = self.lock(&id)? {
            if old.value_zat != new.value_zat
                || old.owner_height != new.owner_height
                || old.destination != new.destination
            {
                return Err(StoreError::Duplicate {
                    kind: ObjectKind::Lock,
                    id: lock_object_id(&id),
                });
            }
            if old.state == LockState::Reorged {
                self.conn().execute(
                    "UPDATE locks SET block_hash = ?2, block_height = ?3 WHERE lock_id = ?1",
                    params![id, new.block_hash, new.block_height],
                )?;
                self.transition_lock(
                    &id,
                    LockState::Seen,
                    Some(new.block_height),
                    Some("re-mined"),
                )?;
                return self.require_lock(&id);
            }
            if old.block_hash != new.block_hash || old.block_height != new.block_height {
                self.conn().execute(
                    "UPDATE locks SET block_hash = ?2, block_height = ?3, updated_at = ?4
                     WHERE lock_id = ?1",
                    params![id, new.block_hash, new.block_height, self.now()],
                )?;
                let detail = format!("block moved from height {}", old.block_height);
                self.log(
                    ObjectKind::Lock,
                    &lock_object_id(&id),
                    Some(old.state.as_str()),
                    old.state.as_str(),
                    Some(new.block_height.into()),
                    Some(&detail),
                )?;
                return self.require_lock(&id);
            }
            return Ok(old);
        }
        self.conn().execute(
            "INSERT INTO locks (lock_id, txid, vout, value_zat, owner_height, destination,
                                block_hash, block_height, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                id,
                new.outpoint.txid,
                new.outpoint.vout,
                new.value_zat,
                new.owner_height,
                new.destination.map(|d| d.0),
                new.block_hash,
                new.block_height,
                LockState::Seen,
                self.now(),
            ],
        )?;
        self.log(
            ObjectKind::Lock,
            &lock_object_id(&id),
            None,
            LockState::Seen.as_str(),
            Some(new.block_height.into()),
            None,
        )?;
        self.require_lock(&id)
    }

    /// The lock with this `lockId`.
    pub fn lock(&self, lock_id: &Hash32) -> Result<Option<LockRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM locks WHERE lock_id = ?1"),
            [lock_id],
            row,
        )
    }

    /// The lock at this outpoint.
    pub fn lock_by_outpoint(&self, op: &OutPoint) -> Result<Option<LockRecord>> {
        self.lock(&lock_id(op))
    }

    pub(crate) fn require_lock(&self, id: &Hash32) -> Result<LockRecord> {
        self.lock(id)?.ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::Lock,
            id: lock_object_id(id),
        })
    }

    /// Every lock in `state`, by block height then `lockId`.
    pub fn locks_in_state(&self, state: LockState) -> Result<Vec<LockRecord>> {
        self.all(
            &format!("SELECT {COLS} FROM locks WHERE state = ?1 ORDER BY block_height, lock_id"),
            [state],
            row,
        )
    }

    /// Move a lock along a forward edge of the Lock machine; returns the state it left.
    ///
    /// `POLICY_REJECTED` takes `detail` as the rejection reason (required). `SIGNED` requires the
    /// lock's sign-once record ([`Tx::sign_once_mint`] takes that edge itself). `REORGED` sets
    /// the exposure flag when a mint signature exists.
    pub fn transition_lock(
        &self,
        lock_id: &Hash32,
        to: LockState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<LockState> {
        let old = self.require_lock(lock_id)?;
        let oid = lock_object_id(lock_id);
        check_forward(&oid, old.state, to)?;
        match to {
            LockState::PolicyRejected => {
                let reason = detail
                    .ok_or_else(|| StoreError::Invalid("POLICY_REJECTED needs a reason".into()))?;
                self.conn().execute(
                    "UPDATE locks SET rejection_reason = ?2 WHERE lock_id = ?1",
                    params![lock_id, reason],
                )?;
            }
            LockState::Signed if self.mint_signature(lock_id)?.is_none() => {
                return Err(StoreError::Invalid(format!(
                    "lock {oid}: SIGNED without a sign-once record"
                )));
            }
            LockState::Reorged if self.mint_signature(lock_id)?.is_some() => {
                self.conn().execute(
                    "UPDATE locks SET exposure = 1 WHERE lock_id = ?1",
                    [lock_id],
                )?;
            }
            _ => {}
        }
        self.conn().execute(
            "UPDATE locks SET state = ?2, updated_at = ?3 WHERE lock_id = ?1",
            params![lock_id, to, self.now()],
        )?;
        self.log(
            ObjectKind::Lock,
            &oid,
            Some(old.state.as_str()),
            to.as_str(),
            height.map(u64::from),
            detail,
        )?;
        Ok(old.state)
    }

    /// `CONFIRMED → POLICY_REJECTED` with `reason`.
    pub fn reject_lock(&self, lock_id: &Hash32, reason: &str, height: Option<u32>) -> Result<()> {
        self.transition_lock(lock_id, LockState::PolicyRejected, height, Some(reason))
            .map(drop)
    }
}
