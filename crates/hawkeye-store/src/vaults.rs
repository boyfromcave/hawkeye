//! The set's `WYEC` vault outputs (plan §3.1; the Vault machine of §5.1).

use hawkeye_core::OutPoint;
use hawkeye_core::bytes::{Hash32, txid_to_display};
use rusqlite::{Row, params};

use crate::state::{ObjectKind, VaultState, check_forward};
use crate::{Result, StoreError, Tx};

/// A vault output as first seen mined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVault {
    /// The vault output.
    pub outpoint: OutPoint,
    /// Value in zatoshi.
    pub value_zat: u64,
    /// The V's `ownerHeight`.
    pub owner_height: u32,
    /// The height of the block that created it.
    pub created_height: u32,
}

/// A vault row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    /// The vault output.
    pub outpoint: OutPoint,
    /// Value in zatoshi.
    pub value_zat: u64,
    /// The V's `ownerHeight`.
    pub owner_height: u32,
    /// Creation height.
    pub created_height: u32,
    /// The machine state.
    pub state: VaultState,
    /// The transaction that ended it (`SPENT`: the spend; `ROLLED`: the release).
    pub spent_txid: Option<Hash32>,
    /// That transaction's height.
    pub spent_height: Option<u32>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

const COLS: &str = "txid, vout, value_zat, owner_height, created_height, state, spent_txid, \
                    spent_height, created_at, updated_at";

fn row(r: &Row<'_>) -> rusqlite::Result<VaultRecord> {
    Ok(VaultRecord {
        outpoint: OutPoint::new(r.get(0)?, r.get(1)?),
        value_zat: r.get(2)?,
        owner_height: r.get(3)?,
        created_height: r.get(4)?,
        state: r.get(5)?,
        spent_txid: r.get(6)?,
        spent_height: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

impl Tx<'_> {
    /// Record a vault (`LIVE`), or return the stored one (idempotent; different content for
    /// the same outpoint is [`StoreError::Duplicate`]).
    pub fn insert_vault(&self, new: &NewVault) -> Result<VaultRecord> {
        let op = &new.outpoint;
        if let Some(old) = self.vault(op)? {
            if old.value_zat != new.value_zat
                || old.owner_height != new.owner_height
                || old.created_height != new.created_height
            {
                return Err(StoreError::Duplicate {
                    kind: ObjectKind::Vault,
                    id: op.to_string(),
                });
            }
            return Ok(old);
        }
        self.conn().execute(
            "INSERT INTO vaults (txid, vout, value_zat, owner_height, created_height, state,
                                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                op.txid,
                op.vout,
                new.value_zat,
                new.owner_height,
                new.created_height,
                VaultState::Live,
                self.now(),
            ],
        )?;
        self.log(
            ObjectKind::Vault,
            &op.to_string(),
            None,
            VaultState::Live.as_str(),
            Some(new.created_height.into()),
            None,
        )?;
        self.require_vault(op)
    }

    /// The vault at this outpoint.
    pub fn vault(&self, op: &OutPoint) -> Result<Option<VaultRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM vaults WHERE txid = ?1 AND vout = ?2"),
            params![op.txid, op.vout],
            row,
        )
    }

    pub(crate) fn require_vault(&self, op: &OutPoint) -> Result<VaultRecord> {
        self.vault(op)?.ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::Vault,
            id: op.to_string(),
        })
    }

    /// Every vault in `state`, nearest `ownerHeight` first (the drain order, §3.1 item 3).
    pub fn vaults_in_state(&self, state: VaultState) -> Result<Vec<VaultRecord>> {
        self.all(
            &format!(
                "SELECT {COLS} FROM vaults WHERE state = ?1 ORDER BY owner_height, txid, vout"
            ),
            [state],
            row,
        )
    }

    /// `LIVE → ROLL_DUE`, `ROLL_DUE → ROLLING`; returns the state left. `SPENT` and `ROLLED`
    /// go through [`Tx::vault_spent`].
    pub fn transition_vault(
        &self,
        op: &OutPoint,
        to: VaultState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<VaultState> {
        check_forward(&op.to_string(), self.require_vault(op)?.state, to)?;
        if matches!(to, VaultState::Spent | VaultState::Rolled) {
            return Err(StoreError::Invalid(format!(
                "{to} carries data: use vault_spent"
            )));
        }
        self.vault_edge(op, to, height, detail)
    }

    /// `… → SPENT | ROLLED`, ended by `txid` mined at `height`.
    pub fn vault_spent(
        &self,
        op: &OutPoint,
        to: VaultState,
        txid: &Hash32,
        height: u32,
    ) -> Result<()> {
        if !matches!(to, VaultState::Spent | VaultState::Rolled) {
            return Err(StoreError::Invalid(format!("vault_spent to {to}")));
        }
        let detail = format!("by {}", txid_to_display(txid));
        self.vault_edge(op, to, Some(height), Some(&detail))?;
        self.conn().execute(
            "UPDATE vaults SET spent_txid = ?3, spent_height = ?4 WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, txid, height],
        )?;
        Ok(())
    }

    fn vault_edge(
        &self,
        op: &OutPoint,
        to: VaultState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<VaultState> {
        let old = self.require_vault(op)?;
        check_forward(&op.to_string(), old.state, to)?;
        self.set_vault_state(op, old.state, to, height.map(u64::from), detail)?;
        Ok(old.state)
    }

    pub(crate) fn set_vault_state(
        &self,
        op: &OutPoint,
        from: VaultState,
        to: VaultState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE vaults SET state = ?3, updated_at = ?4 WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, to, self.now()],
        )?;
        self.log(
            ObjectKind::Vault,
            &op.to_string(),
            Some(from.as_str()),
            to.as_str(),
            height,
            detail,
        )
    }
}
