//! The append-only audit log: one row per state transition (and per creation, rewind,
//! deletion), written by the ledger in the same transaction as the change. SQLite triggers
//! refuse any `UPDATE` or `DELETE` of `events`.
//!
//! `from` is `None` for a creation; `to` is the new state's name, or [`DELETED`] when a reorg
//! rewind removed the row. A non-transition note (an intent mined, a lock's block moved) has
//! `from == to` and says what happened in `detail`.

use rusqlite::{Row, params};

use crate::state::ObjectKind;
use crate::{Result, Tx};

/// The `to` of an event for a row a rewind deleted.
pub const DELETED: &str = "DELETED";

/// One event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Monotonic id (`AUTOINCREMENT`, never reused).
    pub id: i64,
    /// The machine.
    pub kind: ObjectKind,
    /// The object's id (see the crate docs for each kind's form).
    pub object_id: String,
    /// The state left (`None` on creation).
    pub from: Option<String>,
    /// The state entered.
    pub to: String,
    /// The chain height the change belongs to (Ycash height, or Ethereum block for burns).
    pub height: Option<u64>,
    /// Free text: the reason, the txid, the leader, …
    pub detail: Option<String>,
    /// Unix seconds.
    pub at: i64,
}

const COLS: &str = "id, kind, object_id, from_state, to_state, height, detail, at";

fn row(r: &Row<'_>) -> rusqlite::Result<Event> {
    let kind: String = r.get(1)?;
    Ok(Event {
        id: r.get(0)?,
        kind: kind.parse().map_err(|e: crate::StoreError| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, e.into())
        })?,
        object_id: r.get(2)?,
        from: r.get(3)?,
        to: r.get(4)?,
        height: r.get(5)?,
        detail: r.get(6)?,
        at: r.get(7)?,
    })
}

impl Tx<'_> {
    /// Every event of one object, oldest first.
    pub fn events_for(&self, kind: ObjectKind, object_id: &str) -> Result<Vec<Event>> {
        self.all(
            &format!("SELECT {COLS} FROM events WHERE kind = ?1 AND object_id = ?2 ORDER BY id"),
            params![kind.as_str(), object_id],
            row,
        )
    }

    /// Up to `limit` events with `id > after`, oldest first (tail the log).
    pub fn events_since(&self, after: i64, limit: u32) -> Result<Vec<Event>> {
        self.all(
            &format!("SELECT {COLS} FROM events WHERE id > ?1 ORDER BY id LIMIT ?2"),
            params![after, limit],
            row,
        )
    }
}
