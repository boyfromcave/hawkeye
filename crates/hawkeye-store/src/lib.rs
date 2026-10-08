//! `hawkeye-store`: the attestor's SQLite ledger (plan `docs/hawkeye-bridge-plan.md` §5, §6;
//! phase H4). Synchronous, one file per attestor, WAL, foreign keys on, `synchronous = FULL`
//! (a sign-once record must be durable before its signature leaves the process).
//!
//! | Module | Contents |
//! |---|---|
//! | [`state`] | the §5.1 machines ([`LockState`], [`BurnState`], [`IntentState`], [`VaultState`], [`SlashState`]) and their edge tables |
//! | [`locks`] | `WYEC` locks (§1.2, §4.1) |
//! | [`burns`] | `BurnToYcash` events (§1.3), the matcher's burn lookup |
//! | [`intents`] | intents seen on Ycash and their classification (§3.2, §5.3) |
//! | [`vaults`] | the set's vault outputs (§3.1) |
//! | [`signonce`] | sign-once records: EIP-712 `Mint` by `lockId`, `Challenge` by `(lockId, proposalId)`, the drill's rogue `Mint`, Ycash set/act signatures by `(set, prevout)` (HK-7) |
//! | [`slash`] | slash cases (§2.3, §5.3) |
//! | [`progress`] | restart state (v2): deferred mint checks, slash votes gathered and given, set signatures seen |
//! | [`chain`] | chain cursors and reorg rewinds (§5.4) |
//! | [`events`] | the append-only audit log |
//!
//! Every read and write goes through a [`Tx`], obtained from [`Store::tx`]: the closure's
//! writes commit together or not at all. A transaction is `BEGIN IMMEDIATE`, so it holds the
//! write lock from its start.
//!
//! Every state change goes through a typed `transition_*` (or a payload-carrying call such as
//! [`Tx::assign_burn`]) that checks the edge against the machine and appends to the event log
//! in the same transaction. Object ids in the event log are: a lock's `lockId` as hex, a
//! burn's [`BurnKey`] display (`chainId:bridge:nonce`), an intent's or vault's
//! [`OutPoint`](hawkeye_core::OutPoint) display (`txid:vout`, display-order txid), a slash
//! case's number.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

pub mod burns;
pub mod chain;
mod error;
pub mod events;
pub mod intents;
pub mod locks;
pub mod progress;
pub mod schema;
pub mod signonce;
pub mod slash;
pub mod state;
pub mod vaults;

pub use burns::{BurnKey, BurnRecord, NewBurn};
pub use chain::{Cursor, RewindReport};
pub use error::{Result, SignerError, StoreError};
pub use events::Event;
pub use intents::{IntentRecord, NewIntent, classification_code};
pub use locks::{LockRecord, NewLock};
pub use progress::{PendingMintRecord, SeenSetSig, SlashProgress, VoteGiven};
pub use signonce::{
    ChallengeSignRecord, ChallengedProposal, MintSignRecord, YcashSignKey, YcashSignRecord,
};
pub use slash::{NewSlashCase, SlashCaseRecord};
pub use state::{
    BurnState, Chain, Edge, FaultKind, IntentState, LockState, Machine, ObjectKind, SignDomain,
    SlashState, VaultState,
};
pub use vaults::{NewVault, VaultRecord};

/// The ledger.
pub struct Store {
    conn: Connection,
    clock: fn() -> i64,
}

fn system_clock() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl Store {
    /// Open (creating if absent) the ledger file at `path` and migrate it to the current
    /// schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// An in-memory ledger (tests, simulations).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        // In-memory databases answer "memory"; files answer "wal".
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;")?;
        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        if fk != 1 {
            return Err(StoreError::corrupt("foreign keys could not be enabled"));
        }
        migrate(&mut conn)?;
        Ok(Self {
            conn,
            clock: system_clock,
        })
    }

    /// The schema version (`PRAGMA user_version`).
    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// The SQLite journal mode (`wal` for a file ledger).
    pub fn journal_mode(&self) -> Result<String> {
        Ok(self
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))?)
    }

    /// Replace the wall clock (unix seconds) used for `created_at` / `updated_at` / event
    /// times; for deterministic tests and simulations.
    pub fn set_clock(&mut self, clock: fn() -> i64) {
        self.clock = clock;
    }

    /// Run `f` in one `BEGIN IMMEDIATE` transaction: commit if it returns `Ok`, roll back if it
    /// returns `Err` (or panics).
    pub fn tx<T, E>(
        &mut self,
        f: impl FnOnce(&Tx<'_>) -> core::result::Result<T, E>,
    ) -> core::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        let now = (self.clock)();
        let inner = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let t = Tx { inner, now };
        let v = f(&t)?;
        t.inner.commit().map_err(StoreError::from)?;
        Ok(v)
    }

    /// [`Tx::sign_once_mint`] in its own transaction.
    pub fn sign_once_mint<F, E>(
        &mut self,
        lock_id: &hawkeye_core::bytes::Hash32,
        amount: u64,
        to: &hawkeye_core::EthAddress,
        digest: &hawkeye_core::bytes::Hash32,
        sign: F,
    ) -> Result<MintSignRecord>
    where
        F: FnOnce(&hawkeye_core::bytes::Hash32) -> core::result::Result<[u8; 65], E>,
        E: Into<SignerError>,
    {
        self.tx(|t| t.sign_once_mint(lock_id, amount, to, digest, sign))
    }

    /// [`Tx::sign_once_ycash`] in its own transaction.
    pub fn sign_once_ycash<F, E>(
        &mut self,
        key: &YcashSignKey,
        built_hex: &str,
        sign: F,
    ) -> Result<YcashSignRecord>
    where
        F: FnOnce(&str) -> core::result::Result<(String, hawkeye_core::bytes::Hash32), E>,
        E: Into<SignerError>,
    {
        self.tx(|t| t.sign_once_ycash(key, built_hex, sign))
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let supported = u32::try_from(schema::MIGRATIONS.len()).expect("few migrations");
    if current > supported {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported,
        });
    }
    for (i, sql) in schema::MIGRATIONS.iter().enumerate().skip(current as usize) {
        let t = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        t.execute_batch(sql)?;
        t.pragma_update(None, "user_version", i + 1)?;
        t.commit()?;
    }
    Ok(())
}

/// An open ledger transaction. Every typed API of the ledger is a method of `Tx`.
pub struct Tx<'a> {
    inner: rusqlite::Transaction<'a>,
    now: i64,
}

impl Tx<'_> {
    /// The transaction's timestamp (unix seconds), used for every row it writes.
    pub fn now(&self) -> i64 {
        self.now
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.inner
    }

    /// Append one event (the only writer of `events`).
    pub(crate) fn log(
        &self,
        kind: ObjectKind,
        object_id: &str,
        from: Option<&str>,
        to: &str,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO events (kind, object_id, from_state, to_state, height, detail, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![kind.as_str(), object_id, from, to, height, detail, self.now],
        )?;
        Ok(())
    }

    /// Read one row as `T`, `None` if absent.
    pub(crate) fn one<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        f: impl FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>> {
        Ok(self.conn().query_row(sql, params, f).optional()?)
    }

    /// Read every row as `T`.
    pub(crate) fn all<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        f: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>> {
        let mut st = self.conn().prepare(sql)?;
        let rows = st.query_map(params, f)?;
        Ok(rows.collect::<rusqlite::Result<Vec<T>>>()?)
    }
}

/// Lower-case hex (event ids, error keys).
pub(crate) fn hx(b: &[u8]) -> String {
    hex::encode(b)
}
