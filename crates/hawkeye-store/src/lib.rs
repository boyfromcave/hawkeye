//! `hawkeye-store`: the attestor's SQLite ledger (plan `docs/hawkeye-bridge-plan.md` §5, §6;
//! phase H4). Synchronous, one file per attestor, WAL, foreign keys on, `synchronous = FULL`
//! (a sign-once record must be durable before its signature leaves the process).
//!
//! | Module | Contents |
//! |---|---|
//! | [`state`] | the §5.1 machines ([`LockState`], [`BurnState`], [`IntentState`], [`VaultState`], [`SlashState`]) and their edge tables |
//! | [`accounts`] | foreign-chain accounts and guardians as ledger text (v4: Ethereum or NEAR) |
//! | [`locks`] | the bridge's locks (§1.2, §4.1; `WYEC` or `NYEC`) |
//! | [`burns`] | burns on the foreign chain (§1.3), the matcher's burn lookup |
//! | [`intents`] | intents seen on Ycash and their classification (§3.2, §5.3) |
//! | [`vaults`] | the set's vault outputs (§3.1) |
//! | [`signonce`] | sign-once records: the bridge's `Mint` attestation by `lockId`, `Challenge` by `(lockId, proposalId)`, the drill's rogue `Mint`, Ycash set/act signatures by `(set, prevout)` (HK-7), unlocks also by the burn they pay (v6, HK-13) |
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

pub mod accounts;
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

pub use accounts::{Account, Guardian};
pub use burns::{BurnKey, BurnRecord, NewBurn, OVER_CAP_EPOCH};
pub use chain::{Cursor, RewindReport};
pub use error::{Result, SignerError, StoreError};
pub use events::Event;
pub use intents::{IntentRecord, NewIntent, classification_code};
pub use locks::{LockRecord, NewLock};
pub use progress::{PendingMintRecord, SeenSetSig, SlashProgress, VoteGiven};
pub use signonce::{
    ChallengeSignRecord, ChallengedProposal, MintSignRecord, UnlockBurn, UnlockBurnRecord,
    UnlockOrigin, YcashSignKey, YcashSignRecord,
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

/// The single-instance lock (W3-B-10): an exclusive advisory lock on `<ledger>.lock`, held
/// for the life of the value and released by the kernel when the process exits.
#[derive(Debug)]
pub struct InstanceLock {
    _file: std::fs::File,
}

impl Store {
    /// Take the single-instance lock beside the ledger at `path` (`hawkeye.db` →
    /// `hawkeye.db.lock`, mode `0600`). Fails with [`StoreError::Invalid`] naming the holder's
    /// pid when another process holds it. Covers one host and a local filesystem only.
    pub fn lock_instance(path: impl AsRef<Path>) -> Result<InstanceLock> {
        use std::io::{Read, Seek, Write};
        let mut lock = path.as_ref().as_os_str().to_owned();
        lock.push(".lock");
        let lock = std::path::PathBuf::from(lock);
        create_private(&lock)?;
        let io =
            |e: std::io::Error| StoreError::Invalid(format!("cannot lock {}: {e}", lock.display()));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .map_err(io)?;
        match f.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut holder = String::new();
                let _ = f.read_to_string(&mut holder);
                return Err(StoreError::Invalid(format!(
                    "ledger {} is in use by pid {}: one hawkeye per ledger (docs/operations.md section 2)",
                    path.as_ref().display(),
                    holder.trim()
                )));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(io(e)),
        }
        f.set_len(0).map_err(io)?;
        f.rewind().map_err(io)?;
        write!(f, "{}", std::process::id()).map_err(io)?;
        Ok(InstanceLock { _file: f })
    }

    /// Open (creating if absent) the ledger file at `path` and migrate it to the current
    /// schema. A new ledger is created mode `0600` before SQLite opens it, and its `-wal` /
    /// `-shm` files are held to `0600` too (remedial report 05/L-2: the sign-once ledger is
    /// owner-only; SQLite's unix VFS gives `-wal`/`-shm` the main file's mode since 3.7, and the
    /// mode is set again here regardless).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        create_private(path)?;
        let s = Self::init(Connection::open(path)?)?;
        for ext in ["-wal", "-shm"] {
            let mut side = path.as_os_str().to_owned();
            side.push(ext);
            restrict_private(Path::new(&side))?;
        }
        Ok(s)
    }

    /// Open an existing ledger **read-only**, without migrating it or touching its files
    /// (`hawkeye audit-ledger`, remedial report 05/M-3): an older binary never rewrites a newer
    /// ledger, a restored copy is inspected as it is. Refused unless its schema is exactly this
    /// build's (a newer one: [`StoreError::SchemaTooNew`]; an older one would need the
    /// migration a read-only open must not run).
    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self> {
        use rusqlite::OpenFlags;
        let path = path.as_ref();
        if !path.is_file() {
            return Err(StoreError::Invalid(format!(
                "no ledger at {}",
                path.display()
            )));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let found: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let supported = u32::try_from(schema::MIGRATIONS.len()).expect("few migrations");
        if found > supported {
            return Err(StoreError::SchemaTooNew { found, supported });
        }
        if found < supported {
            return Err(StoreError::Invalid(format!(
                "the ledger is schema v{found}, this build reads v{supported}: a read-only open \
                 does not migrate it (stop, back it up, and let `hawkeye run` migrate it first)"
            )));
        }
        Ok(Self {
            conn,
            clock: system_clock,
        })
    }

    /// An in-memory ledger (tests, simulations).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        // In-memory databases answer "memory"; files answer "wal".
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA synchronous = FULL;")?;
        // SQLite's table-rebuild procedure: migrations run with foreign keys off, each checked
        // with `foreign_key_check` before it commits; then they are enabled for good.
        conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
        let migrated = migrate(&mut conn);
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrated?;
        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        if fk != 1 {
            return Err(StoreError::corrupt("foreign keys could not be enabled"));
        }
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

    /// Run `f` in one deferred (read) transaction, always rolled back: the only way to read a
    /// ledger opened with [`Store::open_readonly`].
    pub fn read<T, E>(
        &mut self,
        f: impl FnOnce(&Tx<'_>) -> core::result::Result<T, E>,
    ) -> core::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        let now = (self.clock)();
        let inner = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(StoreError::from)?;
        let t = Tx { inner, now };
        let v = f(&t);
        t.inner.rollback().map_err(StoreError::from)?;
        v
    }

    /// [`Tx::sign_once_mint`] in its own transaction.
    pub fn sign_once_mint<F, E>(
        &mut self,
        deployment: &hawkeye_core::Deployment,
        lock_id: &hawkeye_core::bytes::Hash32,
        amount: u64,
        to: &Account,
        digest: &hawkeye_core::bytes::Hash32,
        sign: F,
    ) -> Result<MintSignRecord>
    where
        F: FnOnce(&hawkeye_core::bytes::Hash32) -> core::result::Result<[u8; 65], E>,
        E: Into<SignerError>,
    {
        self.tx(|t| t.sign_once_mint(deployment, lock_id, amount, to, digest, sign))
    }

    /// The schema-v6 backfill of the per-burn unlock record (remedial report 05/H-1 §4.3): once
    /// per ledger (`meta.backfill_unlock_burns`), one `leader` row per pre-v6 unlock record
    /// whose signed transaction names a burn. `decode` maps a signed unlock's hex to the burn its
    /// memo names (the daemon passes the `HKB1`/`HKN1` memo decoder; this crate decodes no
    /// transactions). Returns the rows inserted (0 when already done).
    pub fn backfill_unlock_burns(
        &mut self,
        decode: impl Fn(&str) -> Option<(hawkeye_core::Deployment, u64)>,
    ) -> Result<usize> {
        self.tx(|t| {
            if t.meta(signonce::BACKFILL_UNLOCK_BURNS)?.as_deref() == Some("done") {
                return Ok(0);
            }
            t.backfill_unlock_burns(&decode)
        })
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

/// Create `path` empty with mode `0600` if it does not exist (unix).
#[cfg(unix)]
fn create_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(StoreError::corrupt(format!(
            "cannot create the ledger {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(not(unix))]
fn create_private(_path: &Path) -> Result<()> {
    Ok(())
}

/// Clear the group and world bits of `path` if it exists (unix).
#[cfg(unix)]
fn restrict_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Ok(m) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = m.permissions().mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o700))
            .map_err(|e| StoreError::corrupt(format!("cannot restrict {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private(_path: &Path) -> Result<()> {
    Ok(())
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
        let violations: i64 =
            t.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if violations != 0 {
            return Err(StoreError::corrupt(format!(
                "migration to v{} leaves {violations} foreign-key violations",
                i + 1
            )));
        }
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
