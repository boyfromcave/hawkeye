//! The ledger schema as an ordered list of migrations.
//!
//! `PRAGMA user_version` is the number of migrations applied. [`MIGRATIONS`] is append-only:
//! a released migration is never edited; a change is a new entry.

/// Every migration, in order. Entry `i` takes `user_version` from `i` to `i + 1`.
pub const MIGRATIONS: &[&str] = &[V1, V2, V3];

/// Version 1: the H4 ledger.
const V1: &str = r#"
-- Chain cursors (§5.4) and the recent block hashes a Ycash rewind needs.
CREATE TABLE chain_cursor (
    chain       TEXT    PRIMARY KEY CHECK (chain IN ('ycash', 'ethereum')),
    height      INTEGER NOT NULL CHECK (height >= 0),
    hash        BLOB    CHECK (hash IS NULL OR length(hash) = 32),
    updated_at  INTEGER NOT NULL
);

CREATE TABLE chain_blocks (
    chain       TEXT    NOT NULL CHECK (chain IN ('ycash', 'ethereum')),
    height      INTEGER NOT NULL CHECK (height >= 0),
    hash        BLOB    NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (chain, height)
) WITHOUT ROWID;

-- WYEC locks seen on Ycash (§1.2, §4.1). lock_id = SHA256(txid_internal || vout LE).
CREATE TABLE locks (
    lock_id          BLOB    PRIMARY KEY CHECK (length(lock_id) = 32),
    txid             BLOB    NOT NULL CHECK (length(txid) = 32),
    vout             INTEGER NOT NULL CHECK (vout >= 0),
    value_zat        INTEGER NOT NULL CHECK (value_zat >= 0),
    owner_height     INTEGER NOT NULL CHECK (owner_height >= 0),
    destination      BLOB    CHECK (destination IS NULL OR length(destination) = 20),
    block_hash       BLOB    NOT NULL CHECK (length(block_hash) = 32),
    block_height     INTEGER NOT NULL CHECK (block_height >= 0),
    state            TEXT    NOT NULL,
    rejection_reason TEXT,
    exposure         INTEGER NOT NULL DEFAULT 0 CHECK (exposure IN (0, 1)),
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    UNIQUE (txid, vout)
);
CREATE INDEX locks_state  ON locks (state);
CREATE INDEX locks_height ON locks (block_height);

-- BurnToYcash events (§1.3). The natural key is (chain_id, bridge, nonce).
CREATE TABLE burns (
    id              INTEGER PRIMARY KEY,
    chain_id        INTEGER NOT NULL CHECK (chain_id >= 0),
    bridge          BLOB    NOT NULL CHECK (length(bridge) = 20),
    nonce           INTEGER NOT NULL CHECK (nonce >= 0),
    tx_hash         BLOB    NOT NULL CHECK (length(tx_hash) = 32),
    block_number    INTEGER NOT NULL CHECK (block_number >= 0),
    block_hash      BLOB    NOT NULL CHECK (length(block_hash) = 32),
    sender          BLOB    NOT NULL CHECK (length(sender) = 20),
    amount          INTEGER NOT NULL CHECK (amount >= 0),
    recipient       BLOB    NOT NULL CHECK (length(recipient) = 32),
    state           TEXT    NOT NULL,
    leader          BLOB    CHECK (leader IS NULL OR length(leader) = 33),
    assigned_height INTEGER,
    waiting_epoch   INTEGER,
    intent_txid     BLOB,
    intent_vout     INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (chain_id, bridge, nonce),
    CHECK ((intent_txid IS NULL) = (intent_vout IS NULL)),
    FOREIGN KEY (intent_txid, intent_vout) REFERENCES intents (txid, vout)
);
CREATE INDEX burns_state ON burns (state, nonce);
CREATE INDEX burns_block ON burns (block_number);

-- Intents seen on Ycash, mempool or block (§5.3), keyed by the intent output.
CREATE TABLE intents (
    txid              BLOB    NOT NULL CHECK (length(txid) = 32),
    vout              INTEGER NOT NULL CHECK (vout >= 0),
    value_zat         INTEGER NOT NULL CHECK (value_zat >= 0),
    recipient_hash    BLOB    NOT NULL CHECK (length(recipient_hash) = 32),
    vault_hash        BLOB    NOT NULL CHECK (length(vault_hash) = 32),
    origin_txid       BLOB    CHECK (origin_txid IS NULL OR length(origin_txid) = 32),
    origin_vout       INTEGER,
    signer_key        BLOB    CHECK (signer_key IS NULL OR length(signer_key) = 33),
    memo              BLOB,
    classification    TEXT,
    matched_burn      INTEGER REFERENCES burns (id),
    first_seen_height INTEGER NOT NULL CHECK (first_seen_height >= 0),
    confirmed_height  INTEGER,
    state             TEXT    NOT NULL,
    cancel_txid       BLOB    CHECK (cancel_txid IS NULL OR length(cancel_txid) = 32),
    cancel_height     INTEGER,
    cancel_by_us      INTEGER NOT NULL DEFAULT 0 CHECK (cancel_by_us IN (0, 1)),
    released_txid     BLOB    CHECK (released_txid IS NULL OR length(released_txid) = 32),
    released_height   INTEGER,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    PRIMARY KEY (txid, vout),
    CHECK ((origin_txid IS NULL) = (origin_vout IS NULL))
);
CREATE INDEX intents_state ON intents (state);
CREATE INDEX intents_burn  ON intents (matched_burn);

-- WYEC vault outputs of the set (§3.1 rolls and drain order).
CREATE TABLE vaults (
    txid            BLOB    NOT NULL CHECK (length(txid) = 32),
    vout            INTEGER NOT NULL CHECK (vout >= 0),
    value_zat       INTEGER NOT NULL CHECK (value_zat >= 0),
    owner_height    INTEGER NOT NULL CHECK (owner_height >= 0),
    created_height  INTEGER NOT NULL CHECK (created_height >= 0),
    state           TEXT    NOT NULL,
    spent_txid      BLOB    CHECK (spent_txid IS NULL OR length(spent_txid) = 32),
    spent_height    INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);
CREATE INDEX vaults_state ON vaults (state, owner_height);

-- Sign-once, EIP-712 Mint (HK-7): one (amount, to, digest) per lockId, ever.
CREATE TABLE sign_once_mint (
    lock_id    BLOB    PRIMARY KEY CHECK (length(lock_id) = 32)
                       REFERENCES locks (lock_id) ON DELETE RESTRICT,
    amount     INTEGER NOT NULL CHECK (amount >= 0),
    recipient  BLOB    NOT NULL CHECK (length(recipient) = 20),
    digest     BLOB    NOT NULL CHECK (length(digest) = 32),
    signature  BLOB    NOT NULL CHECK (length(signature) = 65),
    signed_at  INTEGER NOT NULL
);

-- Sign-once, Ycash set and act signatures requested through the node (mirrors the node's
-- guard, upgrade finding (70)): one signed transaction per (domain, set, prevout).
CREATE TABLE sign_once_ycash (
    domain        TEXT    NOT NULL CHECK (domain IN ('ycash-unlock', 'ycash-cancel', 'ycash-act')),
    set_id        BLOB    NOT NULL CHECK (length(set_id) = 32),
    prevout_txid  BLOB    NOT NULL CHECK (length(prevout_txid) = 32),
    prevout_vout  INTEGER NOT NULL CHECK (prevout_vout >= 0),
    sighash       BLOB    NOT NULL CHECK (length(sighash) = 32),
    built_hex     TEXT    NOT NULL,
    signed_hex    TEXT    NOT NULL,
    signed_at     INTEGER NOT NULL,
    PRIMARY KEY (domain, set_id, prevout_txid, prevout_vout)
) WITHOUT ROWID;

-- Slash cases (§2.3, §5.3). (fault, subject, target_key) is unique: one case per fault.
CREATE TABLE slash_cases (
    id              INTEGER PRIMARY KEY,
    target_key      BLOB    NOT NULL CHECK (length(target_key) = 33),
    fault           TEXT    NOT NULL,
    subject         BLOB    NOT NULL,
    evidence        TEXT    NOT NULL CHECK (json_valid(evidence)),
    opened_height   INTEGER,
    state           TEXT    NOT NULL,
    my_vote         TEXT,
    act_hex         TEXT,
    txid            BLOB    CHECK (txid IS NULL OR length(txid) = 32),
    slashed_height  INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (fault, subject, target_key)
);
CREATE INDEX slash_cases_state ON slash_cases (state);

-- The audit log: every state transition, append-only.
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,
    object_id   TEXT    NOT NULL,
    from_state  TEXT,
    to_state    TEXT    NOT NULL,
    height      INTEGER,
    detail      TEXT,
    at          INTEGER NOT NULL
);
CREATE INDEX events_object ON events (kind, object_id, id);

CREATE TRIGGER events_append_only_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER events_append_only_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;

CREATE TRIGGER sign_once_mint_immutable_update BEFORE UPDATE ON sign_once_mint
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_mint_immutable_delete BEFORE DELETE ON sign_once_mint
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_ycash_immutable_update BEFORE UPDATE ON sign_once_ycash
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_ycash_immutable_delete BEFORE DELETE ON sign_once_ycash
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
"#;

/// Version 2: the working state a restarted daemon resumes from (deferred mint checks, slash
/// votes gathered and given, set signatures seen for equivocation detection).
const V2: &str = r#"
-- Minted / MintProposed events waiting for this attestor's Ycash view (§5.3 step 2): a restart
-- re-judges them instead of losing them behind the advanced Ethereum cursor.
CREATE TABLE pending_mints (
    lock_id      BLOB    NOT NULL CHECK (length(lock_id) = 32),
    tx_hash      BLOB    NOT NULL CHECK (length(tx_hash) = 32),
    recipient    BLOB    NOT NULL CHECK (length(recipient) = 20),
    amount       INTEGER NOT NULL CHECK (amount >= 0),
    block        INTEGER NOT NULL CHECK (block >= 0),
    since_height INTEGER NOT NULL CHECK (since_height >= 0),
    proposal     INTEGER NOT NULL CHECK (proposal IN (0, 1)),
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (lock_id, tx_hash)
) WITHOUT ROWID;

-- The case owner's act with every signature gathered so far (§5.3 step 3).
CREATE TABLE slash_progress (
    case_id     INTEGER PRIMARY KEY REFERENCES slash_cases (id),
    act_hex     TEXT    NOT NULL,
    complete    INTEGER NOT NULL CHECK (complete IN (0, 1)),
    signatures  INTEGER NOT NULL,
    required    INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- The peers that signed a case's act (owner side): a restart does not ask them again.
CREATE TABLE slash_votes (
    case_id     INTEGER NOT NULL REFERENCES slash_cases (id),
    peer        TEXT    NOT NULL,
    signatures  INTEGER NOT NULL,
    complete    INTEGER NOT NULL CHECK (complete IN (0, 1)),
    at          INTEGER NOT NULL,
    PRIMARY KEY (case_id, peer)
) WITHOUT ROWID;

-- The votes this attestor gave (peer side), keyed by the act's prevout like its sign-once
-- record: a repeated request is answered from here, with the verdict it was given for.
CREATE TABLE slash_votes_given (
    act_txid    BLOB    NOT NULL CHECK (length(act_txid) = 32),
    act_vout    INTEGER NOT NULL CHECK (act_vout >= 0),
    fault       TEXT    NOT NULL,
    target_key  BLOB    NOT NULL CHECK (length(target_key) = 33),
    subject     BLOB    NOT NULL,
    signed_hex  TEXT    NOT NULL,
    complete    INTEGER NOT NULL CHECK (complete IN (0, 1)),
    signatures  INTEGER NOT NULL,
    required    INTEGER NOT NULL,
    reason      TEXT    NOT NULL,
    at          INTEGER NOT NULL,
    PRIMARY KEY (act_txid, act_vout)
) WITHOUT ROWID;

-- Set signatures seen on Ycash, by (set, prevout, key): two different (role, sighash) by one key
-- over one prevout are an equivocation (§2.3 row 1), across restarts.
CREATE TABLE set_sigs_seen (
    set_id        BLOB    NOT NULL CHECK (length(set_id) = 32),
    prevout_txid  BLOB    NOT NULL CHECK (length(prevout_txid) = 32),
    prevout_vout  INTEGER NOT NULL CHECK (prevout_vout >= 0),
    member_key    BLOB    NOT NULL CHECK (length(member_key) = 33),
    role          INTEGER NOT NULL CHECK (role IN (1, 2)),
    sighash       BLOB    NOT NULL CHECK (length(sighash) = 32),
    signature     BLOB    NOT NULL CHECK (length(signature) = 65),
    txid          BLOB    NOT NULL CHECK (length(txid) = 32),
    at            INTEGER NOT NULL,
    PRIMARY KEY (set_id, prevout_txid, prevout_vout, member_key, role, sighash)
) WITHOUT ROWID;

-- SET_EQUIVOCATION proofs this attestor broadcast: one per (prevout, key).
CREATE TABLE equivocations_sent (
    prevout_txid  BLOB    NOT NULL CHECK (length(prevout_txid) = 32),
    prevout_vout  INTEGER NOT NULL CHECK (prevout_vout >= 0),
    member_key    BLOB    NOT NULL CHECK (length(member_key) = 33),
    txid          BLOB    CHECK (txid IS NULL OR length(txid) = 32),
    at            INTEGER NOT NULL,
    PRIMARY KEY (prevout_txid, prevout_vout, member_key)
) WITHOUT ROWID;
"#;

/// Version 3: sign-once records for the optimistic mint's other EIP-712 signatures (wyec @
/// `cad126a`, wyec-contract-design.md §4.5): `Challenge(lockId, proposalId)` vetoes, and the
/// `Mint` signatures of the `rogue-mint` drill (no lock behind them, so not in `sign_once_mint`).
const V3: &str = r#"
-- Sign-once, EIP-712 Challenge: one signature per (lockId, proposalId), ever. proposal_id is the
-- contract's uint96 counter as a decimal string (it exceeds SQLite's INTEGER). The proposal
-- judged (proposer, amount, recipient) is kept with it: what was vetoed and why.
CREATE TABLE sign_once_challenge (
    lock_id      BLOB    NOT NULL CHECK (length(lock_id) = 32),
    proposal_id  TEXT    NOT NULL CHECK (proposal_id GLOB '[1-9]*' AND proposal_id NOT GLOB '*[^0-9]*'
                                         AND length(proposal_id) <= 29),
    proposer     BLOB    NOT NULL CHECK (length(proposer) = 20),
    amount       INTEGER NOT NULL CHECK (amount >= 0),
    recipient    BLOB    NOT NULL CHECK (length(recipient) = 20),
    reason       TEXT    NOT NULL,
    digest       BLOB    NOT NULL CHECK (length(digest) = 32),
    signature    BLOB    NOT NULL CHECK (length(signature) = 65),
    signed_at    INTEGER NOT NULL,
    PRIMARY KEY (lock_id, proposal_id)
) WITHOUT ROWID;

-- Sign-once, the drill-only rogue Mint (drill D-5, `hawkeye rogue-mint`): one per lockId.
CREATE TABLE sign_once_drill_mint (
    lock_id    BLOB    PRIMARY KEY CHECK (length(lock_id) = 32),
    amount     INTEGER NOT NULL CHECK (amount >= 0),
    recipient  BLOB    NOT NULL CHECK (length(recipient) = 20),
    digest     BLOB    NOT NULL CHECK (length(digest) = 32),
    signature  BLOB    NOT NULL CHECK (length(signature) = 65),
    signed_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TRIGGER sign_once_challenge_immutable_update BEFORE UPDATE ON sign_once_challenge
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_challenge_immutable_delete BEFORE DELETE ON sign_once_challenge
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_drill_mint_immutable_update BEFORE UPDATE ON sign_once_drill_mint
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
CREATE TRIGGER sign_once_drill_mint_immutable_delete BEFORE DELETE ON sign_once_drill_mint
BEGIN SELECT RAISE(ABORT, 'sign-once records are immutable'); END;
"#;
