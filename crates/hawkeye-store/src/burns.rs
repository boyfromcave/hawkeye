//! Burns on the foreign chain (plan §1.3; the Burn machine of §5.1): Ethereum `BurnToYcash`
//! events, NEAR `BurnRecord`s.

use core::fmt;

use hawkeye_core::bytes::Hash32;
use hawkeye_core::matcher::{Burn, Consumer};
use hawkeye_core::{Deployment, EthAddress, OutPoint, PubKey33};

use crate::accounts::{Account, SqlAccount};
use rusqlite::{Row, params};

use crate::state::{BurnState, IntentState, ObjectKind, check_forward};
use crate::{Result, StoreError, Tx};

/// A burn's natural key: the deployment it was burned on and its nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BurnKey {
    /// Chain id and bridge address.
    pub deployment: Deployment,
    /// The bridge's burn nonce.
    pub nonce: u64,
}

impl BurnKey {
    /// A key.
    pub fn new(deployment: Deployment, nonce: u64) -> Self {
        Self { deployment, nonce }
    }
}

impl fmt::Display for BurnKey {
    /// `chainId:bridge:nonce`, the bridge in EIP-55 form: the event-log id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.deployment.chain_id, self.deployment.bridge, self.nonce
        )
    }
}

/// A burn as read from the foreign chain (an Ethereum log, a NEAR burn record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBurn {
    /// The burn's key.
    pub key: BurnKey,
    /// The Ethereum transaction hash; NEAR: `SHA256(borsh(BurnRecord))` (the `HKN1` memo's
    /// `data`).
    pub tx_hash: Hash32,
    /// The block number.
    pub block_number: u64,
    /// The block hash.
    pub block_hash: Hash32,
    /// The burner.
    pub from: Account,
    /// The amount in wYEC base units (= zatoshi).
    pub amount: u64,
    /// The raw `ycashRecipient` bytes32 (§4.2), decoded or not.
    pub recipient: [u8; 32],
    /// Whether the block is finalized (`FINALIZED`) or only `latest` (`SEEN`).
    pub finalized: bool,
}

/// A burn row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnRecord {
    /// The burn's key.
    pub key: BurnKey,
    /// The Ethereum transaction hash (NEAR: the burn record's hash).
    pub tx_hash: Hash32,
    /// The block number.
    pub block_number: u64,
    /// The block hash.
    pub block_hash: Hash32,
    /// The burner.
    pub from: Account,
    /// The amount in base units.
    pub amount: u64,
    /// The raw recipient.
    pub recipient: [u8; 32],
    /// The machine state.
    pub state: BurnState,
    /// The assigned leader's member key (`ASSIGNED` and later).
    pub leader: Option<PubKey33>,
    /// The Ycash height of the (latest) assignment: the takeover deadline counts from here.
    pub assigned_height: Option<u32>,
    /// The rate-limit epoch it waits for (`WAITING_CAP`).
    pub waiting_epoch: Option<u64>,
    /// The intent output paying it (`INTENT_*`, `RELEASED`).
    pub intent: Option<OutPoint>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

const COLS: &str = "chain_id, bridge, nonce, tx_hash, block_number, block_hash, sender, amount, \
                    recipient, state, leader, assigned_height, waiting_epoch, intent_txid, \
                    intent_vout, created_at, updated_at";

fn row(r: &Row<'_>) -> rusqlite::Result<BurnRecord> {
    let intent = match (
        r.get::<_, Option<Hash32>>(13)?,
        r.get::<_, Option<u32>>(14)?,
    ) {
        (Some(t), Some(v)) => Some(OutPoint::new(t, v)),
        _ => None,
    };
    Ok(BurnRecord {
        key: BurnKey::new(
            Deployment {
                chain_id: r.get(0)?,
                bridge: EthAddress(r.get(1)?),
            },
            r.get(2)?,
        ),
        tx_hash: r.get(3)?,
        block_number: r.get(4)?,
        block_hash: r.get(5)?,
        from: r.get::<_, SqlAccount>(6)?.0,
        amount: r.get(7)?,
        recipient: r.get(8)?,
        state: r.get(9)?,
        leader: r.get(10)?,
        assigned_height: r.get(11)?,
        waiting_epoch: r.get(12)?,
        intent,
        created_at: r.get(15)?,
        updated_at: r.get(16)?,
    })
}

impl Tx<'_> {
    /// Record a burn, or update the stored one.
    ///
    /// - absent: inserted `SEEN` (or `FINALIZED` when `new.finalized`);
    /// - stored `SEEN`: replaced by `new` (an unfinalized reorg may move the burn or even give
    ///   the nonce to another transaction), and moved to `FINALIZED` when `new.finalized`;
    /// - stored finalized: idempotent if identical, [`StoreError::Duplicate`] otherwise.
    pub fn insert_burn(&self, new: &NewBurn) -> Result<BurnRecord> {
        let k = &new.key;
        let oid = k.to_string();
        let target = if new.finalized {
            BurnState::Finalized
        } else {
            BurnState::Seen
        };
        if let Some(old) = self.burn(k)? {
            let same = old.tx_hash == new.tx_hash
                && old.block_number == new.block_number
                && old.block_hash == new.block_hash
                && old.from == new.from
                && old.amount == new.amount
                && old.recipient == new.recipient;
            if old.state != BurnState::Seen {
                return if same {
                    Ok(old)
                } else {
                    Err(StoreError::Duplicate {
                        kind: ObjectKind::Burn,
                        id: oid,
                    })
                };
            }
            if !same {
                self.conn().execute(
                    "UPDATE burns SET tx_hash = ?4, block_number = ?5, block_hash = ?6,
                            sender = ?7, amount = ?8, recipient = ?9, updated_at = ?10
                     WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
                    params![
                        k.deployment.chain_id,
                        k.deployment.bridge.0,
                        k.nonce,
                        new.tx_hash,
                        new.block_number,
                        new.block_hash,
                        SqlAccount(new.from.clone()),
                        new.amount,
                        new.recipient,
                        self.now(),
                    ],
                )?;
                self.log(
                    ObjectKind::Burn,
                    &oid,
                    Some(BurnState::Seen.as_str()),
                    BurnState::Seen.as_str(),
                    Some(new.block_number),
                    Some("replaced (unfinalized reorg)"),
                )?;
            }
            if new.finalized {
                self.transition_burn(k, BurnState::Finalized, Some(new.block_number), None)?;
            }
            return self.require_burn(k);
        }
        self.conn().execute(
            "INSERT INTO burns (chain_id, bridge, nonce, tx_hash, block_number, block_hash,
                                sender, amount, recipient, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                k.deployment.chain_id,
                k.deployment.bridge.0,
                k.nonce,
                new.tx_hash,
                new.block_number,
                new.block_hash,
                SqlAccount(new.from.clone()),
                new.amount,
                new.recipient,
                target,
                self.now(),
            ],
        )?;
        self.log(
            ObjectKind::Burn,
            &oid,
            None,
            target.as_str(),
            Some(new.block_number),
            None,
        )?;
        self.require_burn(k)
    }

    /// The burn with this key.
    pub fn burn(&self, k: &BurnKey) -> Result<Option<BurnRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM burns WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3"),
            params![k.deployment.chain_id, k.deployment.bridge.0, k.nonce],
            row,
        )
    }

    pub(crate) fn require_burn(&self, k: &BurnKey) -> Result<BurnRecord> {
        self.burn(k)?.ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::Burn,
            id: k.to_string(),
        })
    }

    pub(crate) fn burn_rowid(&self, k: &BurnKey) -> Result<i64> {
        self.one(
            "SELECT id FROM burns WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
            params![k.deployment.chain_id, k.deployment.bridge.0, k.nonce],
            |r| r.get(0),
        )?
        .ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::Burn,
            id: k.to_string(),
        })
    }

    /// Every burn in `state` of one deployment, FIFO by nonce (§5.5).
    pub fn burns_in_state(
        &self,
        deployment: &Deployment,
        state: BurnState,
    ) -> Result<Vec<BurnRecord>> {
        self.all(
            &format!(
                "SELECT {COLS} FROM burns WHERE chain_id = ?1 AND bridge = ?2 AND state = ?3
                 ORDER BY nonce"
            ),
            params![deployment.chain_id, deployment.bridge.0, state],
            row,
        )
    }

    /// The burn whose intent is `op`, if any.
    pub fn burn_for_intent(&self, op: &OutPoint) -> Result<Option<BurnRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM burns WHERE intent_txid = ?1 AND intent_vout = ?2"),
            params![op.txid, op.vout],
            row,
        )
    }

    /// The matcher's view of a burn (`hawkeye_core::matcher::classify_intent`'s `lookup`):
    /// any burn past `SEEN` (an orphaned one included, so the matcher can say so), with
    /// `consumed_by` = the earliest-seen intent matched to it that is mined and not cancelled
    /// (§3.2).
    pub fn matcher_burn(&self, deployment: &Deployment, nonce: u64) -> Result<Option<Burn>> {
        let k = BurnKey::new(*deployment, nonce);
        let Some(b) = self.burn(&k)? else {
            return Ok(None);
        };
        if b.state == BurnState::Seen {
            return Ok(None);
        }
        let id = self.burn_rowid(&k)?;
        let consumed_by = self.one(
            "SELECT txid, first_seen_height FROM intents
             WHERE matched_burn = ?1 AND confirmed_height IS NOT NULL AND state IN (?2, ?3)
             ORDER BY first_seen_height, txid LIMIT 1",
            params![id, IntentState::Matched, IntentState::Released],
            |r| {
                Ok(Consumer {
                    txid: r.get(0)?,
                    first_seen: r.get(1)?,
                })
            },
        )?;
        Ok(Some(Burn {
            nonce,
            tx_hash: b.tx_hash,
            amount: b.amount,
            recipient: b.recipient,
            consumed_by,
        }))
    }

    /// Move a burn along a forward edge that carries no payload; returns the state it left.
    ///
    /// `ASSIGNED`, `WAITING_CAP` and `INTENT_PENDING` carry data: use [`Tx::assign_burn`],
    /// [`Tx::burn_wait_cap`], [`Tx::burn_intent_pending`]. `CANCELLED → FINALIZED` clears the
    /// leader, epoch and intent (the burn is up for reassignment).
    pub fn transition_burn(
        &self,
        k: &BurnKey,
        to: BurnState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<BurnState> {
        check_forward(&k.to_string(), self.require_burn(k)?.state, to)?;
        if matches!(
            to,
            BurnState::Assigned | BurnState::WaitingCap | BurnState::IntentPending
        ) {
            return Err(StoreError::Invalid(format!(
                "{to} carries data: use assign_burn / burn_wait_cap / burn_intent_pending"
            )));
        }
        let from = self.burn_edge(k, to, height, detail)?;
        if from == BurnState::Cancelled && to == BurnState::Finalized {
            self.conn().execute(
                "UPDATE burns SET leader = NULL, assigned_height = NULL, waiting_epoch = NULL,
                                  intent_txid = NULL, intent_vout = NULL
                 WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
                params![k.deployment.chain_id, k.deployment.bridge.0, k.nonce],
            )?;
        }
        Ok(from)
    }

    /// `FINALIZED | WAITING_CAP | ASSIGNED → ASSIGNED(leader)` at Ycash `height` (assignment or
    /// takeover, §5.2).
    pub fn assign_burn(&self, k: &BurnKey, leader: &PubKey33, height: u32) -> Result<()> {
        let detail = format!("leader {}", crate::hx(leader));
        self.burn_edge(k, BurnState::Assigned, Some(height.into()), Some(&detail))?;
        self.conn().execute(
            "UPDATE burns SET leader = ?4, assigned_height = ?5, waiting_epoch = NULL
             WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
            params![
                k.deployment.chain_id,
                k.deployment.bridge.0,
                k.nonce,
                leader,
                height
            ],
        )?;
        Ok(())
    }

    /// `FINALIZED | ASSIGNED → WAITING_CAP(epoch)` (§5.5).
    pub fn burn_wait_cap(&self, k: &BurnKey, epoch: u64, height: Option<u32>) -> Result<()> {
        let detail = format!("epoch {epoch}");
        self.burn_edge(
            k,
            BurnState::WaitingCap,
            height.map(u64::from),
            Some(&detail),
        )?;
        self.conn().execute(
            "UPDATE burns SET waiting_epoch = ?4
             WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
            params![k.deployment.chain_id, k.deployment.bridge.0, k.nonce, epoch],
        )?;
        Ok(())
    }

    /// `FINALIZED | ASSIGNED | WAITING_CAP → INTENT_PENDING(intent)`. The intent row must exist.
    pub fn burn_intent_pending(&self, k: &BurnKey, intent: &OutPoint, height: u32) -> Result<()> {
        self.require_intent(intent)?;
        let detail = format!("intent {intent}");
        self.burn_edge(
            k,
            BurnState::IntentPending,
            Some(height.into()),
            Some(&detail),
        )?;
        self.conn().execute(
            "UPDATE burns SET intent_txid = ?4, intent_vout = ?5, waiting_epoch = NULL
             WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
            params![
                k.deployment.chain_id,
                k.deployment.bridge.0,
                k.nonce,
                intent.txid,
                intent.vout
            ],
        )?;
        Ok(())
    }

    /// Check and apply one forward edge, log it, return the old state.
    fn burn_edge(
        &self,
        k: &BurnKey,
        to: BurnState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<BurnState> {
        let old = self.require_burn(k)?;
        let oid = k.to_string();
        check_forward(&oid, old.state, to)?;
        self.set_burn_state(k, old.state, to, height, detail)?;
        Ok(old.state)
    }

    /// Write a burn state and log it (no edge check: callers check).
    pub(crate) fn set_burn_state(
        &self,
        k: &BurnKey,
        from: BurnState,
        to: BurnState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE burns SET state = ?4, updated_at = ?5
             WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
            params![
                k.deployment.chain_id,
                k.deployment.bridge.0,
                k.nonce,
                to,
                self.now()
            ],
        )?;
        self.log(
            ObjectKind::Burn,
            &k.to_string(),
            Some(from.as_str()),
            to.as_str(),
            height,
            detail,
        )
    }
}
