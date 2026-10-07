//! Chain cursors and reorg rewinds (plan §5.4).
//!
//! Each chain has one cursor (the last processed block) and a window of recent block hashes
//! (`chain_blocks`) so the engine can find a Ycash fork point by comparing hashes with the node
//! (walk down from the cursor until [`Tx::block_hash`] equals `getblockhash`), then call
//! [`Tx::rewind_ycash_to`] with the fork height. Ethereum is followed at `finalized`, so its
//! rewind only drops unfinalized (`SEEN`) burns; un-finalizing a finalized burn is refused.

use hawkeye_core::OutPoint;
use hawkeye_core::bytes::Hash32;
use rusqlite::params;

use crate::burns::BurnKey;
use crate::events::DELETED;
use crate::locks::lock_object_id;
use crate::state::{
    BurnState, Chain, Edge, IntentState, LockState, Machine, ObjectKind, SlashState, VaultState,
    check_edge,
};
use crate::{Result, StoreError, Tx};

/// A chain cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// The last processed height (Ycash height or Ethereum block number).
    pub height: u64,
    /// Its block hash, when known (a rewind below the hash window leaves it unknown).
    pub hash: Option<Hash32>,
}

/// What a rewind changed (for the engine's alarms and metrics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewindReport {
    /// The height rewound to.
    pub to: u64,
    /// Unsigned locks in reorged blocks, deleted.
    pub locks_deleted: Vec<Hash32>,
    /// Locks whose mint this attestor had signed, now `REORGED` with the exposure flag (§5.4
    /// alarm).
    pub exposures: Vec<Hash32>,
    /// Intents whose confirmation was undone.
    pub intents_unconfirmed: Vec<OutPoint>,
    /// Intents whose release was undone (`RELEASED → MATCHED`).
    pub intents_unreleased: Vec<OutPoint>,
    /// Intents whose cancel was undone (`CANCELLED → CANCEL_SENT | MATCHED | UNMATCHED`).
    pub intents_uncancelled: Vec<OutPoint>,
    /// Burns moved back (`RELEASED → INTENT_CONFIRMED`, `INTENT_CONFIRMED → INTENT_PENDING`).
    pub burns_reverted: Vec<BurnKey>,
    /// Unfinalized burns deleted (Ethereum rewind).
    pub burns_deleted: Vec<BurnKey>,
    /// Vaults created in reorged blocks, deleted.
    pub vaults_deleted: Vec<OutPoint>,
    /// Vaults whose spend was undone (`SPENT → LIVE`, `ROLLED → ROLLING`).
    pub vaults_unspent: Vec<OutPoint>,
    /// Slash cases whose removal was undone.
    pub slash_cases_reverted: Vec<i64>,
}

impl Tx<'_> {
    /// The cursor of `chain`.
    pub fn cursor(&self, chain: Chain) -> Result<Option<Cursor>> {
        self.one(
            "SELECT height, hash FROM chain_cursor WHERE chain = ?1",
            [chain.as_str()],
            |r| {
                Ok(Cursor {
                    height: r.get(0)?,
                    hash: r.get(1)?,
                })
            },
        )
    }

    /// Record block `height` with `hash` as processed and move the cursor to it.
    ///
    /// Heights only increase (gaps allowed: Ethereum's finalized head jumps). Re-advancing to
    /// the current block is a no-op; any other non-increase is
    /// [`StoreError::CursorRegression`] — a different block at a known height is a reorg, and
    /// takes a rewind first.
    pub fn advance_cursor(&self, chain: Chain, height: u64, hash: &Hash32) -> Result<()> {
        if let Some(c) = self.cursor(chain)? {
            if height == c.height && c.hash.as_ref() == Some(hash) {
                return Ok(());
            }
            if height <= c.height {
                return Err(StoreError::CursorRegression {
                    chain: chain.as_str(),
                    current: c.height,
                    requested: height,
                });
            }
        }
        self.conn().execute(
            "INSERT OR REPLACE INTO chain_blocks (chain, height, hash) VALUES (?1, ?2, ?3)",
            params![chain.as_str(), height, hash],
        )?;
        self.set_cursor(chain, height, Some(hash))
    }

    fn set_cursor(&self, chain: Chain, height: u64, hash: Option<&Hash32>) -> Result<()> {
        self.conn().execute(
            "INSERT INTO chain_cursor (chain, height, hash, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (chain) DO UPDATE SET height = ?2, hash = ?3, updated_at = ?4",
            params![chain.as_str(), height, hash, self.now()],
        )?;
        Ok(())
    }

    /// The recorded hash of block `height`.
    pub fn block_hash(&self, chain: Chain, height: u64) -> Result<Option<Hash32>> {
        self.one(
            "SELECT hash FROM chain_blocks WHERE chain = ?1 AND height = ?2",
            params![chain.as_str(), height],
            |r| r.get(0),
        )
    }

    /// Forget recorded block hashes below `height` (keep a window deeper than any plausible
    /// reorg); returns how many were dropped.
    pub fn prune_blocks(&self, chain: Chain, below: u64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM chain_blocks WHERE chain = ?1 AND height < ?2",
            params![chain.as_str(), below],
        )?)
    }

    fn rewind_cursor(&self, chain: Chain, to: u64) -> Result<()> {
        self.conn().execute(
            "DELETE FROM chain_blocks WHERE chain = ?1 AND height > ?2",
            params![chain.as_str(), to],
        )?;
        if let Some(c) = self.cursor(chain)?
            && c.height > to
        {
            let hash = self.block_hash(chain, to)?;
            self.set_cursor(chain, to, hash.as_ref())?;
            self.log(
                ObjectKind::Cursor,
                chain.as_str(),
                Some(&c.height.to_string()),
                &to.to_string(),
                Some(to),
                Some("rewind"),
            )?;
        }
        Ok(())
    }

    /// Undo everything the ledger derived from Ycash blocks above `height` (the last block
    /// still on the active chain), and move the cursor there.
    ///
    /// - locks mined above it: deleted if unsigned; `REORGED` + exposure if this attestor
    ///   signed their mint (the sign-once record stays: the signature exists);
    /// - intents: releases, cancels and confirmations above it undone (rewind edges), and the
    ///   linked burn moved back with them; an intent is never deleted (it is likely back in the
    ///   mempool; the engine re-observes it);
    /// - vaults created above it deleted, spends above it undone;
    /// - slash removals above it undone.
    ///
    /// Not undone: a burn that went `CANCELLED → FINALIZED` (and maybe was reassigned) after a
    /// cancel that is now reorged stays where it is; the un-cancelled intent is re-matched by
    /// the engine. Sign-once records and the event log are never touched.
    pub fn rewind_ycash_to(&self, height: u32) -> Result<RewindReport> {
        let h = u64::from(height);
        let mut rep = RewindReport {
            to: h,
            ..Default::default()
        };
        let at = Some(h);
        let reorg = Some("reorg");

        // Locks.
        let locks: Vec<(Hash32, LockState)> = self.all(
            "SELECT lock_id, state FROM locks WHERE block_height > ?1 AND state != ?2
             ORDER BY block_height, lock_id",
            params![height, LockState::Reorged],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        for (id, state) in locks {
            if self.mint_signature(&id)?.is_some() {
                self.transition_lock(
                    &id,
                    LockState::Reorged,
                    Some(height),
                    Some("reorg: exposure"),
                )?;
                rep.exposures.push(id);
            } else {
                self.conn()
                    .execute("DELETE FROM locks WHERE lock_id = ?1", [&id])?;
                self.log(
                    ObjectKind::Lock,
                    &lock_object_id(&id),
                    Some(state.as_str()),
                    DELETED,
                    at,
                    reorg,
                )?;
                rep.locks_deleted.push(id);
            }
        }

        // Releases.
        let released: Vec<OutPoint> = self.all(
            "SELECT txid, vout FROM intents WHERE released_height > ?1 AND state = ?2",
            params![height, IntentState::Released],
            |r| Ok(OutPoint::new(r.get(0)?, r.get(1)?)),
        )?;
        for op in released {
            self.intent_rewind(&op, IntentState::Released, IntentState::Matched, at)?;
            self.conn().execute(
                "UPDATE intents SET released_txid = NULL, released_height = NULL
                 WHERE txid = ?1 AND vout = ?2",
                params![op.txid, op.vout],
            )?;
            self.burn_rewind(
                &op,
                BurnState::Released,
                BurnState::IntentConfirmed,
                at,
                &mut rep,
            )?;
            rep.intents_unreleased.push(op);
        }

        // Cancels.
        let cancelled: Vec<OutPoint> = self.all(
            "SELECT txid, vout FROM intents WHERE cancel_height > ?1 AND state = ?2",
            params![height, IntentState::Cancelled],
            |r| Ok(OutPoint::new(r.get(0)?, r.get(1)?)),
        )?;
        for op in cancelled {
            let rec = self.require_intent(&op)?;
            let to = if rec.cancel_by_us {
                IntentState::CancelSent
            } else if rec.is_matched() {
                IntentState::Matched
            } else {
                IntentState::Unmatched
            };
            self.intent_rewind(&op, IntentState::Cancelled, to, at)?;
            self.conn().execute(
                "UPDATE intents SET cancel_height = NULL, cancel_by_us = 0,
                        cancel_txid = CASE WHEN ?3 THEN cancel_txid ELSE NULL END
                 WHERE txid = ?1 AND vout = ?2",
                params![op.txid, op.vout, rec.cancel_by_us],
            )?;
            rep.intents_uncancelled.push(op);
        }

        // Confirmations.
        let confirmed: Vec<(OutPoint, IntentState)> = self.all(
            "SELECT txid, vout, state FROM intents WHERE confirmed_height > ?1",
            [height],
            |r| Ok((OutPoint::new(r.get(0)?, r.get(1)?), r.get(2)?)),
        )?;
        for (op, state) in confirmed {
            self.conn().execute(
                "UPDATE intents SET confirmed_height = NULL, updated_at = ?3
                 WHERE txid = ?1 AND vout = ?2",
                params![op.txid, op.vout, self.now()],
            )?;
            self.log(
                ObjectKind::Intent,
                &op.to_string(),
                Some(state.as_str()),
                state.as_str(),
                at,
                Some("reorg: unconfirmed"),
            )?;
            self.burn_rewind(
                &op,
                BurnState::IntentConfirmed,
                BurnState::IntentPending,
                at,
                &mut rep,
            )?;
            rep.intents_unconfirmed.push(op);
        }

        // Vaults.
        let created: Vec<(OutPoint, VaultState)> = self.all(
            "SELECT txid, vout, state FROM vaults WHERE created_height > ?1",
            [height],
            |r| Ok((OutPoint::new(r.get(0)?, r.get(1)?), r.get(2)?)),
        )?;
        for (op, state) in created {
            self.conn().execute(
                "DELETE FROM vaults WHERE txid = ?1 AND vout = ?2",
                params![op.txid, op.vout],
            )?;
            self.log(
                ObjectKind::Vault,
                &op.to_string(),
                Some(state.as_str()),
                DELETED,
                at,
                reorg,
            )?;
            rep.vaults_deleted.push(op);
        }
        let spent: Vec<(OutPoint, VaultState)> = self.all(
            "SELECT txid, vout, state FROM vaults WHERE spent_height > ?1",
            [height],
            |r| Ok((OutPoint::new(r.get(0)?, r.get(1)?), r.get(2)?)),
        )?;
        for (op, state) in spent {
            let to = match state {
                VaultState::Spent => VaultState::Live,
                VaultState::Rolled => VaultState::Rolling,
                other => other,
            };
            check_edge(&op.to_string(), state, to, Edge::Rewind)?;
            self.set_vault_state(&op, state, to, at, reorg)?;
            self.conn().execute(
                "UPDATE vaults SET spent_txid = NULL, spent_height = NULL
                 WHERE txid = ?1 AND vout = ?2",
                params![op.txid, op.vout],
            )?;
            rep.vaults_unspent.push(op);
        }

        // Slash cases.
        let slashed: Vec<i64> = self.all(
            "SELECT id FROM slash_cases WHERE slashed_height > ?1 AND state = ?2",
            params![height, SlashState::Slashed],
            |r| r.get(0),
        )?;
        for id in slashed {
            let case = self
                .slash_case(id)?
                .ok_or_else(|| StoreError::corrupt("slash case vanished"))?;
            let to = if case.txid.is_some() {
                SlashState::Submitted
            } else if case.my_vote.is_some() {
                SlashState::Voted
            } else {
                SlashState::Opened
            };
            check_edge(&id.to_string(), SlashState::Slashed, to, Edge::Rewind)?;
            self.set_slash_state(id, SlashState::Slashed, to, at, reorg)?;
            self.conn().execute(
                "UPDATE slash_cases SET slashed_height = NULL WHERE id = ?1",
                [id],
            )?;
            rep.slash_cases_reverted.push(id);
        }

        self.rewind_cursor(Chain::Ycash, h)?;
        Ok(rep)
    }

    /// Drop Ethereum state above block `block`: unfinalized (`SEEN`) burns are deleted, the
    /// cursor moves back. A finalized burn above `block` refuses the whole rewind with
    /// [`StoreError::FinalizedReorg`] (Hawkeye acts on finalized blocks only, §5.4).
    pub fn rewind_eth_to(&self, block: u64) -> Result<RewindReport> {
        let mut rep = RewindReport {
            to: block,
            ..Default::default()
        };
        if let Some((k, n)) = self.one(
            "SELECT chain_id, bridge, nonce, block_number FROM burns
             WHERE block_number > ?1 AND state != ?2 ORDER BY block_number LIMIT 1",
            params![block, BurnState::Seen],
            |r| {
                Ok((
                    BurnKey::new(
                        hawkeye_core::Deployment {
                            chain_id: r.get(0)?,
                            bridge: hawkeye_core::EthAddress(r.get(1)?),
                        },
                        r.get(2)?,
                    ),
                    r.get::<_, u64>(3)?,
                ))
            },
        )? {
            return Err(StoreError::FinalizedReorg {
                to: block,
                burn: k.to_string(),
                block: n,
            });
        }
        let seen: Vec<BurnKey> = self.all(
            "SELECT chain_id, bridge, nonce FROM burns WHERE block_number > ?1 AND state = ?2
             ORDER BY nonce",
            params![block, BurnState::Seen],
            |r| {
                Ok(BurnKey::new(
                    hawkeye_core::Deployment {
                        chain_id: r.get(0)?,
                        bridge: hawkeye_core::EthAddress(r.get(1)?),
                    },
                    r.get(2)?,
                ))
            },
        )?;
        for k in seen {
            self.conn().execute(
                "DELETE FROM burns WHERE chain_id = ?1 AND bridge = ?2 AND nonce = ?3",
                params![k.deployment.chain_id, k.deployment.bridge.0, k.nonce],
            )?;
            self.log(
                ObjectKind::Burn,
                &k.to_string(),
                Some(BurnState::Seen.as_str()),
                DELETED,
                Some(block),
                Some("reorg (unfinalized)"),
            )?;
            rep.burns_deleted.push(k);
        }
        self.rewind_cursor(Chain::Ethereum, block)?;
        Ok(rep)
    }

    fn intent_rewind(
        &self,
        op: &OutPoint,
        from: IntentState,
        to: IntentState,
        at: Option<u64>,
    ) -> Result<()> {
        check_edge(&op.to_string(), from, to, Edge::Rewind)?;
        self.set_intent_state(op, from, to, at, Some("reorg"))
    }

    /// Move the burn whose intent is `op` from `from` to `to` (a rewind edge), if it is in
    /// `from`.
    fn burn_rewind(
        &self,
        op: &OutPoint,
        from: BurnState,
        to: BurnState,
        at: Option<u64>,
        rep: &mut RewindReport,
    ) -> Result<()> {
        if let Some(b) = self.burn_for_intent(op)?
            && b.state == from
        {
            debug_assert_eq!(from.edge(to), Some(Edge::Rewind));
            check_edge(&b.key.to_string(), from, to, Edge::Rewind)?;
            self.set_burn_state(&b.key, from, to, at, Some("reorg"))?;
            if !rep.burns_reverted.contains(&b.key) {
                rep.burns_reverted.push(b.key);
            }
        }
        Ok(())
    }
}
