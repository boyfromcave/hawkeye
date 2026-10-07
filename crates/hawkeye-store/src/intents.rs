//! Intents seen on Ycash (plan §3.2, §5.3; the Intent machine of §5.1).

use hawkeye_core::bytes::Hash32;
use hawkeye_core::matcher::{Classification, Unmatched};
use hawkeye_core::{Deployment, OutPoint, PubKey33};
use rusqlite::{Row, params};

use crate::burns::BurnKey;
use crate::state::{IntentState, ObjectKind, check_forward};
use crate::{Result, StoreError, Tx};

/// An intent output as first observed (mempool or block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIntent {
    /// The intent output (the unlock transaction's txid and the intent's index).
    pub outpoint: OutPoint,
    /// The intent's value in zatoshi.
    pub value_zat: u64,
    /// The intent's `recipientHash`.
    pub recipient_hash: Hash32,
    /// The intent's `vaultHash`.
    pub vault_hash: Hash32,
    /// The vault outpoint the unlock spent, when known.
    pub origin_vault: Option<OutPoint>,
    /// The member key recovered from the unlock's set signature (§4.5), when recovered.
    pub signer_key: Option<PubKey33>,
    /// The raw memo (`HKB1` payload or whatever single `OP_RETURN` the unlock carried).
    pub memo: Option<Vec<u8>>,
    /// The Ycash height at which it was first seen (the tip for a mempool sighting).
    pub first_seen_height: u32,
    /// The block height if it was first seen mined.
    pub confirmed_height: Option<u32>,
}

/// An intent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    /// The intent output.
    pub outpoint: OutPoint,
    /// Value in zatoshi.
    pub value_zat: u64,
    /// `recipientHash`.
    pub recipient_hash: Hash32,
    /// `vaultHash`.
    pub vault_hash: Hash32,
    /// The spent vault, when known.
    pub origin_vault: Option<OutPoint>,
    /// The recovered signer.
    pub signer_key: Option<PubKey33>,
    /// The raw memo.
    pub memo: Option<Vec<u8>>,
    /// [`classification_code`] of the latest classification.
    pub classification: Option<String>,
    /// The burn it pays (`MATCHED` to a burn).
    pub matched_burn: Option<BurnKey>,
    /// First seen at.
    pub first_seen_height: u32,
    /// Mined at (cleared by a reorg rewind).
    pub confirmed_height: Option<u32>,
    /// The machine state.
    pub state: IntentState,
    /// This attestor's cancel (`CANCEL_SENT`) or the mined cancel (`CANCELLED`).
    pub cancel_txid: Option<Hash32>,
    /// The mined cancel's height.
    pub cancel_height: Option<u32>,
    /// The mined cancel was this attestor's.
    pub cancel_by_us: bool,
    /// The release transaction.
    pub released_txid: Option<Hash32>,
    /// The release's height.
    pub released_height: Option<u32>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

impl IntentRecord {
    /// Whether the latest classification is a match (burn or roll).
    pub fn is_matched(&self) -> bool {
        self.classification
            .as_deref()
            .is_some_and(|c| c.starts_with("matched"))
    }
}

const COLS: &str = "i.txid, i.vout, i.value_zat, i.recipient_hash, i.vault_hash, i.origin_txid, \
                    i.origin_vout, i.signer_key, i.memo, i.classification, b.chain_id, b.bridge, \
                    b.nonce, i.first_seen_height, i.confirmed_height, i.state, i.cancel_txid, \
                    i.cancel_height, i.cancel_by_us, i.released_txid, i.released_height, \
                    i.created_at, i.updated_at";
const FROM: &str = "intents i LEFT JOIN burns b ON b.id = i.matched_burn";

fn row(r: &Row<'_>) -> rusqlite::Result<IntentRecord> {
    let origin_vault = match (r.get::<_, Option<Hash32>>(5)?, r.get::<_, Option<u32>>(6)?) {
        (Some(t), Some(v)) => Some(OutPoint::new(t, v)),
        _ => None,
    };
    let matched_burn = match (
        r.get::<_, Option<u64>>(10)?,
        r.get::<_, Option<[u8; 20]>>(11)?,
        r.get::<_, Option<u64>>(12)?,
    ) {
        (Some(chain_id), Some(bridge), Some(nonce)) => Some(BurnKey::new(
            Deployment {
                chain_id,
                bridge: hawkeye_core::EthAddress(bridge),
            },
            nonce,
        )),
        _ => None,
    };
    Ok(IntentRecord {
        outpoint: OutPoint::new(r.get(0)?, r.get(1)?),
        value_zat: r.get(2)?,
        recipient_hash: r.get(3)?,
        vault_hash: r.get(4)?,
        origin_vault,
        signer_key: r.get(7)?,
        memo: r.get(8)?,
        classification: r.get(9)?,
        matched_burn,
        first_seen_height: r.get(13)?,
        confirmed_height: r.get(14)?,
        state: r.get(15)?,
        cancel_txid: r.get(16)?,
        cancel_height: r.get(17)?,
        cancel_by_us: r.get(18)?,
        released_txid: r.get(19)?,
        released_height: r.get(20)?,
        created_at: r.get(21)?,
        updated_at: r.get(22)?,
    })
}

/// The stored form of a classification: `matched-burn`, `matched-roll`, `foreign`, or
/// `unmatched:<reason>` (`no-memo`, `multiple-memos`, `malformed-memo`, `wrong-deployment`,
/// `unknown-burn`, `consumed-burn` / `consumed-burn:benign-race`, `wrong-value:<expected>:<got>`,
/// `orphaned-burn`, `wrong-recipient`, `bad-roll`, `roll-too-short:<ownerHeight>`).
pub fn classification_code(c: &Classification) -> String {
    match c {
        Classification::Foreign => "foreign".into(),
        Classification::MatchedBurn { .. } => "matched-burn".into(),
        Classification::MatchedRoll { .. } => "matched-roll".into(),
        Classification::Unmatched(u) => {
            let reason = match u {
                Unmatched::NoMemo => "no-memo".into(),
                Unmatched::MultipleMemos => "multiple-memos".into(),
                Unmatched::MalformedMemo => "malformed-memo".into(),
                Unmatched::WrongDeployment => "wrong-deployment".into(),
                Unmatched::UnknownBurn => "unknown-burn".into(),
                Unmatched::ConsumedBurn {
                    benign_race: true, ..
                } => "consumed-burn:benign-race".into(),
                Unmatched::ConsumedBurn { .. } => "consumed-burn".into(),
                Unmatched::WrongValue { expected, got } => {
                    format!("wrong-value:{expected}:{got}")
                }
                Unmatched::OrphanedBurn => "orphaned-burn".into(),
                Unmatched::WrongRecipient => "wrong-recipient".into(),
                Unmatched::BadRoll => "bad-roll".into(),
                Unmatched::RollTooShort { owner_height } => {
                    format!("roll-too-short:{owner_height}")
                }
            };
            format!("unmatched:{reason}")
        }
    }
}

fn oid(op: &OutPoint) -> String {
    op.to_string()
}

impl Tx<'_> {
    /// Record an intent (`OBSERVED`), or return the stored one. Re-observing an existing intent
    /// is idempotent, except that a `confirmed_height` the row lacks is recorded
    /// ([`Tx::confirm_intent`]).
    pub fn insert_intent(&self, new: &NewIntent) -> Result<IntentRecord> {
        let op = &new.outpoint;
        if let Some(old) = self.intent(op)? {
            if old.value_zat != new.value_zat
                || old.recipient_hash != new.recipient_hash
                || old.vault_hash != new.vault_hash
            {
                return Err(StoreError::Duplicate {
                    kind: ObjectKind::Intent,
                    id: oid(op),
                });
            }
            if let (None, Some(h)) = (old.confirmed_height, new.confirmed_height) {
                self.confirm_intent(op, h)?;
                return self.require_intent(op);
            }
            return Ok(old);
        }
        self.conn().execute(
            "INSERT INTO intents (txid, vout, value_zat, recipient_hash, vault_hash, origin_txid,
                                  origin_vout, signer_key, memo, first_seen_height,
                                  confirmed_height, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
            params![
                op.txid,
                op.vout,
                new.value_zat,
                new.recipient_hash,
                new.vault_hash,
                new.origin_vault.map(|o| o.txid),
                new.origin_vault.map(|o| o.vout),
                new.signer_key,
                new.memo,
                new.first_seen_height,
                new.confirmed_height,
                IntentState::Observed,
                self.now(),
            ],
        )?;
        let detail = new.confirmed_height.map(|h| format!("mined at {h}"));
        self.log(
            ObjectKind::Intent,
            &oid(op),
            None,
            IntentState::Observed.as_str(),
            Some(new.first_seen_height.into()),
            detail.as_deref(),
        )?;
        self.require_intent(op)
    }

    /// The intent at this outpoint.
    pub fn intent(&self, op: &OutPoint) -> Result<Option<IntentRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM {FROM} WHERE i.txid = ?1 AND i.vout = ?2"),
            params![op.txid, op.vout],
            row,
        )
    }

    pub(crate) fn require_intent(&self, op: &OutPoint) -> Result<IntentRecord> {
        self.intent(op)?.ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::Intent,
            id: oid(op),
        })
    }

    /// Every intent in `state`, by first sighting.
    pub fn intents_in_state(&self, state: IntentState) -> Result<Vec<IntentRecord>> {
        self.all(
            &format!(
                "SELECT {COLS} FROM {FROM} WHERE i.state = ?1
                 ORDER BY i.first_seen_height, i.txid, i.vout"
            ),
            [state],
            row,
        )
    }

    /// Every intent matched to burn `k`, by first sighting.
    pub fn intents_for_burn(&self, k: &BurnKey) -> Result<Vec<IntentRecord>> {
        let id = self.burn_rowid(k)?;
        self.all(
            &format!(
                "SELECT {COLS} FROM {FROM} WHERE i.matched_burn = ?1
                 ORDER BY i.first_seen_height, i.txid, i.vout"
            ),
            [id],
            row,
        )
    }

    /// Record that the intent is mined at `height` (not a state change; logged).
    pub fn confirm_intent(&self, op: &OutPoint, height: u32) -> Result<()> {
        let old = self.require_intent(op)?;
        self.conn().execute(
            "UPDATE intents SET confirmed_height = ?3, updated_at = ?4
             WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, height, self.now()],
        )?;
        let detail = format!("mined at {height}");
        self.log(
            ObjectKind::Intent,
            &oid(op),
            Some(old.state.as_str()),
            old.state.as_str(),
            Some(height.into()),
            Some(&detail),
        )
    }

    /// Record the matcher's verdict: `OBSERVED | UNMATCHED | MATCHED → MATCHED | UNMATCHED`.
    ///
    /// A [`Classification::MatchedBurn`] links the intent to that burn of `deployment` (which
    /// must be stored). Re-classifying into the same state updates the stored classification
    /// (logged) when it changed and is a no-op otherwise. `Foreign` is refused: the ledger only
    /// holds the set's intents.
    pub fn classify_intent(
        &self,
        op: &OutPoint,
        deployment: &Deployment,
        c: &Classification,
        height: Option<u32>,
    ) -> Result<IntentState> {
        let (to, burn) = match c {
            Classification::Foreign => {
                return Err(StoreError::Invalid(
                    "a foreign intent is not the set's: not recorded".into(),
                ));
            }
            Classification::MatchedBurn { nonce } => {
                let k = BurnKey::new(*deployment, *nonce);
                if self.require_burn(&k)?.state == crate::BurnState::Seen {
                    return Err(StoreError::Invalid(format!(
                        "burn {k} is not finalized: an intent cannot match it"
                    )));
                }
                (IntentState::Matched, Some(self.burn_rowid(&k)?))
            }
            Classification::MatchedRoll { .. } => (IntentState::Matched, None),
            Classification::Unmatched(_) => (IntentState::Unmatched, None),
        };
        let code = classification_code(c);
        let old = self.require_intent(op)?;
        let id = oid(op);
        if old.state == to {
            if old.classification.as_deref() == Some(code.as_str()) {
                return Ok(old.state);
            }
        } else {
            check_forward(&id, old.state, to)?;
        }
        self.conn().execute(
            "UPDATE intents SET state = ?3, classification = ?4, matched_burn = ?5, updated_at = ?6
             WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, to, code, burn, self.now()],
        )?;
        self.log(
            ObjectKind::Intent,
            &id,
            Some(old.state.as_str()),
            to.as_str(),
            height.map(u64::from),
            Some(&code),
        )?;
        Ok(old.state)
    }

    /// `UNMATCHED → CANCEL_SENT`: this attestor broadcast `cancel_txid`.
    pub fn intent_cancel_sent(
        &self,
        op: &OutPoint,
        cancel_txid: &Hash32,
        height: Option<u32>,
    ) -> Result<()> {
        let detail = format!(
            "cancel {}",
            hawkeye_core::bytes::txid_to_display(cancel_txid)
        );
        self.intent_edge(op, IntentState::CancelSent, height, Some(&detail))?;
        self.conn().execute(
            "UPDATE intents SET cancel_txid = ?3 WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, cancel_txid],
        )?;
        Ok(())
    }

    /// `UNMATCHED | CANCEL_SENT | MATCHED → CANCELLED`: `cancel_txid` is mined at `height`.
    /// It counts as this attestor's when it is the txid recorded by
    /// [`Tx::intent_cancel_sent`].
    pub fn intent_cancelled(&self, op: &OutPoint, cancel_txid: &Hash32, height: u32) -> Result<()> {
        let old = self.require_intent(op)?;
        let by_us = old.cancel_txid.as_ref() == Some(cancel_txid);
        let detail = format!(
            "cancel {}{}",
            hawkeye_core::bytes::txid_to_display(cancel_txid),
            if by_us { " (ours)" } else { "" }
        );
        self.intent_edge(op, IntentState::Cancelled, Some(height), Some(&detail))?;
        self.conn().execute(
            "UPDATE intents SET cancel_txid = ?3, cancel_height = ?4, cancel_by_us = ?5
             WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, cancel_txid, height, by_us],
        )?;
        Ok(())
    }

    /// `MATCHED → RELEASED`: `release_txid` is mined at `height`.
    pub fn intent_released(&self, op: &OutPoint, release_txid: &Hash32, height: u32) -> Result<()> {
        let detail = format!(
            "release {}",
            hawkeye_core::bytes::txid_to_display(release_txid)
        );
        self.intent_edge(op, IntentState::Released, Some(height), Some(&detail))?;
        self.conn().execute(
            "UPDATE intents SET released_txid = ?3, released_height = ?4
             WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, release_txid, height],
        )?;
        Ok(())
    }

    /// Move an intent along a forward edge that carries no payload (`MATURED_UNMATCHED`);
    /// returns the state it left. The other targets have their own calls.
    pub fn transition_intent(
        &self,
        op: &OutPoint,
        to: IntentState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<IntentState> {
        check_forward(&oid(op), self.require_intent(op)?.state, to)?;
        if to != IntentState::MaturedUnmatched {
            return Err(StoreError::Invalid(format!(
                "{to} carries data: use classify_intent / intent_cancel_sent / \
                 intent_cancelled / intent_released"
            )));
        }
        self.intent_edge(op, to, height, detail)
    }

    fn intent_edge(
        &self,
        op: &OutPoint,
        to: IntentState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<IntentState> {
        let old = self.require_intent(op)?;
        check_forward(&oid(op), old.state, to)?;
        self.set_intent_state(op, old.state, to, height.map(u64::from), detail)?;
        Ok(old.state)
    }

    pub(crate) fn set_intent_state(
        &self,
        op: &OutPoint,
        from: IntentState,
        to: IntentState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE intents SET state = ?3, updated_at = ?4 WHERE txid = ?1 AND vout = ?2",
            params![op.txid, op.vout, to, self.now()],
        )?;
        self.log(
            ObjectKind::Intent,
            &oid(op),
            Some(from.as_str()),
            to.as_str(),
            height,
            detail,
        )
    }
}
