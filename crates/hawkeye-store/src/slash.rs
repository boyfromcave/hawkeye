//! Slash cases (plan §2.3, §5.3; the SlashCase machine of §5.1).

use hawkeye_core::PubKey33;
use hawkeye_core::bytes::{Hash32, txid_to_display};
use rusqlite::{Row, params};

use crate::state::{FaultKind, ObjectKind, SlashState, check_forward};
use crate::{Result, StoreError, Tx};

/// A case to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSlashCase {
    /// The accused member key.
    pub target_key: PubKey33,
    /// The fault.
    pub fault: FaultKind,
    /// What the fault is about, for de-duplication: the intent's txid, the `lockId`, the
    /// equivocated outpoint, … One case per `(fault, subject, target)`.
    pub subject: Vec<u8>,
    /// The self-contained evidence bundle, JSON (checked with SQLite's `json_valid`).
    pub evidence_json: String,
    /// The Ycash height at which it was opened.
    pub opened_height: Option<u32>,
}

/// A slash case row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCaseRecord {
    /// The case number.
    pub id: i64,
    /// The accused member key.
    pub target_key: PubKey33,
    /// The fault.
    pub fault: FaultKind,
    /// The de-duplication subject.
    pub subject: Vec<u8>,
    /// The evidence bundle.
    pub evidence_json: String,
    /// Opened at.
    pub opened_height: Option<u32>,
    /// The machine state.
    pub state: SlashState,
    /// This attestor's act signature (`set_signact` result hex).
    pub my_vote: Option<String>,
    /// The act being voted on (`set_buildact` result hex).
    pub act_hex: Option<String>,
    /// The `set_sendact` txid.
    pub txid: Option<Hash32>,
    /// The `SET_REMOVE`'s height.
    pub slashed_height: Option<u32>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

const COLS: &str = "id, target_key, fault, subject, evidence, opened_height, state, my_vote, \
                    act_hex, txid, slashed_height, created_at, updated_at";

fn row(r: &Row<'_>) -> rusqlite::Result<SlashCaseRecord> {
    Ok(SlashCaseRecord {
        id: r.get(0)?,
        target_key: r.get(1)?,
        fault: r.get(2)?,
        subject: r.get(3)?,
        evidence_json: r.get(4)?,
        opened_height: r.get(5)?,
        state: r.get(6)?,
        my_vote: r.get(7)?,
        act_hex: r.get(8)?,
        txid: r.get(9)?,
        slashed_height: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

impl Tx<'_> {
    /// Open a case (`OPENED`), or return the existing case for the same
    /// `(fault, subject, target)`. The bool is `true` when a new case was opened.
    pub fn open_slash_case(&self, new: &NewSlashCase) -> Result<(SlashCaseRecord, bool)> {
        if let Some(old) = self.one(
            &format!(
                "SELECT {COLS} FROM slash_cases
                 WHERE fault = ?1 AND subject = ?2 AND target_key = ?3"
            ),
            params![new.fault, new.subject, new.target_key],
            row,
        )? {
            return Ok((old, false));
        }
        self.conn().execute(
            "INSERT INTO slash_cases (target_key, fault, subject, evidence, opened_height, state,
                                      created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                new.target_key,
                new.fault,
                new.subject,
                new.evidence_json,
                new.opened_height,
                SlashState::Opened,
                self.now(),
            ],
        )?;
        let id = self.conn().last_insert_rowid();
        let detail = format!("{} against {}", new.fault, crate::hx(&new.target_key));
        self.log(
            ObjectKind::SlashCase,
            &id.to_string(),
            None,
            SlashState::Opened.as_str(),
            new.opened_height.map(u64::from),
            Some(&detail),
        )?;
        Ok((self.require_slash_case(id)?, true))
    }

    /// The case with this number.
    pub fn slash_case(&self, id: i64) -> Result<Option<SlashCaseRecord>> {
        self.one(
            &format!("SELECT {COLS} FROM slash_cases WHERE id = ?1"),
            [id],
            row,
        )
    }

    fn require_slash_case(&self, id: i64) -> Result<SlashCaseRecord> {
        self.slash_case(id)?.ok_or_else(|| StoreError::NotFound {
            kind: ObjectKind::SlashCase,
            id: id.to_string(),
        })
    }

    /// Every case in `state`, oldest first.
    pub fn slash_cases_in_state(&self, state: SlashState) -> Result<Vec<SlashCaseRecord>> {
        self.all(
            &format!("SELECT {COLS} FROM slash_cases WHERE state = ?1 ORDER BY id"),
            [state],
            row,
        )
    }

    /// `OPENED → VOTED`: this attestor verified the evidence independently and signed the act.
    pub fn slash_vote(
        &self,
        id: i64,
        act_hex: &str,
        my_vote: &str,
        height: Option<u32>,
    ) -> Result<()> {
        self.slash_edge(id, SlashState::Voted, height, None)?;
        self.conn().execute(
            "UPDATE slash_cases SET act_hex = ?2, my_vote = ?3 WHERE id = ?1",
            params![id, act_hex, my_vote],
        )?;
        Ok(())
    }

    /// `VOTED → SUBMITTED`: `set_sendact` returned `txid`.
    pub fn slash_submitted(&self, id: i64, txid: &Hash32, height: Option<u32>) -> Result<()> {
        let detail = format!("act {}", txid_to_display(txid));
        self.slash_edge(id, SlashState::Submitted, height, Some(&detail))?;
        self.conn().execute(
            "UPDATE slash_cases SET txid = ?2 WHERE id = ?1",
            params![id, txid],
        )?;
        Ok(())
    }

    /// `OPENED | VOTED | SUBMITTED → SLASHED`: the removal is mined at `height`.
    pub fn slash_slashed(&self, id: i64, height: u32, detail: Option<&str>) -> Result<()> {
        self.slash_edge(id, SlashState::Slashed, Some(height), detail)?;
        self.conn().execute(
            "UPDATE slash_cases SET slashed_height = ?2 WHERE id = ?1",
            params![id, height],
        )?;
        Ok(())
    }

    /// `… → EXPIRED`; returns the state left. The other targets have their own calls.
    pub fn transition_slash(
        &self,
        id: i64,
        to: SlashState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<SlashState> {
        check_forward(&id.to_string(), self.require_slash_case(id)?.state, to)?;
        if to != SlashState::Expired {
            return Err(StoreError::Invalid(format!(
                "{to} carries data: use slash_vote / slash_submitted / slash_slashed"
            )));
        }
        self.slash_edge(id, to, height, detail)
    }

    fn slash_edge(
        &self,
        id: i64,
        to: SlashState,
        height: Option<u32>,
        detail: Option<&str>,
    ) -> Result<SlashState> {
        let old = self.require_slash_case(id)?;
        check_forward(&id.to_string(), old.state, to)?;
        self.set_slash_state(id, old.state, to, height.map(u64::from), detail)?;
        Ok(old.state)
    }

    pub(crate) fn set_slash_state(
        &self,
        id: i64,
        from: SlashState,
        to: SlashState,
        height: Option<u64>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE slash_cases SET state = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, to, self.now()],
        )?;
        self.log(
            ObjectKind::SlashCase,
            &id.to_string(),
            Some(from.as_str()),
            to.as_str(),
            height,
            detail,
        )
    }
}
