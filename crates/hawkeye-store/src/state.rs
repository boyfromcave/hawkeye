//! The §5.1 state machines (plan `docs/hawkeye-bridge-plan.md`).
//!
//! Every state enum stores as its upper-case name ([`Display`](core::fmt::Display) /
//! [`FromStr`]), and every machine has one edge table, [`Machine::edge`].
//! An edge is either [`Edge::Forward`] — what the engine may ask for through the ledger's
//! `transition` calls — or [`Edge::Rewind`] — taken only by the ledger itself when a Ycash reorg
//! undoes the block that caused the forward edge (`rewind_ycash_to`).
//!
//! The diagram in §5.1 is the spine; where it is silent the edges below are this crate's
//! decisions, each marked *(ledger)* in the per-machine docs.

use core::fmt;
use core::str::FromStr;

use crate::error::StoreError;

/// Which kind of object a state, an event or an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// A `WYEC` lock on Ycash.
    Lock,
    /// A `BurnToYcash` event on Ethereum.
    Burn,
    /// An intent seen on Ycash.
    Intent,
    /// A `WYEC` vault output of the set.
    Vault,
    /// A slash case.
    SlashCase,
    /// A chain cursor (event log only).
    Cursor,
    /// A sign-once record (errors only).
    SignOnce,
}

impl ObjectKind {
    /// The stored name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Burn => "burn",
            Self::Intent => "intent",
            Self::Vault => "vault",
            Self::SlashCase => "slash",
            Self::Cursor => "cursor",
            Self::SignOnce => "sign-once",
        }
    }

    /// Every kind.
    pub const ALL: &'static [Self] = &[
        Self::Lock,
        Self::Burn,
        Self::Intent,
        Self::Vault,
        Self::SlashCase,
        Self::Cursor,
        Self::SignOnce,
    ];
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ObjectKind {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, StoreError> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| StoreError::corrupt(format!("unknown object kind {s:?}")))
    }
}

/// The kind of an edge in a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// A transition the engine may request.
    Forward,
    /// A transition only a reorg rewind takes.
    Rewind,
}

/// A §5.1 state machine.
pub trait Machine:
    Copy + Eq + fmt::Debug + fmt::Display + FromStr<Err = StoreError> + 'static
{
    /// The object kind the machine belongs to.
    const KIND: ObjectKind;
    /// Every state.
    const ALL: &'static [Self];
    /// The edge `self → to`, if any.
    fn edge(self, to: Self) -> Option<Edge>;
    /// Whether no forward edge leaves this state.
    fn is_terminal(self) -> bool {
        Self::ALL
            .iter()
            .all(|&t| self.edge(t) != Some(Edge::Forward))
    }
}

/// Check that `from → to` is a forward edge of `S`; `id` names the object in the error.
pub fn check_forward<S: Machine>(id: &str, from: S, to: S) -> Result<(), StoreError> {
    check_edge(id, from, to, Edge::Forward)
}

pub(crate) fn check_edge<S: Machine>(
    id: &str,
    from: S,
    to: S,
    want: Edge,
) -> Result<(), StoreError> {
    if from.edge(to) == Some(want) {
        Ok(())
    } else {
        Err(StoreError::IllegalTransition {
            kind: S::KIND,
            id: id.to_owned(),
            from: from.to_string(),
            to: to.to_string(),
        })
    }
}

macro_rules! states {
    (
        $(#[$m:meta])*
        $name:ident: $kind:expr;
        $( $(#[$vm:meta])* $v:ident = $s:literal ),+ $(,)?
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $( $(#[$vm])* $v ),+
        }

        impl $name {
            /// The stored name.
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$v => $s ),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = StoreError;
            fn from_str(s: &str) -> Result<Self, StoreError> {
                match s {
                    $( $s => Ok(Self::$v), )+
                    _ => Err(StoreError::corrupt(format!(
                        "unknown {} state {s:?}", $kind
                    ))),
                }
            }
        }

        impl rusqlite::types::ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                Ok(self.as_str().into())
            }
        }

        impl rusqlite::types::FromSql for $name {
            fn column_result(
                v: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let s = v.as_str()?;
                s.parse().map_err(|e: StoreError| rusqlite::types::FromSqlError::Other(e.into()))
            }
        }
    };
}

states! {
    /// The Lock machine (§5.1):
    ///
    /// ```text
    /// SEEN → CONFIRMED → POLICY_OK | POLICY_REJECTED
    /// POLICY_OK → SIGNED → (MINT_SUBMITTED | PROPOSED → CHALLENGED | EXECUTED) → MINTED
    /// any → REORGED
    /// ```
    ///
    /// *(ledger)* additions: `CHALLENGED → PROPOSED` (a challenged proposal is re-proposable,
    /// CR-W1, with the same signed bytes); `POLICY_OK → MINTED` and `SIGNED → MINTED` (the mint was
    /// observed on Ethereum, submitted by another attestor); `REORGED → SEEN` (the lock's
    /// transaction re-entered the active chain). A reorg rewind **deletes** an unsigned lock
    /// instead of marking it `REORGED`.
    LockState: "lock";
    /// In a block, fewer than `C_Y` confirmations.
    Seen = "SEEN",
    /// `C_Y` confirmations reached.
    Confirmed = "CONFIRMED",
    /// The lock policy (§4.1) accepts it.
    PolicyOk = "POLICY_OK",
    /// The lock policy refuses it (never minted; the owner recovers).
    PolicyRejected = "POLICY_REJECTED",
    /// This attestor's EIP-712 `Mint` signature exists (sign-once record).
    Signed = "SIGNED",
    /// An immediate (k-of-n) mint was submitted.
    MintSubmitted = "MINT_SUBMITTED",
    /// An optimistic mint was proposed (CR-W1).
    Proposed = "PROPOSED",
    /// The proposal was challenged.
    Challenged = "CHALLENGED",
    /// The proposal was executed.
    Executed = "EXECUTED",
    /// `Minted` observed on Ethereum (finalized).
    Minted = "MINTED",
    /// The lock left the active chain.
    Reorged = "REORGED",
}

impl Machine for LockState {
    const KIND: ObjectKind = ObjectKind::Lock;
    const ALL: &'static [Self] = &[
        Self::Seen,
        Self::Confirmed,
        Self::PolicyOk,
        Self::PolicyRejected,
        Self::Signed,
        Self::MintSubmitted,
        Self::Proposed,
        Self::Challenged,
        Self::Executed,
        Self::Minted,
        Self::Reorged,
    ];
    fn edge(self, to: Self) -> Option<Edge> {
        use LockState::*;
        let fwd = matches!(
            (self, to),
            (Seen, Confirmed)
                | (Confirmed, PolicyOk)
                | (Confirmed, PolicyRejected)
                | (PolicyOk, Signed)
                | (PolicyOk, Minted)
                | (Signed, MintSubmitted)
                | (Signed, Proposed)
                | (Signed, Minted)
                | (MintSubmitted, Minted)
                | (Proposed, Challenged)
                | (Proposed, Executed)
                | (Challenged, Proposed)
                | (Executed, Minted)
                | (Reorged, Seen)
        ) || (to == Reorged && self != Reorged);
        fwd.then_some(Edge::Forward)
    }
}

states! {
    /// The Burn machine (§5.1):
    ///
    /// ```text
    /// SEEN(unfinalized) → FINALIZED → (ORPHANED | ASSIGNED(leader, deadline))
    /// ASSIGNED → INTENT_PENDING(intent) → INTENT_CONFIRMED → RELEASED
    /// INTENT_* → CANCELLED → FINALIZED (reassignment)
    /// FINALIZED → WAITING_CAP(epoch)
    /// ```
    ///
    /// *(ledger)* additions: `ASSIGNED → ASSIGNED` (takeover: the next leader, §5.2);
    /// `ASSIGNED → WAITING_CAP` (the leader found the cap exhausted when building, §5.5);
    /// `WAITING_CAP → FINALIZED | ASSIGNED` (the epoch turned); `FINALIZED | WAITING_CAP →
    /// INTENT_PENDING` (an intent for the burn appeared before this attestor assigned it).
    /// Rewind edges: `INTENT_CONFIRMED → INTENT_PENDING`, `RELEASED → INTENT_CONFIRMED`.
    BurnState: "burn";
    /// In a non-finalized Ethereum block (display and early warning only).
    Seen = "SEEN",
    /// In a finalized block; waiting for a leader.
    Finalized = "FINALIZED",
    /// The recipient does not decode (§3.4): never released.
    Orphaned = "ORPHANED",
    /// A leader is assigned (column `leader`, `assigned_height`).
    Assigned = "ASSIGNED",
    /// S-3 would refuse it; waits for epoch `waiting_epoch` (§5.5).
    WaitingCap = "WAITING_CAP",
    /// Its intent is in the mempool (column `intent`).
    IntentPending = "INTENT_PENDING",
    /// Its intent is mined.
    IntentConfirmed = "INTENT_CONFIRMED",
    /// Its intent was released to the recipient.
    Released = "RELEASED",
    /// Its intent was cancelled; the next step is `FINALIZED` (reassignment).
    Cancelled = "CANCELLED",
}

impl Machine for BurnState {
    const KIND: ObjectKind = ObjectKind::Burn;
    const ALL: &'static [Self] = &[
        Self::Seen,
        Self::Finalized,
        Self::Orphaned,
        Self::Assigned,
        Self::WaitingCap,
        Self::IntentPending,
        Self::IntentConfirmed,
        Self::Released,
        Self::Cancelled,
    ];
    fn edge(self, to: Self) -> Option<Edge> {
        use BurnState::*;
        match (self, to) {
            (Seen, Finalized)
            | (Finalized, Orphaned)
            | (Finalized, Assigned)
            | (Finalized, WaitingCap)
            | (Assigned, Assigned)
            | (Assigned, WaitingCap)
            | (WaitingCap, Finalized)
            | (WaitingCap, Assigned)
            | (Finalized, IntentPending)
            | (Assigned, IntentPending)
            | (WaitingCap, IntentPending)
            | (IntentPending, IntentConfirmed)
            | (IntentConfirmed, Released)
            | (IntentPending, Cancelled)
            | (IntentConfirmed, Cancelled)
            | (Cancelled, Finalized) => Some(Edge::Forward),
            (IntentConfirmed, IntentPending) | (Released, IntentConfirmed) => Some(Edge::Rewind),
            _ => None,
        }
    }
}

states! {
    /// The Intent machine (§5.1):
    ///
    /// ```text
    /// OBSERVED → MATCHED(burn | roll) | UNMATCHED → CANCEL_SENT → CANCELLED | MATURED_UNMATCHED
    /// ```
    ///
    /// *(ledger)* additions: `MATCHED → RELEASED` (the plan tracks release on the burn; the
    /// intent records it too); `MATCHED → CANCELLED` (cancelled by another attestor: griefing
    /// evidence, or the losing side of a benign race); `MATCHED → UNMATCHED` (re-classified:
    /// another intent consumed the burn first); `UNMATCHED → MATCHED` (re-classified before a
    /// cancel was sent, e.g. this attestor's Ethereum view lagged the burn's finality);
    /// `UNMATCHED → CANCELLED` (another attestor's cancel was mined first);
    /// `MATURED_UNMATCHED → RELEASED` (a release mined while this attestor did not yet know the
    /// intent's burn — a restart, or a lagging Ethereum view — adopted once the burn is known,
    /// so the burn is not posted again). Rewind edges:
    /// `CANCELLED → CANCEL_SENT | MATCHED | UNMATCHED`, `RELEASED → MATCHED`.
    IntentState: "intent";
    /// Seen, not yet classified.
    Observed = "OBSERVED",
    /// Matches a finalized burn or is a valid roll.
    Matched = "MATCHED",
    /// Matches nothing: to be cancelled (`classification` holds the reason).
    Unmatched = "UNMATCHED",
    /// This attestor's cancel is broadcast (column `cancel_txid`).
    CancelSent = "CANCEL_SENT",
    /// A cancel is mined.
    Cancelled = "CANCELLED",
    /// The window passed without a cancel (alarm).
    MaturedUnmatched = "MATURED_UNMATCHED",
    /// Released after the delay.
    Released = "RELEASED",
}

impl Machine for IntentState {
    const KIND: ObjectKind = ObjectKind::Intent;
    const ALL: &'static [Self] = &[
        Self::Observed,
        Self::Matched,
        Self::Unmatched,
        Self::CancelSent,
        Self::Cancelled,
        Self::MaturedUnmatched,
        Self::Released,
    ];
    fn edge(self, to: Self) -> Option<Edge> {
        use IntentState::*;
        match (self, to) {
            (Observed, Matched)
            | (Observed, Unmatched)
            | (Matched, Released)
            | (Matched, Cancelled)
            | (Matched, Unmatched)
            | (Unmatched, Matched)
            | (Unmatched, CancelSent)
            | (Unmatched, Cancelled)
            | (Unmatched, MaturedUnmatched)
            | (CancelSent, Cancelled)
            | (CancelSent, MaturedUnmatched)
            | (MaturedUnmatched, Released) => Some(Edge::Forward),
            (Cancelled, CancelSent)
            | (Cancelled, Matched)
            | (Cancelled, Unmatched)
            | (Released, Matched) => Some(Edge::Rewind),
            _ => None,
        }
    }
}

states! {
    /// The Vault machine (§5.1): `LIVE → ROLL_DUE → ROLLING → ROLLED ; LIVE → SPENT`.
    ///
    /// *(ledger)* additions: `ROLL_DUE → SPENT` (drained by a release before its roll, §3.1
    /// item 3; or recovered by its owner); `ROLLING → SPENT` (the roll intent was cancelled — the
    /// cancel re-creates the value as a new vault row). Rewind edges: `SPENT → LIVE`,
    /// `ROLLED → ROLLING`.
    VaultState: "vault";
    /// Unspent.
    Live = "LIVE",
    /// Within `ROLL_MARGIN` of its `ownerHeight`.
    RollDue = "ROLL_DUE",
    /// Unlocked into a roll intent.
    Rolling = "ROLLING",
    /// The roll intent was released into a fresh vault.
    Rolled = "ROLLED",
    /// Spent (unlocked for a burn, recovered by its owner, or its roll cancelled).
    Spent = "SPENT",
}

impl Machine for VaultState {
    const KIND: ObjectKind = ObjectKind::Vault;
    const ALL: &'static [Self] = &[
        Self::Live,
        Self::RollDue,
        Self::Rolling,
        Self::Rolled,
        Self::Spent,
    ];
    fn edge(self, to: Self) -> Option<Edge> {
        use VaultState::*;
        match (self, to) {
            (Live, RollDue)
            | (RollDue, Rolling)
            | (Rolling, Rolled)
            | (Live, Spent)
            | (RollDue, Spent)
            | (Rolling, Spent) => Some(Edge::Forward),
            (Spent, Live) | (Rolled, Rolling) => Some(Edge::Rewind),
            _ => None,
        }
    }
}

states! {
    /// The SlashCase machine (§5.1): `OPENED(evidence) → VOTED(mine) → SUBMITTED → SLASHED |
    /// EXPIRED`.
    ///
    /// *(ledger)* additions: `OPENED | VOTED → EXPIRED` and `OPENED | VOTED → SLASHED` (the case
    /// lapsed, or other members' act removed the target before this attestor voted or
    /// submitted). Rewind edges: `SLASHED → SUBMITTED | VOTED | OPENED` (the act's block was
    /// reorged).
    SlashState: "slash";
    /// Evidence recorded.
    Opened = "OPENED",
    /// This attestor's act signature recorded.
    Voted = "VOTED",
    /// `set_sendact` broadcast (column `txid`).
    Submitted = "SUBMITTED",
    /// The `SET_REMOVE` is mined.
    Slashed = "SLASHED",
    /// The case lapsed without enough votes.
    Expired = "EXPIRED",
}

impl Machine for SlashState {
    const KIND: ObjectKind = ObjectKind::SlashCase;
    const ALL: &'static [Self] = &[
        Self::Opened,
        Self::Voted,
        Self::Submitted,
        Self::Slashed,
        Self::Expired,
    ];
    fn edge(self, to: Self) -> Option<Edge> {
        use SlashState::*;
        match (self, to) {
            (Opened, Voted)
            | (Voted, Submitted)
            | (Submitted, Slashed)
            | (Opened, Slashed)
            | (Voted, Slashed)
            | (Opened, Expired)
            | (Voted, Expired)
            | (Submitted, Expired) => Some(Edge::Forward),
            (Slashed, Submitted) | (Slashed, Voted) | (Slashed, Opened) => Some(Edge::Rewind),
            _ => None,
        }
    }
}

states! {
    /// The fault kinds of §2.3.
    FaultKind: "fault";
    /// Two set signatures by one key over two spends of one outpoint (`SET_EQUIVOCATION`).
    Equivocation = "EQUIVOCATION",
    /// An intent with no finalized burn behind it, the wrong value or recipient, or a consumed
    /// burn.
    FraudulentIntent = "FRAUDULENT_INTENT",
    /// A mint signature or proposal with no lock behind it, or the wrong amount or recipient.
    FraudulentMint = "FRAUDULENT_MINT",
    /// Cancelling or challenging honest work (`SET_REMOVE burn=0`).
    Griefing = "GRIEFING",
    /// Two EIP-712 `Mint` signatures for one `lockId` with different `(amount, to)`.
    MintEquivocation = "MINT_EQUIVOCATION",
}

impl FaultKind {
    /// Every fault kind.
    pub const ALL: &'static [Self] = &[
        Self::Equivocation,
        Self::FraudulentIntent,
        Self::FraudulentMint,
        Self::Griefing,
        Self::MintEquivocation,
    ];
}

/// The sign-once domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignDomain {
    /// EIP-712 `Mint(lockId, amount, to)`, keyed by `lockId`.
    Eip712Mint,
    /// A Ycash set signature in role unlock (`set_signunlock`).
    YcashUnlock,
    /// A Ycash set signature in role cancel (`set_signcancel`).
    YcashCancel,
    /// A Ycash act signature (`set_signact`, `set_heartbeat`).
    YcashAct,
}

impl SignDomain {
    /// The stored name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eip712Mint => "eip712-mint",
            Self::YcashUnlock => "ycash-unlock",
            Self::YcashCancel => "ycash-cancel",
            Self::YcashAct => "ycash-act",
        }
    }

    /// The three Ycash domains.
    pub const YCASH: &'static [Self] = &[Self::YcashUnlock, Self::YcashCancel, Self::YcashAct];
}

impl fmt::Display for SignDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SignDomain {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, StoreError> {
        [
            Self::Eip712Mint,
            Self::YcashUnlock,
            Self::YcashCancel,
            Self::YcashAct,
        ]
        .into_iter()
        .find(|d| d.as_str() == s)
        .ok_or_else(|| StoreError::corrupt(format!("unknown sign domain {s:?}")))
    }
}

impl rusqlite::types::ToSql for SignDomain {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.as_str().into())
    }
}

impl rusqlite::types::FromSql for SignDomain {
    fn column_result(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        v.as_str()?
            .parse()
            .map_err(|e: StoreError| rusqlite::types::FromSqlError::Other(e.into()))
    }
}

/// The two chains a cursor follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Ycash (active chain tip, reorgs rewound by height).
    Ycash,
    /// Ethereum (finalized blocks only).
    Ethereum,
}

impl Chain {
    /// The stored name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ycash => "ycash",
            Self::Ethereum => "ethereum",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Chain {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, StoreError> {
        match s {
            "ycash" => Ok(Self::Ycash),
            "ethereum" => Ok(Self::Ethereum),
            _ => Err(StoreError::corrupt(format!("unknown chain {s:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<S: Machine>() {
        for &s in S::ALL {
            assert_eq!(s.to_string().parse::<S>().unwrap(), s);
        }
        assert!("nope".parse::<S>().is_err());
    }

    #[test]
    fn names_round_trip() {
        round_trip::<LockState>();
        round_trip::<BurnState>();
        round_trip::<IntentState>();
        round_trip::<VaultState>();
        round_trip::<SlashState>();
        for &f in FaultKind::ALL {
            assert_eq!(f.to_string().parse::<FaultKind>().unwrap(), f);
        }
        for d in [
            SignDomain::Eip712Mint,
            SignDomain::YcashUnlock,
            SignDomain::YcashCancel,
            SignDomain::YcashAct,
        ] {
            assert_eq!(d.to_string().parse::<SignDomain>().unwrap(), d);
        }
        for &k in ObjectKind::ALL {
            assert_eq!(k.to_string().parse::<ObjectKind>().unwrap(), k);
        }
        assert_eq!(LockState::PolicyOk.to_string(), "POLICY_OK");
    }

    #[test]
    fn terminal_states() {
        assert!(LockState::PolicyRejected.edge(LockState::Reorged).is_some());
        assert!(!LockState::Minted.is_terminal()); // → REORGED (exposure)
        assert!(BurnState::Orphaned.is_terminal());
        assert!(BurnState::Released.is_terminal());
        // → RELEASED: a release recorded while the burn was unknown here is adopted later
        assert!(!IntentState::MaturedUnmatched.is_terminal());
        assert!(IntentState::Released.is_terminal());
        assert!(VaultState::Rolled.is_terminal());
        assert!(VaultState::Spent.is_terminal());
        assert!(SlashState::Slashed.is_terminal());
        assert!(SlashState::Expired.is_terminal());
    }
}
