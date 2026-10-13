// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying file LICENSE or
// https://www.opensource.org/licenses/mit-license.php.

//! `hawkeye audit-ledger` (remedial report 05/M-3; `docs/operations.md` §5): is this ledger
//! behind the chain?
//!
//! The ledger's Ycash sign-once records (and, in `"wallet"` mode, the node wallet's) are the
//! only guard against signing a second spend of a vault this member already signed — a provable
//! equivocation (`SET_EQUIVOCATION`: ejection and a frozen bond). A ledger restored from an old
//! backup, or copied to a second host, lacks the newest records. The audit reads the ledger
//! without migrating or writing it and compares it with what the node shows:
//!
//! 1. every Ycash sign-once record of the set, with whether its outpoint is still unspent
//!    (`gettxout`, mempool included: a live record);
//! 2. every unlock this member signed that the node still shows — the transactions behind the
//!    set's unspent intents (`vault_list`) and every mempool transaction spending a vault of the
//!    set with the UNLOCK selector —
//!    attributed by signature; one with no `YcashUnlock` record for its vault here is
//!    **missing**: the ledger is behind the chain, and starting from it risks an equivocation.
//!
//! Spent intents are not revisited (their vaults are gone; a second spend cannot confirm), and
//! cancels and acts are listed from the ledger only.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::template::{TemplateKind, parse_selector, parse_vault};
use hawkeye_core::{OutPoint as CoreOutPoint, PubKey33};
use hawkeye_store::{Chain, SignDomain, Store};
use hawkeye_ycash::tx::Transaction;
use hawkeye_ycash::types::{TemplateKind as RpcKind, VaultListFilter};
use hawkeye_ycash::{Hash256, YcashRpc};
use serde::Serialize;

use crate::attribution::Attributor;
use crate::config::Params;
use crate::convert::op_core;

/// One sign-once record and where its outpoint stands.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecordRow {
    /// `ycash-unlock`, `ycash-cancel`, `ycash-act`.
    pub domain: String,
    /// The signed prevout.
    pub prevout: String,
    /// The outpoint is still unspent (mempool included): the record is live.
    pub unspent: bool,
    /// Unix seconds.
    pub signed_at: i64,
}

/// An unlock this member signed that the ledger has no record of.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Missing {
    /// The vault the unlock spends.
    pub vault: String,
    /// The unlock transaction.
    pub txid: String,
    /// `mempool` or `chain`.
    pub seen: &'static str,
}

/// The audit's result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditReport {
    /// The ledger's schema version.
    pub schema: u32,
    /// The ledger's Ycash cursor (height), if any.
    pub ledger_cursor: Option<u64>,
    /// The node's tip.
    pub node_tip: u32,
    /// The ledger's Ycash sign-once records of the set.
    pub records: Vec<RecordRow>,
    /// Unlocks signed by this member on the chain or in the mempool with no record here.
    pub missing: Vec<Missing>,
    /// No record is missing.
    pub ok: bool,
}

impl AuditReport {
    /// The one-line verdict.
    pub fn verdict(&self) -> String {
        if self.ok {
            format!(
                "ledger consistent with the node: {} sign-once records ({} live), none missing",
                self.records.len(),
                self.records.iter().filter(|r| r.unspent).count()
            )
        } else {
            let v: Vec<&str> = self.missing.iter().map(|m| m.vault.as_str()).collect();
            format!(
                "ledger is behind the chain: records for vault {} missing — do not sign from \
                 this ledger (docs/operations.md §5)",
                v.join(", ")
            )
        }
    }
}

/// What the audit reads from the ledger (sync, so a caller holding the ledger behind a mutex
/// can release it before the node is asked).
#[derive(Debug, Clone)]
pub struct LedgerView {
    schema: u32,
    cursor: Option<u64>,
    recs: Vec<hawkeye_store::YcashSignRecord>,
}

/// Read the [`LedgerView`] of `store` for the set of `p` (opened read-only or not; only read).
pub fn ledger_view(store: &mut Store, p: &Params) -> Result<LedgerView> {
    let schema = store.schema_version()?;
    let (cursor, recs) = store.read(|t| {
        Ok::<_, hawkeye_store::StoreError>((
            t.cursor(Chain::Ycash)?.map(|c| c.height),
            t.ycash_signatures(&p.set_id)?,
        ))
    })?;
    Ok(LedgerView {
        schema,
        cursor,
        recs,
    })
}

/// Audit `store` against the node, for member `me`.
pub async fn audit_ledger(
    store: &mut Store,
    ycash: &YcashRpc,
    attributor: &dyn Attributor,
    p: &Params,
    me: &PubKey33,
) -> Result<AuditReport> {
    let view = ledger_view(store, p)?;
    audit_view(view, ycash, attributor, p, me).await
}

/// Audit a [`LedgerView`] against the node, for member `me`.
pub async fn audit_view(
    view: LedgerView,
    ycash: &YcashRpc,
    attributor: &dyn Attributor,
    p: &Params,
    me: &PubKey33,
) -> Result<AuditReport> {
    let LedgerView {
        schema,
        cursor,
        recs,
    } = view;
    let node_tip = ycash.getblockcount().await?;
    let mut records = vec![];
    let mut unlocked: BTreeSet<CoreOutPoint> = BTreeSet::new();
    for r in &recs {
        let op = r.key.prevout;
        let unspent = ycash
            .gettxout(&Hash256::from_internal(op.txid), op.vout, true)
            .await?
            .is_some();
        if r.key.domain == SignDomain::YcashUnlock {
            unlocked.insert(op);
        }
        records.push(RecordRow {
            domain: r.key.domain.to_string(),
            prevout: op.to_string(),
            unspent,
            signed_at: r.signed_at,
        });
    }
    // the transactions behind the set's unspent intents, and the mempool's intent creators
    let mut candidates: Vec<(Hash32, &'static str)> = vec![];
    let rows = ycash
        .vault_list(Some(&VaultListFilter {
            tag: Some(p.tag_text()),
            setid: Some(p.set_hash()),
            kind: Some(RpcKind::Intent),
            ..Default::default()
        }))
        .await?;
    for r in rows.iter().filter_map(|r| r.as_intent()) {
        candidates.push((r.txid.0, "chain"));
    }
    for txid in ycash.getrawmempool().await? {
        if !candidates.iter().any(|(t, _)| *t == txid.0) {
            candidates.push((txid.0, "mempool"));
        }
    }
    let mut missing = vec![];
    let mut seen_tx = BTreeSet::new();
    for (txid, seen) in candidates {
        if !seen_tx.insert(txid) {
            continue;
        }
        let Ok(raw) = ycash.getrawtransaction(&Hash256::from_internal(txid)).await else {
            continue;
        };
        let Ok(tx) = Transaction::decode(raw.as_slice()) else {
            continue;
        };
        for (idx, input) in tx.inputs.iter().enumerate() {
            if parse_selector(TemplateKind::Vault, &input.script_sig)
                .map(|s| s.selector)
                .ok()
                != Some(1)
            {
                continue;
            }
            let Ok(prev_raw) = ycash.getrawtransaction(&input.prevout.txid).await else {
                continue;
            };
            let Ok(prev) = Transaction::decode(prev_raw.as_slice()) else {
                continue;
            };
            let Some(o) = prev.outputs.get(input.prevout.vout as usize) else {
                continue;
            };
            let Ok(v) = parse_vault(&o.script_pubkey) else {
                continue;
            };
            if v.tag != p.tag() || v.set_id != p.set_id {
                continue;
            }
            let a = attributor.attribute(
                raw.as_slice(),
                idx,
                &o.script_pubkey,
                u64::try_from(o.value).unwrap_or(0),
                hawkeye_core::VAULT_BRANCH_ID,
            );
            let Ok(a) = a else {
                continue;
            };
            if !a.signers.iter().any(|s| s.pubkey == *me) {
                continue;
            }
            let vault = op_core(&input.prevout);
            if !unlocked.contains(&vault) {
                missing.push(Missing {
                    vault: vault.to_string(),
                    txid: hex::encode({
                        let mut t = txid;
                        t.reverse();
                        t
                    }),
                    seen,
                });
            }
        }
    }
    let ok = missing.is_empty();
    Ok(AuditReport {
        schema,
        ledger_cursor: cursor,
        node_tip,
        records,
        missing,
        ok,
    })
}

/// `anyhow` error for a failed audit (the CLI's exit status).
pub fn refuse(r: &AuditReport) -> anyhow::Error {
    anyhow!("{}", r.verdict())
}
