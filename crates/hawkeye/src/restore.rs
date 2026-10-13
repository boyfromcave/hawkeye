// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying file LICENSE or
// https://www.opensource.org/licenses/mit-license.php.

//! Ledger-restore detection (review L-2 of the 01/V-2 unlock-revival fix).
//!
//! A ledger restored from a backup has forgotten the newest sign-once records: unlocks this
//! member signed and may not have broadcast, whose bytes stay revivable (01/V-2). Signing a
//! fresh vault for such a burn could pay it twice. `hawkeye audit-ledger` (05/M-3) catches the
//! records the chain or the mempool still shows; this catches the rest, as far as possible:
//!
//! - a **high-water mark** next to the ledger (`<ledger>.hwm`): the number of Ycash sign-once
//!   records the ledger has held, rewritten after every tick; a ledger holding fewer than its mark
//!   was restored (an operator who restores the mark with it defeats this check);
//! - in `"wallet"` mode, the node wallet's own sign-once records (`set_listsigned`): one of the
//!   set with no record here means the ledger lacks it.
//!
//! On detection the ledger's `meta.ledger_restored` is set and the alarm `ledger-restored`
//! raised; until `hawkeye acknowledge-ledger-restore`, a fresh unlock is signed only after
//! **every** other current member has answered, signed, that it holds no unlock for the burn
//! (`Engine::prior_unlock`), mirroring the node's `set-sign-restored`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hawkeye_store::SignDomain;
use tracing::{error, info};

use crate::engine::Ctx;
use crate::engine::burn::LEDGER_RESTORED;

/// The high-water-mark file of a ledger.
pub fn hwm_path(store: &Path) -> PathBuf {
    let mut p = store.as_os_str().to_owned();
    p.push(".hwm");
    PathBuf::from(p)
}

/// The recorded high-water mark (0 when absent or unreadable).
pub fn read_hwm(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Raise the mark to `count` (never lowers it).
pub fn write_hwm(path: &Path, count: u64) -> Result<()> {
    if read_hwm(path) >= count && path.exists() {
        return Ok(());
    }
    let tmp = path.with_extension("hwm.tmp");
    std::fs::write(&tmp, format!("{count}\n"))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Set the mark to `count` exactly (after an acknowledged restore).
pub fn reset_hwm(path: &Path, count: u64) -> Result<()> {
    std::fs::write(path, format!("{count}\n"))
        .with_context(|| format!("writing {}", path.display()))
}

/// Why the ledger looks restored, if it does.
pub async fn detect(ctx: &Ctx, hwm: &Path) -> Result<Option<String>> {
    let count = ctx.db(|t| t.ycash_signature_count())?;
    let mark = read_hwm(hwm);
    if mark > count {
        return Ok(Some(format!(
            "the ledger holds {count} sign-once records, its high-water mark {} says {mark}",
            hwm.display()
        )));
    }
    if ctx.params.ycash_signing == crate::config::YcashSigning::Wallet
        && let Ok(listed) = ctx.ycash.set_listsigned().await
    {
        for r in listed
            .records
            .iter()
            .filter(|r| r.setid.0 == ctx.params.set_id)
        {
            let domain = match r.role {
                1 => SignDomain::YcashUnlock,
                2 => SignDomain::YcashCancel,
                _ => continue,
            };
            let key = hawkeye_store::YcashSignKey {
                domain,
                set_id: ctx.params.set_id,
                prevout: crate::convert::op_core(&r.prevout),
            };
            if ctx.db(|t| t.ycash_signature(&key))?.is_none() {
                return Ok(Some(format!(
                    "the node wallet signed {} of {} with no record in the ledger",
                    domain, r.prevout
                )));
            }
        }
    }
    Ok(None)
}

/// In `"wallet"` mode: the vaults the node wallet signed an unlock of (`set_listsigned`, role 1)
/// with no record in the ledger (review N-2).
pub async fn unrecorded_unlocks(ctx: &Ctx) -> Result<Vec<hawkeye_core::OutPoint>> {
    if ctx.params.ycash_signing != crate::config::YcashSigning::Wallet {
        return Ok(vec![]);
    }
    let Ok(listed) = ctx.ycash.set_listsigned().await else {
        return Ok(vec![]);
    };
    let mut out = vec![];
    for r in listed
        .records
        .iter()
        .filter(|r| r.setid.0 == ctx.params.set_id && r.role == 1)
    {
        let op = crate::convert::op_core(&r.prevout);
        let key = hawkeye_store::YcashSignKey {
            domain: SignDomain::YcashUnlock,
            set_id: ctx.params.set_id,
            prevout: op,
        };
        if ctx.db(|t| t.ycash_signature(&key))?.is_none() {
            out.push(op);
        }
    }
    Ok(out)
}

/// At start-up: flag the ledger when it looks restored, and (wallet mode) record every vault the
/// node wallet signed an unlock of with no ledger record as an orphan candidate: it is marked
/// `ROLL_DUE` and reported until spent, so those forgotten bytes die (review N-2).
pub async fn check_restore(ctx: &Ctx, hwm: &Path) -> Result<()> {
    for op in unrecorded_unlocks(ctx).await? {
        error!(event = "restore_orphan", vault = %op,
               "the node wallet signed an unlock of this vault the ledger has no record of: rolling it");
        ctx.db(|t| {
            t.set_meta(
                &format!("{}{op}", crate::engine::roll::RESTORE_ORPHAN_PREFIX),
                "wallet",
            )
        })?;
    }
    if let Some(why) = detect(ctx, hwm).await? {
        error!(event = "ledger_restored", reason = %why,
               "fresh unlocks wait for every member's signed answer until `hawkeye acknowledge-ledger-restore`");
        ctx.db(|t| t.set_meta(LEDGER_RESTORED, &why))?;
    } else {
        info!(event = "ledger_restore_check_ok");
    }
    Ok(())
}
