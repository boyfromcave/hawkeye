// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying file LICENSE or
// https://www.opensource.org/licenses/mit-license.php.

//! Ledger-restore detection (review L-2 of the 01/V-2 unlock-revival fix; V-N1).
//!
//! A ledger restored from a backup has forgotten the newest sign-once records: unlocks this
//! member signed and may not have broadcast, whose bytes stay revivable (01/V-2). Signing a
//! fresh vault for such a burn could pay it twice. `hawkeye audit-ledger` (05/M-3) catches the
//! records the chain or the mempool still shows; this catches the rest, as far as possible:
//!
//! - a **high-water mark** next to the ledger (`<ledger>.hwm`): the number of Ycash sign-once
//!   records the ledger has held, rewritten after every tick. The file is a member signature
//!   over that count and the ledger's `meta.ledger_id` (plan §4.7). A verified mark above the
//!   ledger's row count is a restore. A file that does not verify refuses start, so editing the
//!   number cannot make a stock daemon answer `restored`. An operator who restores the mark
//!   with the ledger defeats the count check;
//! - in `"wallet"` mode, the node wallet's own sign-once records (`set_listsigned`): one of the
//!   set with no record here means the ledger lacks it.
//!
//! On detection the ledger's `meta.ledger_restored` is set and the alarm `ledger-restored`
//! raised; until `hawkeye acknowledge-ledger-restore`, a fresh unlock is signed only after
//! **every** other current member has answered, signed, that it holds no unlock for the burn
//! (`Engine::prior_unlock`), mirroring the node's `set-sign-restored`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::{PubKey33, SecretKey};
use hawkeye_store::SignDomain;
use hawkeye_store::{Store, StoreError};
use serde::Deserialize;
use tracing::{error, info};

use crate::engine::Ctx;
use crate::engine::burn::LEDGER_RESTORED;

/// `meta` key of the 16-byte ledger id the high-water mark signs (plan §4.7).
pub const LEDGER_ID_META: &str = "ledger_id";

/// The high-water-mark file of a ledger.
pub fn hwm_path(store: &Path) -> PathBuf {
    let mut p = store.as_os_str().to_owned();
    p.push(".hwm");
    PathBuf::from(p)
}

/// The count written in the mark file (0 when absent or not a v1 number / v2 object).
/// This does not check the signature; [`reconcile_hwm`] does.
pub fn read_hwm(path: &Path) -> u64 {
    match classify(path) {
        Class::V1(n) | Class::V2 { count: n, .. } => n,
        Class::Missing | Class::Bad => 0,
    }
}

/// The file's text, one log field, capped. Empty when the file is absent.
pub fn mark_preview(path: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let text = text.replace(['\n', '\r'], "\\n");
    let mut end = 400.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    if end < text.len() {
        format!("{}…", &text[..end])
    } else {
        text
    }
}

/// `meta.ledger_id`, creating it (16 bytes from `/dev/urandom`) when absent.
pub fn ensure_ledger_id(t: &hawkeye_store::Tx<'_>) -> Result<[u8; 16], StoreError> {
    if let Some(raw) = t.meta(LEDGER_ID_META)? {
        return decode_ledger_id(&raw);
    }
    let id = crate::peer_auth::random_nonce()
        .map_err(|e| StoreError::Invalid(format!("ledger id: {e}")))?;
    t.set_meta(LEDGER_ID_META, &hex::encode(id))?;
    Ok(id)
}

/// Raise the mark to `count` when the file already verifies for this ledger (never lowers it).
/// A file that does not verify is left in place and returned as an error.
pub fn write_hwm(
    path: &Path,
    key: &SecretKey,
    set_id: &Hash32,
    ledger_id: &[u8; 16],
    count: u64,
) -> Result<()> {
    match classify(path) {
        Class::Missing => write_signed(path, key, set_id, ledger_id, count),
        Class::V2 {
            ledger_id: id,
            count: have,
            sig,
        } if id == *ledger_id && verify_mark(&key.public_key(), set_id, &id, have, &sig) => {
            if have >= count {
                Ok(())
            } else {
                write_signed(path, key, set_id, ledger_id, count)
            }
        }
        _ => Err(refusal(path)),
    }
}

/// Set the mark to `count` exactly (after an acknowledged restore, or `--reset-ledger-hwm`).
pub fn reset_hwm(
    path: &Path,
    key: &SecretKey,
    set_id: &Hash32,
    ledger_id: &[u8; 16],
    count: u64,
) -> Result<()> {
    write_signed(path, key, set_id, ledger_id, count)
}

/// Rewrite the mark at the ledger's current sign-once count.
pub fn reset_from_ledger(
    store: &mut Store,
    path: &Path,
    key: &SecretKey,
    set_id: &Hash32,
) -> Result<()> {
    let (id, n) =
        store.tx(|t| Ok::<_, StoreError>((ensure_ledger_id(t)?, t.ycash_signature_count()?)))?;
    reset_hwm(path, key, set_id, &id, n)
}

/// Bind the mark to this ledger. `Ok(Some(why))` is a verified mark above the row count.
/// `Err` means the file does not verify: start-up must stop, and `ledger_restored` stays unset.
/// A v1 decimal is migrated once, at that value, while `meta.ledger_id` is still absent.
pub fn reconcile_hwm(
    store: &mut Store,
    path: &Path,
    key: &SecretKey,
    set_id: &Hash32,
) -> Result<Option<String>> {
    let (had, existing, records) = store.tx(|t| {
        let existing = t.meta(LEDGER_ID_META)?;
        Ok::<_, StoreError>((existing.is_some(), existing, t.ycash_signature_count()?))
    })?;
    match classify(path) {
        Class::V1(n) if !had => {
            let id = crate::peer_auth::random_nonce().map_err(|e| anyhow!("ledger id: {e}"))?;
            write_signed(path, key, set_id, &id, n)?;
            store.tx(|t| {
                if t.meta(LEDGER_ID_META)?.is_none() {
                    t.set_meta(LEDGER_ID_META, &hex::encode(id))?;
                }
                Ok::<_, StoreError>(())
            })?;
            info!(event = "ledger_hwm_migrated", count = n, path = %path.display(), records);
            Ok(restored_if_ahead(path, records, n))
        }
        Class::Missing => {
            let _ = ledger_id_from(store, existing)?;
            Ok(None)
        }
        Class::V1(_) | Class::Bad => Err(refusal(path)),
        Class::V2 {
            ledger_id,
            count,
            sig,
        } => {
            let id = ledger_id_from(store, existing)?;
            if ledger_id != id || !verify_mark(&key.public_key(), set_id, &ledger_id, count, &sig) {
                return Err(refusal(path));
            }
            Ok(restored_if_ahead(path, records, count))
        }
    }
}

/// After every tick: raise the mark to the ledger's current count. A file that does not verify
/// is left untouched.
pub(crate) fn raise_ledger_hwm(ctx: &Ctx, path: &Path) -> Result<()> {
    let mut store = ctx.store.lock().unwrap_or_else(|e| e.into_inner());
    let _why = reconcile_hwm(&mut store, path, &ctx.key, &ctx.params.set_id)?;
    let (id, n) =
        store.tx(|t| Ok::<_, StoreError>((ensure_ledger_id(t)?, t.ycash_signature_count()?)))?;
    write_hwm(path, &ctx.key, &ctx.params.set_id, &id, n)
}

/// Why the ledger looks restored, if it does.
pub async fn detect(ctx: &Ctx, hwm: &Path) -> Result<Option<String>> {
    let mark = {
        let mut store = ctx.store.lock().unwrap_or_else(|e| e.into_inner());
        reconcile_hwm(&mut store, hwm, &ctx.key, &ctx.params.set_id)?
    };
    if mark.is_some() {
        return Ok(mark);
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
        let tip = ctx.ycash.getblockcount().await?;
        error!(event = "ledger_restored", reason = %why, height = tip,
               "fresh unlocks wait for every member's signed answer until `hawkeye acknowledge-ledger-restore`");
        ctx.db(|t| {
            t.set_meta(LEDGER_RESTORED, &why)?;
            if t.meta(crate::engine::burn::LEDGER_RESTORED_HEIGHT)?
                .is_none()
            {
                t.set_meta(
                    crate::engine::burn::LEDGER_RESTORED_HEIGHT,
                    &tip.to_string(),
                )?;
            }
            Ok(())
        })?;
    } else {
        info!(event = "ledger_restore_check_ok");
    }
    Ok(())
}

#[derive(Deserialize)]
struct MarkJson {
    v: u32,
    ledger_id: String,
    count: u64,
    sig: String,
}

enum Class {
    Missing,
    V1(u64),
    V2 {
        ledger_id: [u8; 16],
        count: u64,
        sig: [u8; 65],
    },
    Bad,
}

fn classify(path: &Path) -> Class {
    if !path.exists() {
        return Class::Missing;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Class::Bad;
    };
    let text = text.trim();
    if text.is_empty() {
        return Class::Bad;
    }
    if let Ok(n) = text.parse::<u64>() {
        return Class::V1(n);
    }
    let Ok(parsed) = serde_json::from_str::<MarkJson>(text) else {
        return Class::Bad;
    };
    if parsed.v != 2 {
        return Class::Bad;
    }
    let Ok(ledger_id) = decode_ledger_id(&parsed.ledger_id) else {
        return Class::Bad;
    };
    let Ok(sig) = hawkeye_core::peerauth::parse_sig(&parsed.sig) else {
        return Class::Bad;
    };
    Class::V2 {
        ledger_id,
        count: parsed.count,
        sig,
    }
}

fn decode_ledger_id(raw: &str) -> Result<[u8; 16], StoreError> {
    if raw.len() != 32 || !raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(StoreError::Corrupt(format!(
            "meta {LEDGER_ID_META} is not 32 lowercase hex chars"
        )));
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(raw, &mut id).map_err(|_| {
        StoreError::Corrupt(format!(
            "meta {LEDGER_ID_META} is not 32 lowercase hex chars"
        ))
    })?;
    Ok(id)
}

fn ledger_id_from(store: &mut Store, existing: Option<String>) -> Result<[u8; 16]> {
    if let Some(raw) = existing {
        return Ok(decode_ledger_id(&raw)?);
    }
    Ok(store.tx(ensure_ledger_id)?)
}

fn verify_mark(
    member: &PubKey33,
    set_id: &Hash32,
    ledger_id: &[u8; 16],
    count: u64,
    sig: &[u8],
) -> bool {
    let msg = hawkeye_core::peerauth::hwm_msg(set_id, ledger_id, count);
    hawkeye_core::peerauth::verify(member, &msg, sig).is_ok()
}

fn write_signed(
    path: &Path,
    key: &SecretKey,
    set_id: &Hash32,
    ledger_id: &[u8; 16],
    count: u64,
) -> Result<()> {
    let msg = hawkeye_core::peerauth::hwm_msg(set_id, ledger_id, count);
    let sig = hawkeye_core::peerauth::sign(key, &msg)
        .map_err(|e| anyhow!("signing the ledger high-water mark: {e}"))?;
    let body = serde_json::json!({
        "v": 2,
        "ledger_id": hex::encode(ledger_id),
        "count": count,
        "sig": hex::encode(sig),
    });
    let tmp = path.with_extension("hwm.tmp");
    std::fs::write(&tmp, format!("{body}\n"))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn restored_if_ahead(path: &Path, records: u64, mark: u64) -> Option<String> {
    if mark > records {
        Some(format!(
            "the ledger holds {records} sign-once records, its high-water mark {} says {mark}",
            path.display()
        ))
    } else {
        None
    }
}

fn refusal(path: &Path) -> anyhow::Error {
    anyhow!(
        "ledger high-water mark {} does not verify (edited, or from another ledger): inspect it, then `hawkeye run --reset-ledger-hwm` to re-write it from this ledger",
        path.display()
    )
}
