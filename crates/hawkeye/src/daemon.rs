//! `hawkeye run`: connect, start-up checks, the API, and the loop (plan §9 H5).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use hawkeye_core::SecretKey;
use hawkeye_store::Store;
use hawkeye_ycash::YcashRpc;
use tracing::{error, info, warn};

use crate::attribution::{Attributor, CoreAttributor};
use crate::config::Settings;
use crate::engine::{Ctx, Engine, guardian_mismatch};
use crate::foreign::{self, MAINNET_MIN_THRESHOLD};
use crate::peer_auth::{AuthState, PeerSigner};
use crate::peers::Peers;
use crate::status::Status;
use hawkeye_core::Deployment;
use hawkeye_core::memo::{MemoKind, parse_memo_script_for};

/// Connect to both chains (the foreign one through its adapter, [`foreign::connect`]) and open
/// the ledger. The adapter must be the configured deployment and speak the memo this build's
/// codec does.
pub async fn connect(s: &Settings, key: SecretKey, attributor: Arc<dyn Attributor>) -> Result<Ctx> {
    let ycash = YcashRpc::new(s.ycash_url.clone(), s.ycash_auth.clone())?;
    let foreign = foreign::connect(s, &key).await?;
    ensure!(
        foreign.deployment() == s.params.deployment,
        "the {} adapter is deployment {:?}, the config says {:?}",
        foreign.kind(),
        foreign.deployment(),
        s.params.deployment
    );
    // the engine's memos, tag, policy and matcher follow the configured kind
    ensure!(
        foreign.kind() == s.params.bridge_kind
            && foreign.memo_magic() == s.params.bridge_kind.memo_magic(),
        "the adapter is a {} bridge (memo {:?}), the config says {}",
        foreign.kind(),
        String::from_utf8_lossy(&foreign.memo_magic()),
        s.params.bridge_kind
    );
    let mut store =
        Store::open(&s.store_path).with_context(|| format!("ledger {}", s.store_path.display()))?;
    let backfilled = store
        .backfill_unlock_burns(|hex| burn_named_by(&s.params, hex))
        .context("ledger v6 backfill")?;
    if backfilled > 0 {
        info!(
            event = "ledger_backfill",
            table = "sign_once_unlock_burn",
            rows = backfilled
        );
    }
    // schema v9 (audit 05/L-3): pre-v9 Mint records were made for the deployment configured
    // then; records of another deployment (a migrated bridge) are kept and logged
    let dep = s.params.deployment;
    let set = store
        .tx(|t| t.backfill_mint_deployment(&dep))
        .context("ledger v9 backfill")?;
    if set > 0 {
        info!(
            event = "ledger_backfill",
            table = "sign_once_mint",
            rows = set
        );
    }
    for (d, n) in store.tx(|t| t.mint_signatures_elsewhere(&dep))? {
        info!(event = "ledger_has_other_deployment_rows", table = "sign_once_mint",
              chain_id = d.chain_id, bridge = %format!("0x{}", hex::encode(d.bridge.0)), rows = n,
              "Mint records of another bridge deployment (a migration): kept; this one is signed anew");
    }
    let peers = Peers::new(s.peers.clone())?.with_signer(PeerSigner {
        key: key.clone(),
        set_id: s.params.set_id,
        deployment: s.params.deployment,
        require_auth: s.peer_auth.require_auth,
    });
    Ok(Ctx {
        params: Arc::new(s.params.clone()),
        me: key.public_key(),
        key,
        ycash: Arc::new(ycash),
        foreign,
        store: Arc::new(Mutex::new(store)),
        attributor,
        peers,
        auth: Arc::new(AuthState::new(s.peer_auth.clone())),
        status: Arc::new(RwLock::new(Status::default())),
        network_name: s.network_name.clone(),
    })
}

/// The burn a signed unlock pays, from its `HKB1`/`HKN1` burn memo (the v6 backfill).
pub fn burn_named_by(p: &crate::config::Params, hex: &str) -> Option<(Deployment, u64)> {
    let tx = hawkeye_ycash::tx::Transaction::decode_hex(hex).ok()?;
    tx.outputs.iter().find_map(
        |o| match parse_memo_script_for(p.bridge_kind, &o.script_pubkey) {
            Ok(Some(m)) if m.kind == MemoKind::BurnRelease => Some((m.deployment, m.reference)),
            _ => None,
        },
    )
}

/// The start-up checks: the node's network, the set exists with at least the network's minimum
/// `maturity` (D-Q-31: 16,128 on mainnet/testnet, 2 on regtest), this key is a current member, the
/// guardian set matches the members (refused on mainnet, warned elsewhere), and the live bridge's
/// threshold is ≥ 2 on mainnet in every mint mode (plan §3.3; warned elsewhere when it is 1), and
/// on mainnet its `challengeWindow` is at least two hours and its `mintCap` non-zero (audit
/// 05/H-2; an unbounded cap is warned elsewhere) — the bridge's own rules through
/// [`ForeignChain::check_bridge`](foreign::ForeignChain::check_bridge).
pub async fn startup_checks(ctx: &Ctx) -> Result<()> {
    let info = ctx.ycash.getblockchaininfo().await.context("ycashd")?;
    let want = match ctx.network_name.as_str() {
        "mainnet" => "main",
        "testnet" => "test",
        _ => "regtest",
    };
    if info.chain != want {
        bail!(
            "ycashd is on {:?}, the config says {}",
            info.chain,
            ctx.network_name
        );
    }
    let set = ctx
        .ycash
        .set_getinfo(&ctx.set_hash(), None)
        .await
        .with_context(|| format!("the set {} does not exist on this node", ctx.set_hash()))?;
    let floor = hawkeye_ycash::types::min_set_maturity(&info.chain);
    if set.set.params.maturity < floor {
        bail!(
            "set {} has maturity {} < {floor}, the network's minimum exit window (D-Q-31): \
             a node that created it does not follow the current rules",
            ctx.set_hash(),
            set.set.params.maturity
        );
    }
    // the live floors (audit 05/M-4): the heartbeat against livenesswindow refuses on mainnet
    let locked = u64::try_from(set.set.lockedvalue.0).unwrap_or(0);
    for r in crate::floors::live_rows(&ctx.params, &set.set.params, locked) {
        if r.ok {
            continue;
        }
        if r.param == "bridge.heartbeat_blocks" && ctx.params.mainnet {
            bail!("mainnet refuses {r}: every member would go DORMANT (audit 05/M-4)");
        }
        warn!(event = "startup_param_below_floor", detail = %r, why = r.why);
    }
    let (other, total) = vault_delay_mismatch(ctx).await?;
    if other > 0 {
        warn!(
            event = "vault_delay_mismatch",
            other,
            total,
            delay = ctx.params.delay,
            "vaults of this tag and set carry another delay: the lock policy rejects every one of them"
        );
    }
    if !set
        .memberlist
        .iter()
        .any(|m| m.key.0 == ctx.me && m.current)
    {
        bail!(
            "member key {} is not a current member of set {}",
            hex::encode(ctx.me),
            ctx.set_hash()
        );
    }
    if let Some(d) = guardian_mismatch(ctx, &set.memberlist).await? {
        if ctx.params.mainnet {
            bail!("{d}");
        }
        warn!(event = "startup_guardian_mismatch", detail = %d);
    }
    let bridge = ctx
        .foreign
        .check_bridge(ctx.params.mainnet)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if set.set.params.unlockthreshold <= 1 {
        info!(
            event = "peer_unlock_sign_disabled",
            unlock_threshold = set.set.params.unlockthreshold,
            "POST /unlock/sign is inert: at unlockThreshold 1 (HK-1) the leader completes its \
             own unlocks and no peer co-signs"
        );
    }
    if set.set.params.cancelthreshold <= 1 {
        info!(
            event = "peer_cancel_sign_disabled",
            cancel_threshold = set.set.params.cancelthreshold,
            "POST /cancel/sign is inert: at cancelThreshold 1 any member cancels alone"
        );
    }
    if !ctx.auth.config.require_auth {
        warn!(
            event = "peer_auth_not_required",
            "[peers] require_auth = false: unsigned peer requests are admitted (regtest/testnet \
             rolling upgrade only)"
        );
    }
    let (threshold, window) = (bridge.threshold, bridge.challenge_window);
    if bridge.mint_cap == 0 {
        // refused on mainnet by check_bridge (audit 05/H-2)
        warn!(
            event = "startup_bridge_mint_cap_unbounded",
            "the bridge has no mint rate limit: a proposal nobody challenges mints without bound (development only)"
        );
    }
    if threshold < MAINNET_MIN_THRESHOLD {
        warn!(
            event = "startup_bridge_threshold_one",
            threshold,
            "one key can mint through the threshold path and skip the challenge window: development only"
        );
    }
    info!(event = "startup_ok", set = %ctx.set_hash(), member = %hex::encode(ctx.me),
          foreign = %ctx.foreign.kind(), tag = %ctx.params.tag_text(),
          eth = %ctx.guardian()?, chain = %info.chain, tip = info.blocks,
          mint_mode = %ctx.params.mint_mode, bridge_threshold = threshold,
          challenge_window = window, mint_cap = %bridge.mint_cap,
          cap_window = %bridge.cap_window);
    Ok(())
}

/// How many of the bridge's live vaults (its tag, its set) carry a `delay` other than the
/// configured one, of how many (audit 05/M-4: such a lock is rejected by the policy).
pub async fn vault_delay_mismatch(ctx: &Ctx) -> Result<(usize, usize)> {
    let rows = ctx
        .ycash
        .vault_list(Some(&hawkeye_ycash::types::VaultListFilter {
            tag: Some(ctx.params.tag_text()),
            setid: Some(ctx.set_hash()),
            kind: Some(hawkeye_ycash::types::TemplateKind::Vault),
            ..Default::default()
        }))
        .await
        .context("vault_list")?;
    let vaults: Vec<_> = rows.iter().filter_map(|r| r.as_vault()).collect();
    let other = vaults
        .iter()
        .filter(|v| v.fields.delay != u32::from(ctx.params.delay))
        .count();
    Ok((other, vaults.len()))
}

/// The start-up ledger audit (remedial report 05/M-3, `docs/operations.md` §5): refuse to sign
/// from a ledger that is behind the chain — an unlock this member signed, on the chain or in the
/// mempool, with no sign-once record here (a restored backup, a copied ledger) — unless the
/// operator passes `--i-accept-equivocation-risk`.
async fn ledger_audit(ctx: &Ctx, accept: bool) -> Result<()> {
    let view = {
        let mut st = ctx.store.lock().unwrap_or_else(|e| e.into_inner());
        crate::audit::ledger_view(&mut st, &ctx.params)?
    };
    let r = crate::audit::audit_view(
        view,
        &ctx.ycash,
        ctx.attributor.as_ref(),
        &ctx.params,
        &ctx.me,
    )
    .await
    .context("ledger audit")?;
    if r.ok {
        info!(event = "ledger_audit_ok", records = r.records.len());
        return Ok(());
    }
    for m in &r.missing {
        error!(event = "ledger_record_missing", vault = %m.vault, txid = %m.txid, seen = m.seen);
    }
    if accept {
        error!(event = "ledger_audit_overridden", verdict = %r.verdict(),
               "--i-accept-equivocation-risk: starting anyway");
        return Ok(());
    }
    Err(crate::audit::refuse(&r)).context(
        "refusing to start (hawkeye audit-ledger shows the detail; --i-accept-equivocation-risk \
         overrides)",
    )
}

/// Run the daemon until SIGINT/SIGTERM.
pub async fn run(s: &Settings, accept_equivocation_risk: bool) -> Result<()> {
    // `s.warnings` (floors, transport) are logged by `main` for every command
    let key = s.load_key()?;
    let ctx = connect(s, key, Arc::new(CoreAttributor)).await?;
    startup_checks(&ctx).await?;
    ledger_audit(&ctx, accept_equivocation_risk).await?;
    let listener = tokio::net::TcpListener::bind(s.listen)
        .await
        .with_context(|| format!("api listen {}", s.listen))?;
    info!(event = "api_listening", addr = %s.listen);
    let api_ctx = ctx.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::api::serve(listener, api_ctx).await {
            error!(event = "api_failed", error = %e);
        }
    });
    let mut engine = Engine::new(ctx);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        let r = engine.tick().await;
        if !r.errors.is_empty() {
            warn!(event = "tick_done", tip = r.tip, errors = r.errors.len());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
    }
    info!(event = "stopped");
    Ok(())
}
