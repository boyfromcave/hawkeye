//! `hawkeye run`: connect, start-up checks, the API, and the loop (plan §9 H5).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use hawkeye_core::SecretKey;
use hawkeye_eth::{EthClient, EthConfig};
use hawkeye_store::Store;
use hawkeye_ycash::YcashRpc;
use tracing::{error, info, warn};

use crate::attribution::{Attributor, CoreAttributor};
use crate::config::Settings;
use crate::engine::{Ctx, Engine, guardian_mismatch};
use crate::keys::eth_signer;
use crate::peers::Peers;
use crate::status::Status;

/// Connect to both chains and open the ledger.
pub async fn connect(s: &Settings, key: SecretKey, attributor: Arc<dyn Attributor>) -> Result<Ctx> {
    let ycash = YcashRpc::new(s.ycash_url.clone(), s.ycash_auth.clone())?;
    let mut ec = EthConfig::new(
        s.eth_url.clone(),
        s.deployment.chain_id,
        s.deployment.bridge,
    );
    ec.token = Some(s.deployment.token);
    ec.finality = s.finality;
    let eth = EthClient::connect(&ec, Some(eth_signer(&key)?))
        .await
        .map_err(|e| anyhow!("ethereum {}: {e}", s.eth_url))?;
    let store =
        Store::open(&s.store_path).with_context(|| format!("ledger {}", s.store_path.display()))?;
    Ok(Ctx {
        params: Arc::new(s.params.clone()),
        me: key.public_key(),
        key,
        ycash: Arc::new(ycash),
        eth,
        store: Arc::new(Mutex::new(store)),
        attributor,
        peers: Peers::new(s.peers.clone())?,
        status: Arc::new(RwLock::new(Status::default())),
        network_name: s.network_name.clone(),
    })
}

/// The start-up checks: the node's network, the set exists, this key is a current member, the
/// guardian set matches the members (refused on mainnet, warned elsewhere).
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
    info!(event = "startup_ok", set = %ctx.set_hash(), member = %hex::encode(ctx.me),
          eth = %ctx.key.eth_address().to_checksum(), chain = %info.chain, tip = info.blocks,
          mint_mode = %ctx.params.mint_mode);
    Ok(())
}

/// Run the daemon until SIGINT/SIGTERM.
pub async fn run(s: &Settings) -> Result<()> {
    let key = s.load_key()?;
    let ctx = connect(s, key, Arc::new(CoreAttributor)).await?;
    startup_checks(&ctx).await?;
    let listener = tokio::net::TcpListener::bind(s.listen)
        .await
        .with_context(|| format!("api listen {}", s.listen))?;
    info!(event = "api_listening", addr = %s.listen);
    let app = crate::api::router(ctx.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
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
