//! The one-shot commands: `enroll`, `status`, `lock`, `burn`, `rogue-unlock`, `recover`.
//! Each prints one JSON document on stdout (logs go to stderr).

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use hawkeye_core::address::decode_address;
use hawkeye_core::lock::{destination_script, lock_id};
use hawkeye_core::template::{TAG_WYEC, VaultParams};
use hawkeye_core::{EthAddress, OutPoint as CoreOutPoint};
use hawkeye_eth::{B256, EthClient, EthConfig, U256};
use hawkeye_store::{SignDomain, Store, YcashSignKey};
use hawkeye_ycash::tx::{Transaction, TxIn, TxOut};
use hawkeye_ycash::types::{Recipient, TemplateKind, VaultListFilter};
use hawkeye_ycash::{Amount, HexBytes, YcashRpc};
use serde_json::json;
use tracing::info;

use crate::attribution::CoreAttributor;
use crate::config::Settings;
use crate::convert::op_core;
use crate::engine::{Engine, block_on};
use crate::keys::{eth_signer, key_info, parse_secret, wif};

/// The flat fee of a hand-built lock transaction (the node's vault RPCs use the same).
pub const LOCK_FEE: i64 = 10_000;

fn ycash(s: &Settings) -> Result<YcashRpc> {
    Ok(YcashRpc::new(s.ycash_url.clone(), s.ycash_auth.clone())?)
}

fn zat(text: &str) -> Result<i64> {
    let a = Amount::parse_decimal(text).map_err(|e| anyhow!("amount: {e}"))?;
    ensure!(a.zat() > 0, "amount must be positive");
    Ok(a.zat())
}

fn print(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

/// `hawkeye enroll`: import the member key into the node wallet without a rescan (plan §3.5).
pub async fn enroll(s: &Settings) -> Result<()> {
    let key = s.load_key()?;
    let node = ycash(s)?;
    let address = node
        .importprivkey(&wif(&key, s.network), "hawkeye", false)
        .await
        .context("importprivkey")?;
    info!(event = "enrolled", address = %address, member = %hex::encode(key.public_key()));
    print(&serde_json::to_value(key_info(&key))?)
}

/// `hawkeye status [--json]`.
pub async fn status(s: &Settings, as_json: bool) -> Result<()> {
    let key = s.load_key()?;
    let ctx = crate::daemon::connect(s, key, Arc::new(CoreAttributor)).await?;
    let mut engine = Engine::new(ctx);
    let st = engine.snapshot().await?;
    if as_json {
        return print(&serde_json::to_value(&st)?);
    }
    println!(
        "hawkeye {} on {} — set {}",
        st.version, st.network, st.set_id
    );
    println!("member {}  eth {}", st.member_key, st.eth_address);
    println!(
        "ycash tip {} cursor {} (lag {}); ethereum finalized {} cursor {} (lag {})",
        st.ycash.tip,
        st.ycash.cursor,
        st.ycash.lag,
        st.ethereum.tip,
        st.ethereum.cursor,
        st.ethereum.lag
    );
    println!("live members {}", st.live_members);
    for (name, m) in [
        ("locks", &st.locks),
        ("burns", &st.burns),
        ("intents", &st.intents),
        ("vaults", &st.vaults),
        ("slash cases", &st.slash_cases),
    ] {
        let parts: Vec<String> = m
            .iter()
            .filter(|(_, v)| **v > 0)
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        println!(
            "{name}: {}",
            if parts.is_empty() {
                "-".into()
            } else {
                parts.join(", ")
            }
        );
    }
    println!(
        "supply: wYEC {} vs locked {} → {}",
        st.supply.wyec_total_supply,
        st.supply.locked_vault_value,
        if st.supply.ok { "ok" } else { "BREACH" }
    );
    for a in &st.alarms {
        println!("ALARM {}: {}", a.name, a.detail);
    }
    Ok(())
}

/// `hawkeye lock`: the depositor's lock (plan §1.2): a `WYEC` V of the configured set plus the
/// destination `OP_RETURN`, funded and signed by this node's wallet.
pub async fn lock(s: &Settings, amount: &str, dest: &str, owner_age: Option<u32>) -> Result<()> {
    let p = &s.params;
    let to = EthAddress::parse(dest).map_err(|e| anyhow!("--dest: {e}"))?;
    ensure!(to != EthAddress::ZERO, "--dest is the zero address");
    let value = zat(amount)?;
    let node = ycash(s)?;
    let tip = node.getblockcount().await?;
    let age = owner_age.unwrap_or(p.min_owner_age + p.roll_margin + 10);
    let owner_address = node.getnewaddress().await?;
    let owner_key = node
        .validateaddress(&owner_address)
        .await?
        .pubkey
        .ok_or_else(|| anyhow!("validateaddress gave no pubkey"))?;
    let owner_key: [u8; 33] = owner_key
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("owner key is not compressed"))?;
    let v = VaultParams {
        tag: TAG_WYEC,
        set_id: p.set_id,
        cancel_set_id: p.set_id,
        delay: p.delay,
        owner_height: tip + 1 + age,
        app_height: 0,
        owner_key,
    };
    let script = v.script().map_err(|e| anyhow!("vault: {e}"))?;
    // coins: confirmed, spendable, not spent by a mempool transaction
    let mut busy = std::collections::HashSet::new();
    for t in node.getrawmempool().await? {
        if let Ok(raw) = node.getrawtransaction(&t).await
            && let Ok(tx) = Transaction::decode(raw.as_slice())
        {
            busy.extend(tx.inputs.iter().map(|i| i.prevout));
        }
    }
    let mut coins: Vec<_> = node
        .listunspent(Some(1), None, None)
        .await?
        .into_iter()
        .filter(|u| u.spendable && !busy.contains(&hawkeye_ycash::OutPoint::new(u.txid, u.vout)))
        .collect();
    coins.sort_by_key(|u| std::cmp::Reverse(u.amount_zat));
    let mut inputs = vec![];
    let mut total = 0i64;
    for u in coins {
        inputs.push(TxIn {
            prevout: hawkeye_ycash::OutPoint::new(u.txid, u.vout),
            script_sig: vec![],
            sequence: u32::MAX,
        });
        total += u.amount_zat;
        if total >= value + LOCK_FEE {
            break;
        }
    }
    if total < value + LOCK_FEE {
        bail!(
            "the wallet holds {total} zat in usable coins; the lock needs {}",
            value + LOCK_FEE
        );
    }
    let change_address = node.getnewaddress().await?;
    let change = node
        .validateaddress(&change_address)
        .await?
        .script_pub_key
        .ok_or_else(|| anyhow!("validateaddress gave no scriptPubKey"))?;
    let mut outputs = vec![
        TxOut {
            value,
            script_pubkey: script,
        },
        TxOut {
            value: 0,
            script_pubkey: destination_script(&to),
        },
    ];
    if total - value - LOCK_FEE > 0 {
        outputs.push(TxOut {
            value: total - value - LOCK_FEE,
            script_pubkey: change.0,
        });
    }
    let tx = Transaction::new_v4(inputs, outputs, 0, tip + 40);
    let signed = node
        .signrawtransaction(&HexBytes(tx.encode()), None, None, None, None)
        .await?;
    ensure!(
        signed.complete,
        "signrawtransaction incomplete: {:?}",
        signed.errors
    );
    let txid = node.sendrawtransaction(&signed.hex, false).await?;
    let id = lock_id(&CoreOutPoint::new(txid.0, 0));
    info!(event = "lock_sent", txid = %txid, value, to = %to.to_checksum(),
          owner_height = v.owner_height, lockid = %format!("0x{}", hex::encode(id)));
    print(&json!({
        "txid": txid.to_string(),
        "vout": 0,
        "lockid": format!("0x{}", hex::encode(id)),
        "owner_height": v.owner_height,
        "to": to.to_checksum(),
        "amount_zat": value,
    }))
}

/// `hawkeye burn`: `WyecBridge.burn(amount, ycashRecipient)` with the §4.2 encoding, from
/// `--eth-key` (default: the config's `[keys] secret_hex`).
pub async fn burn(
    s: &Settings,
    amount: &str,
    recipient: &str,
    eth_key: Option<&str>,
) -> Result<()> {
    let r = decode_address(recipient, s.network).map_err(|e| anyhow!("--recipient: {e}"))?;
    let value = zat(amount)?;
    let key = match eth_key {
        Some(k) => parse_secret(k)?,
        None => s.load_key().context("no --eth-key and no [keys] key")?,
    };
    let mut ec = EthConfig::new(
        s.eth_url.clone(),
        s.deployment.chain_id,
        s.deployment.bridge,
    );
    ec.token = Some(s.deployment.token);
    let eth = EthClient::connect(&ec, Some(eth_signer(&key)?))
        .await
        .map_err(|e| anyhow!("ethereum: {e}"))?;
    let b = eth
        .burn(U256::from(value as u64), B256::from(r.to_bytes32()))
        .await
        .map_err(|e| anyhow!("burn: {e}"))?;
    info!(event = "burn_sent", tx = %b.mined.tx, nonce = %b.nonce, amount = value, recipient);
    print(&json!({
        "txhash": b.mined.tx.to_string(),
        "nonce": u64::try_from(b.nonce).unwrap_or(u64::MAX),
        "block": b.mined.block_number,
    }))
}

/// `hawkeye rogue-unlock` (drill D-2 only): this attestor signs an unlock with no burn and no
/// memo behind it.
pub async fn rogue_unlock(s: &Settings, amount: &str, to: Option<&str>) -> Result<()> {
    ensure!(
        s.params.drills && !s.params.mainnet,
        "rogue-unlock is a drill: needs [devnet] drills = true, never on mainnet"
    );
    let value = zat(amount)?;
    let node = Arc::new(ycash(s)?);
    let to = match to {
        Some(t) => t.to_owned(),
        None => node.getnewaddress().await?,
    };
    let to = to.as_str();
    let rows = node
        .vault_list(Some(&VaultListFilter {
            tag: Some("WYEC".into()),
            setid: Some(s.params.set_hash()),
            kind: Some(TemplateKind::Vault),
            ..VaultListFilter::default()
        }))
        .await?;
    let mut store = Store::open(&s.store_path)?;
    let mut chosen = None;
    for r in rows.iter().filter_map(|r| r.as_vault()) {
        if r.valuezat < value {
            continue;
        }
        let key = YcashSignKey {
            domain: SignDomain::YcashUnlock,
            set_id: s.params.set_id,
            prevout: op_core(&r.outpoint),
        };
        if store.tx(|t| t.ycash_signature(&key))?.is_none() {
            chosen = Some((r.outpoint, key));
            break;
        }
    }
    let (vault, key) = chosen.ok_or_else(|| anyhow!("no unsigned WYEC vault holds {value} zat"))?;
    let built = node
        .vault_buildunlock(&vault, &[Recipient::address(to, Amount::from_zat(value))])
        .await?;
    let vout = built.intents.first().map_or(0, |i| i.vout);
    let n2 = node.clone();
    let rec = store.sign_once_ycash(&key, &built.hex.to_string(), |h| {
        let hex: HexBytes = h.parse().map_err(|e| format!("{e}"))?;
        let r = block_on(n2.set_signunlock(&hex)).map_err(|e| e.to_string())?;
        Ok::<_, String>((r.hex.to_string(), r.sighash.0))
    })?;
    let txid = node.vault_send(&rec.signed_hex.parse()?).await?;
    info!(event = "rogue_unlock_sent", txid = %txid, vault = %vault, amount = value, to);
    print(
        &json!({"txid": txid.to_string(), "intent": format!("{txid}:{vout}"), "vault": vault.to_string()}),
    )
}

/// `hawkeye recover`: `vault_ownerspend` of every `WYEC` vault and intent of the set this
/// wallet owns (selector 2 after `ownerHeight`, 3 once the set is released).
pub async fn recover(s: &Settings) -> Result<()> {
    let node = ycash(s)?;
    let rows = node
        .vault_list(Some(&VaultListFilter {
            tag: Some("WYEC".into()),
            setid: Some(s.params.set_hash()),
            mine: Some(true),
            ..VaultListFilter::default()
        }))
        .await?;
    let mut out = vec![];
    for r in rows {
        let op = r.outpoint();
        let address = node.getnewaddress().await?;
        match node.vault_ownerspend(&op, &address).await {
            Ok(res) => {
                info!(event = "recovered", outpoint = %op, txid = %res.txid, selector = res.selector);
                out.push(
                    json!({"outpoint": op.to_string(), "txid": res.txid.to_string(),
                                "selector": res.selector, "value_zat": r.valuezat()}),
                );
            }
            Err(e) => out.push(json!({"outpoint": op.to_string(), "error": e.to_string()})),
        }
    }
    print(&json!({"recovered": out}))
}
