//! The one-shot commands: `enroll`, `status`, `lock`, `burn`, `rogue-unlock`, `rogue-mint`,
//! `recover`, `leave`, `withdraw-bond`, `split-coins`.
//! Each prints one JSON document on stdout (logs go to stderr).

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use hawkeye_core::address::{decode_address, decode_pq_address, encode_pq_address};
use hawkeye_core::lock::lock_id;
use hawkeye_core::pq::{PqKeyId, SCHEME_SLH_DSA_SHA2_128S};
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_core::template::VaultParams;
use hawkeye_core::{
    AccountId, BridgeKind, Destination, EthAddress, Guardian, OutPoint as CoreOutPoint,
};
use hawkeye_store::{SignDomain, SlashDecision, SlashState, Store, YcashSignKey};
use hawkeye_ycash::tx::{Transaction, TxIn, TxOut};
use hawkeye_ycash::types::{MemberStatus, Recipient, TemplateKind, VaultListFilter};
use hawkeye_ycash::{Amount, HexBytes, YcashRpc};
use serde_json::json;
use tracing::{info, warn};

use crate::attribution::CoreAttributor;
use crate::config::Settings;
use crate::convert::op_core;
use crate::engine::Engine;
use crate::foreign::{self, Account};
use crate::keys::{key_info, parse_secret, wif};

/// The flat fee of a hand-built lock transaction (the node's vault RPCs use the same); raised to
/// the transaction's ZIP-317 conventional fee when that is higher (audit 04/N-1).
pub const LOCK_FEE: i64 = 10_000;

/// The flat fee of the bond withdrawal (one P2SH input, one output: about 250 bytes).
pub const BOND_WITHDRAW_FEE: i64 = 10_000;

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

/// `hawkeye enroll`: import the member key into the node wallet without a rescan (plan §3.5),
/// in `[keys] ycash_signing = "wallet"` mode — the wallet then holds it **in clear** (Ycash's
/// wallet encryption is disabled; README "Key custody"). In `"self"` mode (05/M-1) nothing is
/// imported: the key's forms are printed and the wallet only funds fees.
pub async fn enroll(s: &Settings) -> Result<()> {
    let key = s.load_key()?;
    if s.params.ycash_signing == crate::config::YcashSigning::SelfSigned {
        info!(event = "enrolled_self_signing", member = %hex::encode(key.public_key()),
              "ycash_signing = \"self\": the member key is not imported into the node wallet; \
               fund the wallet's own address for fees");
        return print(&serde_json::to_value(key_info(&key))?);
    }
    let node = ycash(s)?;
    let address = node
        .importprivkey(&wif(&key, s.network), "hawkeye", false)
        .await
        .context("importprivkey")?;
    info!(event = "enrolled", address = %address, member = %hex::encode(key.public_key()));
    print(&serde_json::to_value(key_info(&key))?)
}

/// `hawkeye acknowledge-restore` (07/F-5, `"wallet"` mode): the node wallet carries a restore
/// marker once the member key was imported and joined (or the wallet was restored from a seed),
/// and refuses every set signature (`set-sign-restored`) until its sign-once history is imported
/// and acknowledged. This ledger is that history for the bridge: the audit must pass (no unlock by
/// this member on the chain or in the mempool without a record here), then its unlock and cancel
/// records go to `set_importsigned` (a conflicting node record refuses the whole import:
/// `set-sign-once`) and `set_acknowledgerestore` clears the marker. Never run by the daemon.
/// `hawkeye acknowledge-ledger-restore` (review L-2): clear `meta.ledger_restored` and reset the
/// ledger's high-water mark to its current record count. The operator's statement that the
/// restored ledger lacks no unlock this member signed and might still be revived.
pub fn acknowledge_ledger_restore(s: &Settings) -> Result<()> {
    let mut store = Store::open(&s.store_path)?;
    let (was, count) = store.tx(|t| {
        let was = t.meta(crate::engine::burn::LEDGER_RESTORED)?;
        t.set_meta(crate::engine::burn::LEDGER_RESTORED, "acknowledged")?;
        Ok::<_, hawkeye_store::StoreError>((was, t.ycash_signature_count()?))
    })?;
    crate::restore::reset_hwm(&crate::restore::hwm_path(&s.store_path), count)?;
    info!(event = "ledger_restore_acknowledged", previous = ?was, records = count);
    print(&json!({"previous": was, "records": count}))
}

/// `hawkeye declare-leader-gone <member> [--reason]` (the owner's override, 2026-10-13): sign
/// the declaration, record it in this ledger through the same checks a peer's goes through, and
/// send it to every peer. Prints how many declarations each ledger now holds against the quorum.
pub async fn declare_leader_gone(
    s: &Settings,
    member: &str,
    reason: &str,
    expires_in: Option<u32>,
) -> Result<()> {
    let key = s.load_key()?;
    let ctx = crate::daemon::connect(s, key.clone(), Arc::new(CoreAttributor)).await?;
    let mut mk = [0u8; 33];
    hex::decode_to_slice(member.trim_start_matches("0x"), &mut mk)
        .map_err(|_| anyhow!("member must be 66 hex"))?;
    let set = ctx.ycash.set_getinfo(&ctx.set_hash(), None).await?;
    let seq = set
        .memberlist
        .iter()
        .find(|m| m.key.0 == mk)
        .map(|m| m.joinheight)
        .ok_or_else(|| anyhow!("{member} is not in the set's member list"))?;
    let tip = ctx.ycash.getblockcount().await?;
    let expiry = tip.saturating_add(expires_in.unwrap_or(2 * s.params.takeover.max(1)));
    let sig = hawkeye_core::peerauth::sign(
        &key,
        &hawkeye_core::peerauth::gone_msg(&s.params.set_id, &mk, seq, expiry),
    )
    .map_err(|e| anyhow!("{e}"))?;
    let decl = crate::peers::GoneDeclaration {
        member: hex::encode(mk),
        declarer: hex::encode(key.public_key()),
        seq,
        expiry,
        sig: hex::encode(sig),
        reason: reason.to_owned(),
    };
    let here = crate::engine::burn::record_gone(&ctx, None, &decl).await?;
    let mut peers = vec![];
    for peer in ctx.peers.urls().to_vec() {
        match ctx.peers.declare_gone(&peer, &decl).await {
            Ok(a) => peers.push(json!({"peer": peer, "declarations": a.body.declarations,
                                        "quorum": a.body.quorum})),
            Err(e) => peers.push(json!({"peer": peer, "error": format!("{e:#}")})),
        }
    }
    warn!(event = "declare_leader_gone", member = %decl.member, reason, declarations = here.declarations,
          quorum = here.quorum);
    print(
        &json!({"member": decl.member, "here": {"declarations": here.declarations,
                  "quorum": here.quorum}, "peers": peers}),
    )
}

pub async fn acknowledge_restore(s: &Settings) -> Result<()> {
    if s.params.ycash_signing == crate::config::YcashSigning::SelfSigned {
        return print(&json!({"restored": false, "note":
            "ycash_signing = \"self\": the node wallet holds no member key; nothing to acknowledge"}));
    }
    let node = ycash(s)?;
    let before = node.set_listsigned().await.context("set_listsigned")?;
    if !before.restored {
        return print(&json!({"restored": false, "records": before.records.len()}));
    }
    let key = s.load_key()?;
    if !s.store_path.exists() {
        // before the first `hawkeye run`: an empty ledger, as `run` would create it (the audit
        // still checks the chain for unlocks signed by this member)
        drop(
            Store::open(&s.store_path)
                .with_context(|| format!("ledger {}", s.store_path.display()))?,
        );
    }
    let mut store = Store::open_readonly(&s.store_path)
        .with_context(|| format!("ledger {}", s.store_path.display()))?;
    let audit = crate::audit::audit_ledger(
        &mut store,
        &node,
        &CoreAttributor,
        &s.params,
        &key.public_key(),
    )
    .await?;
    if !audit.ok {
        return Err(crate::audit::refuse(&audit));
    }
    let recs = store.read(|t| t.ycash_signatures(&s.params.set_id))?;
    let records: Vec<hawkeye_ycash::types::SignedRecord> = recs
        .iter()
        .filter_map(|r| {
            let role = match r.key.domain {
                SignDomain::YcashUnlock => 1,
                SignDomain::YcashCancel => 2,
                _ => return None,
            };
            Some(hawkeye_ycash::types::SignedRecord {
                setid: hawkeye_ycash::Hash256::from_internal(r.key.set_id),
                prevout: hawkeye_ycash::OutPoint::new(
                    hawkeye_ycash::Hash256::from_internal(r.key.prevout.txid),
                    r.key.prevout.vout,
                ),
                role,
                sighash: hawkeye_ycash::Bytes32(r.sighash),
            })
        })
        .collect();
    let imported = if records.is_empty() {
        None
    } else {
        Some(
            node.set_importsigned(&records)
                .await
                .context("set_importsigned")?,
        )
    };
    let after = node
        .set_acknowledgerestore()
        .await
        .context("set_acknowledgerestore")?;
    info!(
        event = "restore_acknowledged",
        records = records.len(),
        pending_keys = after.pendingkeys,
        restored = after.restored
    );
    print(&json!({
        "restored": after.restored,
        "pendingkeys": after.pendingkeys,
        "ledger_records": records.len(),
        "imported": imported.as_ref().map(|i| i.imported),
        "present": imported.as_ref().map(|i| i.present),
    }))
}

/// `hawkeye audit-ledger [--json]` (docs/operations.md §5): the ledger, opened read-only and
/// not migrated, against the node. Fails (non-zero exit) when a record is missing.
pub async fn audit_ledger(s: &Settings, as_json: bool) -> Result<()> {
    let key = s.load_key()?;
    let mut store = Store::open_readonly(&s.store_path)
        .with_context(|| format!("ledger {}", s.store_path.display()))?;
    let r = crate::audit::audit_ledger(
        &mut store,
        &ycash(s)?,
        &CoreAttributor,
        &s.params,
        &key.public_key(),
    )
    .await?;
    if as_json {
        print(&serde_json::to_value(&r)?)?;
    } else {
        println!(
            "ledger schema v{}, cursor {}, node tip {}",
            r.schema,
            r.ledger_cursor
                .map_or_else(|| "-".to_owned(), |c| c.to_string()),
            r.node_tip
        );
        for rec in &r.records {
            println!(
                "{} {} {}",
                rec.domain,
                rec.prevout,
                if rec.unspent {
                    "live (unspent)"
                } else {
                    "spent"
                }
            );
        }
        for m in &r.missing {
            println!(
                "MISSING {}: signed on {} by this member (unlock {}), no record here",
                m.vault, m.seen, m.txid
            );
        }
        println!("{}", r.verdict());
    }
    if r.ok {
        Ok(())
    } else {
        Err(crate::audit::refuse(&r))
    }
}

/// `hawkeye status [--json]`.
/// `hawkeye status --params` (audit 05/M-4): the effective parameters, the set's live ones and the
/// contract's, each against its mainnet floor. The floors are enforced on mainnet only (refused at
/// start-up), a quarter of them warned on testnet; on regtest they are shown for information.
pub async fn status_params(s: &Settings, as_json: bool) -> Result<()> {
    use crate::floors::{Row, TESTNET_DIVISOR, live_rows, static_rows};
    let key = s.load_key()?;
    let ctx = crate::daemon::connect(s, key, Arc::new(CoreAttributor)).await?;
    let p = &ctx.params;
    let divisor = if s.network_name == "testnet" {
        TESTNET_DIVISOR
    } else {
        1
    };
    let config = static_rows(p, divisor);
    let set = ctx
        .ycash
        .set_getinfo(&ctx.set_hash(), None)
        .await
        .context("set_getinfo")?;
    let locked = u64::try_from(set.set.lockedvalue.0).unwrap_or(0);
    let live = live_rows(p, &set.set.params, locked);
    let (other, total) = crate::daemon::vault_delay_mismatch(&ctx).await?;
    // the contract's values, read without the mainnet refusal, then held to its floors
    let b = ctx
        .foreign
        .check_bridge(false)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let chain = hawkeye_eth::mode::MAINNET;
    let contract = vec![
        Row {
            param: "contract.threshold",
            value: b.threshold.into(),
            rule: ">= 2 (MAINNET_MIN_THRESHOLD)".into(),
            ok: hawkeye_eth::mode::check_contract_threshold(chain, b.threshold).is_ok(),
            why: "plan §3.3: at 1 one key skips the challenge window",
        },
        Row {
            param: "contract.challengeWindow",
            value: b.challenge_window,
            rule: format!(
                ">= {} s (MAINNET_MIN_CHALLENGE_WINDOW_SECS)",
                hawkeye_eth::mode::MAINNET_MIN_CHALLENGE_WINDOW_SECS
            ),
            ok: hawkeye_eth::mode::check_challenge_window(chain, b.challenge_window).is_ok(),
            why: "audit 05/H-2: detection, Ethereum finality included, fits in the window",
        },
        Row {
            param: "contract.mintCap",
            value: u64::try_from(b.mint_cap).unwrap_or(u64::MAX),
            rule: "> 0 (a bounded mint rate)".into(),
            ok: hawkeye_eth::mode::check_mint_cap(chain, b.mint_cap).is_ok(),
            why: "audit 05/H-2: what an unchallenged proposal can mint",
        },
    ];
    let set_params = &set.set.params;
    if as_json {
        return print(&json!({
            "network": s.network_name,
            "enforced": s.network_name == "mainnet",
            "config": config,
            "set": {
                "livenesswindow": set_params.livenesswindow,
                "ratelimitbps": set_params.ratelimitbps,
                "ratewindow": set_params.ratewindow,
                "maturity": set_params.maturity,
                "lockedvalue": locked,
                "rows": live,
                "vaults_with_other_delay": other,
                "vaults": total,
            },
            "contract": {
                "threshold": b.threshold,
                "challengeWindow": b.challenge_window,
                "mintCap": b.mint_cap.to_string(),
                "capWindow": b.cap_window.to_string(),
                "rows": contract,
            },
        }));
    }
    println!(
        "parameters on {} ({}); floors: crates/hawkeye/src/floors.rs, hawkeye-eth mode.rs",
        s.network_name,
        match s.network_name.as_str() {
            "mainnet" => "enforced: below a floor refuses to start",
            "testnet" => "a quarter of the floors, warned",
            _ => "not enforced, shown for information",
        }
    );
    let show = |title: &str, rows: &[Row]| {
        println!("{title}");
        for r in rows {
            println!(
                "  {:<26} {:>12}  {:<11} {}",
                r.param,
                r.value,
                if r.ok { "OK" } else { "BELOW FLOOR" },
                r.rule
            );
        }
    };
    show("config:", &config);
    println!(
        "set: livenesswindow {}, ratelimitbps {} per {}, maturity {}, locked {locked} zat; {other} of {total} vaults with another delay",
        set_params.livenesswindow,
        set_params.ratelimitbps,
        set_params.ratewindow,
        set_params.maturity
    );
    show("  against the set:", &live);
    println!(
        "contract: threshold {}, challengeWindow {} s, mintCap {} per {} s",
        b.threshold, b.challenge_window, b.mint_cap, b.cap_window
    );
    show("  against the mainnet rules:", &contract);
    Ok(())
}

/// `hawkeye exposure list` (audit 05/L-5).
pub fn exposure_list(s: &Settings) -> Result<()> {
    let mut store = Store::open(&s.store_path)?;
    let rows = store.tx(|t| t.unacked_exposures())?;
    let v: Vec<serde_json::Value> = rows
        .iter()
        .map(|l| {
            json!({
                "lock_id": format!("0x{}", hex::encode(l.lock_id)),
                "state": l.state.to_string(),
                "amount": l.value_zat,
                "to": l.destination.as_ref().map(ToString::to_string),
                "block_height": l.block_height,
            })
        })
        .collect();
    print(&serde_json::Value::Array(v))
}

/// `hawkeye exposure ack <lockId> --note …` (audit 05/L-5).
pub fn exposure_ack(s: &Settings, lock_id: &str, note: &str) -> Result<()> {
    ensure!(
        !note.trim().is_empty(),
        "--note: say what was done about the exposure"
    );
    let id: [u8; 32] = hex::decode(lock_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("lockId {lock_id:?}: 32 bytes of hex"))?;
    let mut store = Store::open(&s.store_path)?;
    let new = store.tx(|t| t.ack_exposure(&id, note))?;
    print(&json!({ "lock_id": format!("0x{}", hex::encode(id)), "acknowledged": true, "new": new }))
}

/// `hawkeye slash list` (audit W3-B-2).
pub fn slash_list(s: &Settings) -> Result<()> {
    let mut store = Store::open(&s.store_path)?;
    let rows = store.tx(|t| {
        let mut out = vec![];
        for st in [SlashState::Opened, SlashState::Voted, SlashState::Submitted] {
            for c in t.slash_cases_in_state(st)? {
                let d = t.slash_decision(c.id)?;
                out.push(json!({
                    "id": c.id,
                    "fault": c.fault.to_string(),
                    "target": hex::encode(c.target_key),
                    "state": c.state.to_string(),
                    "opened_height": c.opened_height,
                    "decision": d.map(SlashDecision::as_str),
                }));
            }
        }
        Ok::<_, hawkeye_store::StoreError>(out)
    })?;
    print(&serde_json::Value::Array(rows))
}

/// `hawkeye slash approve|reject <id> --note …` (audit W3-B-2).
pub fn slash_decide(s: &Settings, id: i64, decision: SlashDecision, note: &str) -> Result<()> {
    ensure!(
        !note.trim().is_empty(),
        "--note: say why this case is {}d",
        decision.as_str()
    );
    let mut store = Store::open(&s.store_path)?;
    store.tx(|t| t.decide_slash(id, decision, note))?;
    warn!(
        event = "slash_decided",
        case = id,
        decision = decision.as_str(),
        note
    );
    print(
        &json!({ "case": id, "decision": decision.as_str(), "note": "the daemon acts on it at its next tick" }),
    )
}

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
    println!(
        "member {}  {} guardian {}",
        st.member_key, st.foreign_kind, st.guardian
    );
    println!(
        "ycash tip {} cursor {} (lag {}); {} final {} cursor {} (lag {})",
        st.ycash.tip,
        st.ycash.cursor,
        st.ycash.lag,
        st.foreign_kind,
        st.foreign.tip,
        st.foreign.cursor,
        st.foreign.lag
    );
    println!("live members {}", st.live_members);
    if let (Some(who), Some(bal)) = (&st.sender, &st.sender_balance) {
        println!("{} sender {who} balance {bal}", st.foreign_kind);
    }
    if let Some(n) = st.fee_coins {
        println!("fee coins {n}");
    }
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
    if st.burns_over_cap > 0 {
        println!(
            "burns over cap: {} (WAITING_CAP, reason over-cap: they wait for the set's cap to rise)",
            st.burns_over_cap
        );
    }
    println!(
        "supply: wYEC {} vs locked {} → {}",
        st.supply.wyec_total_supply,
        st.supply.locked_vault_value,
        if st.supply.ok { "ok" } else { "BREACH" }
    );
    if st.pinned_vaults.is_empty() {
        println!("pinned vaults: -");
    } else {
        println!("pinned vaults: {}", st.pinned_vaults.len());
        for v in &st.pinned_vaults {
            println!(
                "  {} burn {} ownerHeight {} ({} blocks left)",
                v.vault, v.burn, v.owner_height, v.blocks_left
            );
        }
    }
    for a in &st.alarms {
        println!("ALARM {}: {}", a.name, a.detail);
    }
    Ok(())
}

/// A `--dest` for a lock of the `kind` bridge: an Ethereum address (`0x` + 40 hex, EIP-55
/// checked when mixed case, not zero) for Ethereum, a NEAR account id for NEAR (NEAR plan §2.1;
/// a lowercase `0x` + 40 hex is NEAR's EVM-implicit account there). A destination of the other
/// chain is refused by name.
pub fn parse_destination(kind: BridgeKind, text: &str) -> Result<Destination> {
    let eth = EthAddress::parse(text);
    let near = AccountId::parse(text);
    match kind {
        BridgeKind::Ethereum => match (eth, near) {
            (Ok(a), _) => {
                ensure!(a != EthAddress::ZERO, "--dest is the zero address");
                Ok(Destination::Ethereum(a))
            }
            (Err(_), Ok(n)) => bail!(
                "--dest {n} is a NEAR account id; this Hawkeye's bridge is on Ethereum ([foreign] kind)"
            ),
            (Err(e), Err(_)) => bail!("--dest: {e}"),
        },
        BridgeKind::Near => match (near, eth) {
            (Ok(n), _) => Ok(Destination::Near(n)),
            (Err(_), Ok(a)) => bail!(
                "--dest {a} is an Ethereum address; this Hawkeye's bridge is on NEAR ([foreign] kind)"
            ),
            (Err(e), Err(_)) => bail!("--dest: {e}"),
        },
    }
}

/// `--owner`: a post-quantum address of the configured network (53 characters) or a `pqkeyid`
/// (66 hex digits). The bridge's lock policy mints for SLH-DSA (scheme 1) owners only.
pub fn parse_owner(text: &str, network: hawkeye_core::address::Network) -> Result<PqKeyId> {
    let owner = if text.len() == 66 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        PqKeyId::from_hex(text).map_err(|e| anyhow!("--owner: {e}"))?
    } else {
        decode_pq_address(text, network).map_err(|e| anyhow!("--owner: {e}"))?
    };
    ensure!(
        owner.scheme == SCHEME_SLH_DSA_SHA2_128S,
        "--owner: scheme {} is not SLH-DSA-SHA2-128s (1); the lock policy would refuse the vault",
        owner.scheme
    );
    Ok(owner)
}

/// `hawkeye lock`: the depositor's lock (plan §1.2): a V of the bridge's tag (`WYEC` or `NYEC`)
/// and the configured set plus the destination `OP_RETURN` (an Ethereum address, or `"NR1"` ‖ a
/// NEAR account id), funded and signed by this node's wallet. The owner is post-quantum:
/// `--owner` (an address or `pqkeyid`, possibly another wallet's), else a new SLH-DSA key of
/// this node's wallet from `vault_getnewowner`, which then also signs `hawkeye recover`.
pub async fn lock(
    s: &Settings,
    amount: &str,
    dest: &str,
    owner_age: Option<u32>,
    owner: Option<&str>,
) -> Result<()> {
    let p = &s.params;
    let to = parse_destination(p.bridge_kind, dest)?;
    let value = zat(amount)?;
    let owner = owner.map(|o| parse_owner(o, s.network)).transpose()?;
    let node = ycash(s)?;
    let tip = node.getblockcount().await?;
    let age = owner_age.unwrap_or(p.min_owner_age + p.roll_margin + 10);
    let owner = match owner {
        Some(o) => o,
        None => {
            let n = node
                .vault_getnewowner(Some(SCHEME_SLH_DSA_SHA2_128S))
                .await
                .context("vault_getnewowner")?;
            ensure!(
                n.scheme == SCHEME_SLH_DSA_SHA2_128S
                    && n.owner.scheme() == n.scheme
                    && n.keyhash.as_slice() == n.owner.hash(),
                "vault_getnewowner: inconsistent owner {n:?}"
            );
            let o = PqKeyId::from_bytes(&n.owner.0).map_err(|e| anyhow!("owner: {e}"))?;
            ensure!(
                encode_pq_address(&o, s.network) == n.address,
                "vault_getnewowner: address {} is not the owner's on this network",
                n.address
            );
            o
        }
    };
    let v = VaultParams {
        tag: p.tag(),
        set_id: p.set_id,
        cancel_set_id: p.set_id,
        delay: p.delay,
        owner_height: tip + 1 + age,
        app_height: 0,
        owner,
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
    let change_address = node.getnewaddress().await?;
    let change = node
        .validateaddress(&change_address)
        .await?
        .script_pub_key
        .ok_or_else(|| anyhow!("validateaddress gave no scriptPubKey"))?;
    // the fee: LOCK_FEE, raised to the signed transaction's ZIP-317 conventional fee when that is
    // higher (a post-quantum coin's scriptSig is ~8 KB: 26,500 zat; audit 04/N-1), re-selecting
    // and re-signing until it covers it
    let mut fee = LOCK_FEE;
    let mut signed = None;
    for _ in 0..4 {
        let mut inputs = vec![];
        let mut total = 0i64;
        for u in &coins {
            inputs.push(TxIn {
                prevout: hawkeye_ycash::OutPoint::new(u.txid, u.vout),
                script_sig: vec![],
                sequence: u32::MAX,
            });
            total += u.amount_zat;
            if total >= value + fee {
                break;
            }
        }
        if total < value + fee {
            bail!(
                "the wallet holds {total} zat in usable coins; the lock needs {}",
                value + fee
            );
        }
        let mut outputs = vec![
            TxOut {
                value,
                script_pubkey: script.clone(),
            },
            TxOut {
                value: 0,
                script_pubkey: to.script(),
            },
        ];
        if total - value - fee > 0 {
            outputs.push(TxOut {
                value: total - value - fee,
                script_pubkey: change.0.clone(),
            });
        }
        let tx = Transaction::new_v4(inputs, outputs, 0, tip + 40);
        let s = node
            .signrawtransaction(&HexBytes(tx.encode()), None, None, None, None)
            .await?;
        ensure!(s.complete, "signrawtransaction incomplete: {:?}", s.errors);
        let conventional = Transaction::decode(&s.hex.0)
            .map_err(|e| anyhow!("signed lock: {e}"))?
            .zip317_conventional_fee();
        if conventional <= fee {
            signed = Some(s);
            break;
        }
        fee = conventional;
    }
    let signed = signed.ok_or_else(|| anyhow!("the lock's ZIP-317 fee did not settle"))?;
    let txid = node.sendrawtransaction(&signed.hex, false).await?;
    let id = lock_id(&CoreOutPoint::new(txid.0, 0));
    info!(event = "lock_sent", txid = %txid, value, to = %to,
          owner_height = v.owner_height, owner = %owner, lockid = %format!("0x{}", hex::encode(id)));
    print(&json!({
        "txid": txid.to_string(),
        "vout": 0,
        "lockid": format!("0x{}", hex::encode(id)),
        "owner_height": v.owner_height,
        "owner": owner.to_hex(),
        "owner_address": encode_pq_address(&owner, s.network),
        "to": to.to_string(),
        "amount_zat": value,
    }))
}

/// `hawkeye burn`: the bridge's burn with the §4.2 encoding (revision 2: 22 bytes for a
/// transparent `--recipient`, 35 for a plain-YEC post-quantum one, `sq…`/`tq…`/`rq…`; a PQ
/// *owner* address `yb…`/`yt…`/`yr…` is refused). Ethereum: `WyecBridge.burn(amount,
/// ycashRecipient)` from `--eth-key` (default: the config's `[keys] secret_hex`). NEAR:
/// `wyec-near` `burn(amount, ycash_recipient)` signed by the holder's NEAR credentials file
/// `--near-key` (default: the config's relayer key), attaching the record's storage deposit.
/// A scheme-2 (FN-DSA-512) recipient is sent with a warning: the release pays it only once Falcon
/// is active on Ycash (§4.2).
pub async fn burn(
    s: &Settings,
    amount: &str,
    recipient: &str,
    eth_key: Option<&str>,
    near_key: Option<&std::path::Path>,
    allow_over_cap: bool,
) -> Result<()> {
    let r = decode_address(recipient, s.network).map_err(|e| anyhow!("--recipient: {e}"))?;
    if let Some(w) = recipient_warning(&r) {
        warn!(event = "burn_recipient_warning", recipient, warning = w);
        eprintln!("warning: {w}");
    }
    let value = zat(amount)?;
    if !allow_over_cap {
        // a courtesy for honest holders (05/M-2): a deliberate over-cap burn is harmless anyway
        match ycash(s)?.set_getinfo(&s.params.set_hash(), None).await {
            Ok(info) => over_cap_check(
                u64::try_from(value)?,
                crate::engine::burn::full_window_cap(&info.set),
            )?,
            Err(e) => {
                warn!(event = "burn_cap_unchecked", error = %e);
                eprintln!(
                    "warning: the set's rate limit could not be read ({e}); the burn is sent \
                     unchecked against the per-window cap"
                );
            }
        }
    }
    let chain = match s.foreign {
        BridgeKind::Ethereum => {
            ensure!(near_key.is_none(), "--near-key is for a NEAR bridge");
            let key = match eth_key {
                Some(k) => parse_secret(k)?,
                None => s.load_key().context("no --eth-key and no [keys] key")?,
            };
            foreign::connect_sending_as(s, &key).await?
        }
        BridgeKind::Near => {
            ensure!(
                eth_key.is_none(),
                "--eth-key is for an Ethereum bridge; use --near-key"
            );
            foreign::near::connect_as(s, near_key).await?
        }
    };
    let bytes = r.to_bytes();
    let b = chain
        .burn(u64::try_from(value)?, bytes.clone())
        .await
        .map_err(|e| anyhow!("burn: {e}"))?;
    info!(event = "burn_sent", tx = %b.mined.tx, nonce = %b.nonce, amount = value, recipient,
          kind = r.kind().name(), recipient_hash = %hex::encode(r.recipient_hash()));
    print(&json!({
        "txhash": b.mined.tx.to_string(),
        "nonce": b.nonce,
        "block": b.mined.height,
        "recipient": format!("0x{}", hex::encode(&bytes)),
        "recipient_kind": r.kind().name(),
        "recipienthash": hex::encode(r.recipient_hash()),
    }))
}

/// `hawkeye burn`'s pre-check (audit 05/M-2): refuse a burn of `amount` zat above the set's
/// full-window cap `full` (`None`: no rate limit). Such a burn is not released until the set raises
/// its rate limit; `--allow-over-cap` sends it anyway.
pub fn over_cap_check(amount: u64, full: Option<u64>) -> Result<()> {
    if let Some(cap) = full {
        ensure!(
            amount <= cap,
            "this burn exceeds the attestor set's per-window cap ({} YEC): it would not be \
             released until the set raises its rate limit; pass --allow-over-cap to burn anyway",
            Amount::from_zat(i64::try_from(cap).unwrap_or(i64::MAX))
        );
    }
    Ok(())
}

/// The warning `hawkeye burn` prints for a recipient the contract accepts but the node may not
/// pay yet (§4.2): a `TX_PQPKH` recipient under scheme 2 (FN-DSA-512) is valid only once Falcon
/// is active at the release.
pub fn recipient_warning(r: &YcashRecipient) -> Option<&'static str> {
    match r {
        YcashRecipient::Pqpkh(id) if id.scheme == hawkeye_core::pq::SCHEME_FN_DSA_512 => Some(
            "a scheme-2 (FN-DSA-512) recipient is valid only once Falcon is active on Ycash at \
             the release; before that the node refuses to pay it and the burn waits",
        ),
        _ => None,
    }
}

/// The drill gate: a drill command needs `[devnet] drills = true` and is refused on mainnet.
pub fn drill_gate(p: &crate::config::Params, command: &str) -> Result<()> {
    ensure!(
        p.drills && !p.mainnet,
        "{command} is a drill: needs [devnet] drills = true, never on mainnet"
    );
    Ok(())
}

/// What `rogue-unlock --replay-burn <nonce>` (drill D-3) posts: a second unlock for a burn this
/// attestor's ledger holds, paying the burn's own recipient its own amount (unless overridden),
/// with the burn's valid `HKB1` kind-1 memo — the double release a watcher must cancel and slash
/// outside the takeover window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPlan {
    /// The recipient script (the burn's `ycashRecipient`).
    pub recipient_script: Vec<u8>,
    /// The intent value in zatoshi.
    pub amount: u64,
    /// The 73-byte `HKB1` memo naming the burn.
    pub memo: Vec<u8>,
}

/// The [`ReplayPlan`] for burn `nonce` from the ledger; `amount` overrides the burn's amount.
pub fn replay_plan(
    t: &hawkeye_store::Tx<'_>,
    p: &crate::config::Params,
    nonce: u64,
    amount: Option<u64>,
) -> Result<ReplayPlan> {
    let b = t
        .burn(&hawkeye_store::BurnKey::new(p.deployment, nonce))?
        .ok_or_else(|| anyhow!("burn {nonce} is not in this attestor's ledger"))?;
    ensure!(
        b.state != hawkeye_store::BurnState::Seen,
        "burn {nonce} is not finalized"
    );
    let r = YcashRecipient::from_bytes(&b.recipient)
        .map_err(|e| anyhow!("burn {nonce} recipient: {e}"))?;
    Ok(ReplayPlan {
        recipient_script: r.script(),
        amount: amount.unwrap_or(b.amount),
        memo: hawkeye_core::memo::HawkeyeMemo::burn_release_for(
            p.bridge_kind,
            p.deployment,
            nonce,
            b.tx_hash,
        )
        .encode()
        .to_vec(),
    })
}

/// `hawkeye rogue-unlock` (drills D-2, D-3 only): this attestor signs an unlock with no burn and
/// no memo behind it, or, with `replay_burn`, a second unlock for an already-released burn that
/// carries that burn's valid memo.
pub async fn rogue_unlock(
    s: &Settings,
    amount: Option<&str>,
    to: Option<&str>,
    replay_burn: Option<u64>,
) -> Result<()> {
    drill_gate(&s.params, "rogue-unlock")?;
    let value = amount.map(zat).transpose()?;
    let mut store = Store::open(&s.store_path)?;
    let replay = match replay_burn {
        Some(n) => {
            let over = value.map(u64::try_from).transpose()?;
            Some(store.tx(|t| replay_plan(t, &s.params, n, over))?)
        }
        None => None,
    };
    let value = match (&replay, value) {
        (Some(r), _) => i64::try_from(r.amount)?,
        (None, Some(v)) => v,
        (None, None) => bail!("give the amount: --amount <YEC> (or --replay-burn <nonce>)"),
    };
    let node = Arc::new(ycash(s)?);
    let recipient = match (&replay, to) {
        (_, Some(t)) => Recipient::address(t, Amount::from_zat(value)),
        (Some(r), None) => Recipient::script(r.recipient_script.clone(), Amount::from_zat(value)),
        (None, None) => Recipient::address(&node.getnewaddress().await?, Amount::from_zat(value)),
    };
    let rows = node
        .vault_list(Some(&VaultListFilter {
            tag: Some(s.params.tag_text()),
            setid: Some(s.params.set_hash()),
            kind: Some(TemplateKind::Vault),
            ..VaultListFilter::default()
        }))
        .await?;
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
    let (vault, key) = chosen.ok_or_else(|| {
        anyhow!(
            "no unsigned {} vault holds {value} zat",
            s.params.tag_text()
        )
    })?;
    // no record of this vault in the ledger (checked above): a stale node build may go
    let built =
        crate::engine::sign::build_unlock(&node, &vault, std::slice::from_ref(&recipient), true)
            .await?;
    let vout = built.intents.first().map_or(0, |i| i.vout);
    let unsigned = match &replay {
        Some(r) => hawkeye_ycash::tx::insert_op_return(&built.hex.to_string(), &r.memo)
            .map_err(|e| anyhow!("memo: {e}"))?,
        None => built.hex.to_string(),
    };
    let n2 = node.clone();
    // drill D-3 records its replay per burn as a `drill` row and skips the per-burn check: the
    // double release is the point (the watchers must cancel it)
    let burn = replay_burn.map(|n| hawkeye_store::UnlockBurn {
        key: hawkeye_store::BurnKey::new(s.params.deployment, n),
        origin: hawkeye_store::UnlockOrigin::Drill,
        allow_double: true,
    });
    let member = s.load_key()?;
    let signer = crate::engine::sign::SetSigning::prepare_with(
        &n2,
        &s.params,
        &member,
        hawkeye_core::setsig::Role::Unlock,
        op_core(&vault),
    )
    .await?;
    let rec = store.tx(|t| {
        t.sign_once_unlock(&key, burn.as_ref(), &unsigned, |h| {
            let o = signer.sign(h)?;
            Ok::<_, String>((o.hex, o.sighash))
        })
    })?;
    let txid = node.vault_send(&rec.signed_hex.parse()?).await?;
    info!(event = "rogue_unlock_sent", txid = %txid, vault = %vault, amount = value,
          replay_burn = ?replay_burn);
    print(
        &json!({"txid": txid.to_string(), "intent": format!("{txid}:{vout}"),
                  "vault": vault.to_string(), "replay_burn": replay_burn}),
    )
}

/// The lockId `rogue-mint` invents when none is given: `sha256("hawkeye/rogue-mint/" ‖ signer ‖
/// nanos)`, a value no vault output's `sha256(txid ‖ vout)` will ever collide with in practice.
pub fn invented_lock_id(signer: &EthAddress, nanos: u128) -> [u8; 32] {
    let mut pre = b"hawkeye/rogue-mint/".to_vec();
    pre.extend_from_slice(&signer.0);
    pre.extend_from_slice(&nanos.to_be_bytes());
    hawkeye_core::bytes::sha256(&pre)
}

/// [`invented_lock_id`] of a guardian: an Ethereum guardian's address as there; a NEAR
/// guardian's 64-byte key in its place.
pub fn invented_lock_id_for(signer: &Guardian, nanos: u128) -> [u8; 32] {
    match signer {
        Guardian::Ethereum(a) => invented_lock_id(a, nanos),
        Guardian::Secp256k1(k) => {
            let mut pre = b"hawkeye/rogue-mint/".to_vec();
            pre.extend_from_slice(k);
            pre.extend_from_slice(&nanos.to_be_bytes());
            hawkeye_core::bytes::sha256(&pre)
        }
    }
}

/// `hawkeye rogue-mint` (drill D-5 only): this attestor signs `Mint(lockId, amount, to)` for a
/// lockId with no lock behind it (sign-once, `eip712-drill-mint`, through the bridge's
/// attestation scheme) and opens an optimistic proposal with it (`proposeMint`, gas from its own
/// account) — the fraud the other attestors must challenge within the window and slash on Ycash.
pub async fn rogue_mint(
    s: &Settings,
    amount: &str,
    to: Option<&str>,
    lock_id: Option<&str>,
) -> Result<()> {
    drill_gate(&s.params, "rogue-mint")?;
    let value = u64::try_from(zat(amount)?)?;
    let key = s.load_key()?;
    let chain = foreign::connect(s, &key).await?;
    let me = chain
        .guardian_of(&key.public_key())
        .map_err(|e| anyhow!("member key: {e}"))?;
    let to: Account = match to {
        Some(t) => chain.parse_account(t).map_err(|e| anyhow!("--to: {e}"))?,
        None => me.account().ok_or_else(|| {
            anyhow!(
                "--to is required on {}: a guardian key is no account",
                s.foreign.title()
            )
        })?,
    };
    ensure!(
        to.ethereum() != Some(&EthAddress::ZERO),
        "--to is the zero address"
    );
    let lock_id: [u8; 32] = match lock_id {
        Some(h) => hawkeye_core::bytes::from_hex_array("--lock-id", h)
            .map_err(|e| anyhow!("--lock-id: {e}"))?,
        None => invented_lock_id_for(
            &me,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        ),
    };
    let digest = chain
        .mint_digest(&lock_id, value, &to)
        .map_err(|e| anyhow!("{e}"))?;
    let mut store = Store::open(&s.store_path)?;
    let rec = store
        .tx(|t| t.sign_once_drill_mint(&lock_id, value, &to, &digest, |d| chain.sign(&key, d)))?;
    let foreign::Proposed {
        mined,
        proposal_id,
        eta,
    } = chain
        .propose_mint(lock_id, value, to.clone(), rec.signature)
        .await
        .map_err(|e| {
            let call = match s.foreign {
                BridgeKind::Ethereum => "proposeMint",
                BridgeKind::Near => "propose_mint",
            };
            anyhow!("{call}: {e}")
        })?;
    info!(event = "rogue_mint_proposed", lock_id = %format!("0x{}", hex::encode(lock_id)),
          proposal_id, amount = value, to = %to, tx = %mined.tx, eta);
    print(&json!({
        "lockid": format!("0x{}", hex::encode(lock_id)),
        "proposal_id": proposal_id.to_string(),
        "proposer": me.to_string(),
        "amount_zat": value,
        "to": to.to_string(),
        "eta": eta,
        "txhash": mined.tx.to_string(),
        "block": mined.height,
    }))
}

/// `hawkeye recover`: `vault_ownerspend` of every vault and intent of the bridge's tag (`WYEC` or
/// `NYEC`) and the set this wallet owns (selector 2 after `ownerHeight`, 3 once the set is
/// released). The owner is a post-quantum key of the node wallet (`vault_list` `mine`); the node
/// signs the SLH-DSA spend (a 7,939-byte scriptSig, about 8.1 KB) and charges
/// `max(10,000 zat, rate × size)`: on a node with the fee structure (rpcversion 8) the rate is
/// $0.05/KB at the attested tip price (at least 5,000 zat/KB), `-pqfeerate` without a price, the
/// fee capped at `min(max(-maxtxfee, $2), -yellowbackmaxtxfee)`
/// (`hawkeye_ycash::mock::owner_spend_fee`). Hawkeye holds no owner key and no post-quantum code.
pub async fn recover(s: &Settings) -> Result<()> {
    let node = ycash(s)?;
    let rows = node
        .vault_list(Some(&VaultListFilter {
            tag: Some(s.params.tag_text()),
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

/// `hawkeye leave`: this attestor's member key leaves the set by its own `SET_REMOVE` (burn 0,
/// signed by the key alone: `set_leave`, owner 2026-10-11). From the next block the member is
/// `removed`; its bond stays locked — and slashable — for the set's `maturity` (at least 16,128
/// blocks, 14 days, on mainnet and testnet: D-Q-31), then `hawkeye withdraw-bond` returns it.
/// Stop the daemon first: it refuses to start once the key is no longer a current member.
pub async fn leave(s: &Settings, with_live_unlocks: bool) -> Result<()> {
    let key = s.load_key()?;
    let node = ycash(s)?;
    if let Some(why) = live_unlocks_block(s, &node, &key).await? {
        if !with_live_unlocks {
            anyhow::bail!("{why}");
        }
        tracing::warn!(event = "leave_with_live_unlocks", detail = %why);
    }
    print(&leave_set(&node, &key, &s.params.set_hash()).await?)
}

/// Why `hawkeye leave` should wait (W4-B-2, V-N2): a live leader/cosign unlock of an unspent
/// vault, or a burn assigned to this member, or an intent this member signed that is still
/// pending. `None` when the ledger is absent or holds nothing of that kind.
pub async fn live_unlocks_block(
    s: &Settings,
    node: &YcashRpc,
    key: &hawkeye_core::SecretKey,
) -> Result<Option<String>> {
    if !s.store_path.exists() {
        return Ok(None);
    }
    let me = key.public_key();
    let mut store = hawkeye_store::Store::open_readonly(&s.store_path)
        .with_context(|| format!("ledger {}", s.store_path.display()))?;
    live_unlock_reason(&mut store, s.params.set_id, s.params.deployment, node, me).await
}

/// The refusal [`live_unlocks_block`] would produce for an already-open ledger.
pub async fn live_unlock_reason(
    store: &mut hawkeye_store::Store,
    set: [u8; 32],
    deployment: hawkeye_core::Deployment,
    node: &YcashRpc,
    me: [u8; 33],
) -> Result<Option<String>> {
    let (rows, assigned, pending) = store.read(|t| {
        let rows = t.live_unlock_rows(&set)?;
        let assigned = t
            .burns_in_state(&deployment, hawkeye_store::BurnState::Assigned)?
            .into_iter()
            .filter(|b| b.leader == Some(me))
            .map(|b| b.key.nonce)
            .collect::<Vec<_>>();
        let pending = t
            .burns_in_state(&deployment, hawkeye_store::BurnState::IntentPending)?
            .into_iter()
            .filter(|b| b.leader == Some(me))
            .map(|b| b.key.nonce)
            .collect::<Vec<_>>();
        Ok::<_, hawkeye_store::StoreError>((rows, assigned, pending))
    })?;
    let mut held = vec![];
    for row in rows {
        if !matches!(
            row.origin,
            hawkeye_store::UnlockOrigin::Leader | hawkeye_store::UnlockOrigin::Cosign
        ) {
            continue;
        }
        let op = hawkeye_ycash::OutPoint::new(
            hawkeye_ycash::Hash256::from_internal(row.prevout.txid),
            row.prevout.vout,
        );
        if node.gettxout(&op.txid, op.vout, true).await?.is_some() {
            held.push(format!("burn {} on vault {}", row.key.nonce, row.prevout));
        }
    }
    if held.is_empty() && assigned.is_empty() && pending.is_empty() {
        return Ok(None);
    }
    let mut parts = held;
    for n in assigned {
        parts.push(format!("burn {n} assigned"));
    }
    for n in pending {
        parts.push(format!("burn {n} intent pending"));
    }
    Ok(Some(format!(
        "this member holds live signed unlocks ({}): let them confirm, or leave with \
         --with-live-unlocks (the set re-signs those burns and rolls the vaults; \
         docs/operations.md §7)",
        parts.join(", ")
    )))
}

/// [`leave`] against `node`: checks the key is an ACTIVE member, calls `set_leave`, and answers
/// `{txid, memberkey, exitheight, bondspendableat, bondoutpoint, maturity}`.
pub async fn leave_set(
    node: &YcashRpc,
    key: &hawkeye_core::SecretKey,
    setid: &hawkeye_ycash::Hash256,
) -> Result<serde_json::Value> {
    let me = hawkeye_ycash::PubKey(key.public_key());
    let info = node.set_getinfo(setid, None).await.context("set_getinfo")?;
    let m = info
        .memberlist
        .iter()
        .find(|m| m.key == me)
        .ok_or_else(|| anyhow!("member key {me} is not in set {setid}"))?;
    ensure!(
        m.status == MemberStatus::Active,
        "member key {me} is {:?} in set {setid}: there is nothing to leave",
        m.status
    );
    let r = node
        .set_leave(setid, Some(&me))
        .await
        .context("set_leave")?;
    info!(event = "left_set", txid = %r.txid, member = %me, exitheight = r.exitheight,
          bondspendableat = r.bondspendableat, maturity = info.set.params.maturity);
    Ok(json!({
        "txid": r.txid.to_string(),
        "memberkey": me.to_string(),
        "exitheight": r.exitheight,
        "bondspendableat": r.bondspendableat,
        "bondoutpoint": m.bondoutpoint.to_string(),
        "maturity": info.set.params.maturity,
    }))
}

/// `hawkeye withdraw-bond [--to <t-address>]`: after `hawkeye leave` and the set's `maturity`,
/// spend this attestor's bond (`P2SH(<locktime> CLTV DROP <memberKey> CHECKSIG)`) to `--to`
/// (default a new address of the node wallet). Hawkeye signs the bond input itself with the
/// member key (the node wallet has no signer for the bond script); the node judges the exit
/// delay (`bad-vault-bond-locked` until `exitHeight + maturity`) and refuses a frozen bond.
pub async fn withdraw_bond(s: &Settings, to: Option<&str>) -> Result<()> {
    let key = s.load_key()?;
    let node = ycash(s)?;
    print(&withdraw_bond_with(&node, &key, &s.params.set_hash(), to).await?)
}

/// [`withdraw_bond`] against `node`.
pub async fn withdraw_bond_with(
    node: &YcashRpc,
    key: &hawkeye_core::SecretKey,
    setid: &hawkeye_ycash::Hash256,
    to: Option<&str>,
) -> Result<serde_json::Value> {
    let me = hawkeye_ycash::PubKey(key.public_key());
    let info = node.set_getinfo(setid, None).await.context("set_getinfo")?;
    let m = info
        .memberlist
        .iter()
        .find(|m| m.key == me)
        .ok_or_else(|| anyhow!("member key {me} is not in set {setid}"))?
        .clone();
    ensure!(
        !m.bondfrozen,
        "the bond {} is frozen (slashed): it is never spendable",
        m.bondoutpoint
    );
    ensure!(
        m.status != MemberStatus::Active,
        "an active member's bond is locked (bad-vault-bond-locked): run `hawkeye leave` first, \
         then wait the set's maturity ({} blocks)",
        info.set.params.maturity
    );
    let op = m.bondoutpoint;
    let out = node
        .gettxout(&op.txid, op.vout, true)
        .await
        .context("gettxout")?
        .ok_or_else(|| anyhow!("the bond {op} is already spent"))?;
    let tip = node.getblockcount().await?;
    ensure!(
        tip >= m.bondlocktime,
        "the bond script's CLTV holds it until height {} (tip {tip})",
        m.bondlocktime + 1
    );
    let to_spk = match to {
        Some(a) => node.validateaddress(a).await?,
        None => node.validateaddress(&node.getnewaddress().await?).await?,
    }
    .script_pub_key
    .ok_or_else(|| anyhow!("validateaddress gave no scriptPubKey"))?;
    let branch = node.getblockchaininfo().await?.consensus.nextblock;
    let branch = u32::from_str_radix(&branch, 16)
        .map_err(|e| anyhow!("consensus.nextblock {branch:?}: {e}"))?;
    let tx = build_bond_withdrawal(
        key,
        &op,
        m.bondlocktime,
        &out.script_pub_key.hex.0,
        out.value.zat(),
        to_spk.0,
        tip,
        branch,
    )?;
    let txid = match node.sendrawtransaction(&HexBytes(tx.encode()), false).await {
        Ok(t) => t,
        Err(e) if e.rpc().and_then(|r| r.bad_vault()) == Some("bad-vault-bond-locked") => bail!(
            "the bond is still in its exit delay: spendable from exitHeight + maturity ({} \
             blocks; `hawkeye leave` printed bondspendableat): {e}",
            info.set.params.maturity
        ),
        Err(e) => return Err(e).context("sendrawtransaction"),
    };
    let value = out.value.zat() - BOND_WITHDRAW_FEE;
    info!(event = "bond_withdrawn", txid = %txid, bond = %op, value);
    Ok(json!({"txid": txid.to_string(), "bondoutpoint": op.to_string(), "value_zat": value}))
}

/// The default amount of one `split-coins` coin: 0.01 YEC (a vault spend's fee is 0.0001).
pub const SPLIT_COIN_DEFAULT: &str = "0.01";

/// `hawkeye split-coins --count N [--amount YEC]` (remedial report 05/H-1 §4.5): one stock
/// `sendmany` from the node wallet to `N` fresh addresses of the same wallet, so the next
/// block confirms `N` coins that each fund one cancel (the node's `Fund` spends confirmed
/// coins only).
pub async fn split_coins(s: &Settings, count: u32, amount: Option<&str>) -> Result<()> {
    ensure!((1..=500).contains(&count), "--count must be 1..=500");
    let each = zat(amount.unwrap_or(SPLIT_COIN_DEFAULT))?;
    ensure!(
        each >= crate::engine::watch::VAULT_RPC_FEE_ZAT
            + crate::engine::watch::VAULT_RPC_MIN_CHANGE_ZAT,
        "--amount must be at least 0.00011 YEC (VAULT_RPC_FEE + VAULT_RPC_MIN_CHANGE)"
    );
    let node = ycash(s)?;
    let mut to = Vec::with_capacity(count as usize);
    for _ in 0..count {
        to.push((node.getnewaddress().await?, Amount::from_zat(each)));
    }
    let txid = node.sendmany(&to).await.context("sendmany")?;
    info!(event = "split_coins_sent", txid = %txid, count, amount_zat = each);
    print(&json!({"txid": txid.to_string(), "count": count, "amount_zat": each}))
}

/// The signed bond withdrawal: input `bond` (whose output is `bond_spk`, `value_zat`), one
/// output of `value_zat − BOND_WITHDRAW_FEE` to `to_spk`, `nLockTime` = `tip` (≥ the CLTV
/// `locktime`, final at the next block), sequence `0xfffffffe`, expiry `tip + 40`, signed for
/// `branch_id` (the next block's). Refuses a `bond_spk` that is not this key's bond script.
#[allow(clippy::too_many_arguments)]
pub fn build_bond_withdrawal(
    key: &hawkeye_core::SecretKey,
    bond: &hawkeye_ycash::OutPoint,
    locktime: u32,
    bond_spk: &[u8],
    value_zat: i64,
    to_spk: Vec<u8>,
    tip: u32,
    branch_id: u32,
) -> Result<Transaction> {
    use hawkeye_core::template::{bond_spk as bond_script, bond_withdrawal_script_sig};
    ensure!(
        bond_spk == bond_script(&key.public_key(), locktime),
        "the bond output {bond} is not this member key's bond script (locktime {locktime})"
    );
    ensure!(
        value_zat > BOND_WITHDRAW_FEE,
        "the bond ({value_zat} zat) does not cover the fee"
    );
    ensure!(
        tip >= locktime,
        "the bond's CLTV ({locktime}) is above the tip ({tip})"
    );
    let mut tx = Transaction::new_v4(
        vec![TxIn {
            prevout: *bond,
            script_sig: vec![],
            sequence: 0xffff_fffe,
        }],
        vec![TxOut {
            value: value_zat - BOND_WITHDRAW_FEE,
            script_pubkey: to_spk,
        }],
        tip,
        tip + 40,
    );
    let core = hawkeye_core::tx::Transaction::parse(&tx.encode())
        .map_err(|e| anyhow!("bond withdrawal: {e}"))?;
    tx.inputs[0].script_sig =
        bond_withdrawal_script_sig(&core, 0, key, locktime, value_zat as u64, branch_id)
            .map_err(|e| anyhow!("bond withdrawal: {e}"))?;
    // one P2SH input and one output: two ZIP-317 actions, 1,000 zat (04/N-1)
    ensure!(
        tx.zip317_conventional_fee() <= BOND_WITHDRAW_FEE,
        "the bond withdrawal's ZIP-317 conventional fee exceeds its flat fee"
    );
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Params;
    use hawkeye_core::memo::{HawkeyeMemo, MemoKind};
    use hawkeye_store::{BurnKey, NewBurn};

    fn params(drills: bool, mainnet: bool) -> Params {
        crate::config::sample_params(drills, mainnet)
    }

    #[test]
    fn invented_lock_ids_are_distinct() {
        let a = EthAddress([1; 20]);
        assert_ne!(invented_lock_id(&a, 1), invented_lock_id(&a, 2));
        assert_ne!(
            invented_lock_id(&a, 1),
            invented_lock_id(&EthAddress([2; 20]), 1)
        );
        assert_eq!(invented_lock_id(&a, 7), invented_lock_id(&a, 7));
    }

    #[test]
    fn destinations_follow_the_bridge_kind() {
        let a = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert_eq!(
            parse_destination(BridgeKind::Ethereum, a).unwrap(),
            Destination::Ethereum(EthAddress::parse(a).unwrap())
        );
        let e = parse_destination(BridgeKind::Near, a)
            .unwrap_err()
            .to_string();
        assert!(e.contains("is an Ethereum address"), "{e}");
        let n = parse_destination(BridgeKind::Near, "alice.near").unwrap();
        assert_eq!(n.near().unwrap().as_str(), "alice.near");
        assert_eq!(n.script()[..5], [0x6a, 0x0d, b'N', b'R', b'1']);
        let e = parse_destination(BridgeKind::Ethereum, "alice.near")
            .unwrap_err()
            .to_string();
        assert!(e.contains("is a NEAR account id"), "{e}");
        // lowercase 0x + 40 hex: an Ethereum address there, NEAR's EVM-implicit account here
        let lower = a.to_lowercase();
        assert!(matches!(
            parse_destination(BridgeKind::Ethereum, &lower).unwrap(),
            Destination::Ethereum(_)
        ));
        assert!(matches!(
            parse_destination(BridgeKind::Near, &lower).unwrap(),
            Destination::Near(_)
        ));
        let zero = format!("0x{}", "0".repeat(40));
        assert!(parse_destination(BridgeKind::Ethereum, &zero).is_err());
        for bad in ["", "Alice.near", "a", "a..b"] {
            assert!(parse_destination(BridgeKind::Near, bad).is_err(), "{bad}");
            assert!(
                parse_destination(BridgeKind::Ethereum, bad).is_err(),
                "{bad}"
            );
        }
    }

    /// 05/M-2 (d): `hawkeye burn` refuses a burn above the set's per-window cap, names the cap
    /// and the override; within the cap, or with no rate limit, it passes.
    #[test]
    fn burn_pre_check_refuses_an_over_cap_amount() {
        let e = over_cap_check(800_000_000, Some(500_000_000)).unwrap_err();
        assert_eq!(
            e.to_string(),
            "this burn exceeds the attestor set's per-window cap (5.00000000 YEC): it would not \
             be released until the set raises its rate limit; pass --allow-over-cap to burn anyway"
        );
        assert!(over_cap_check(500_000_000, Some(500_000_000)).is_ok());
        assert!(over_cap_check(u64::MAX, None).is_ok());
    }

    #[test]
    fn invented_lock_ids_per_guardian_kind() {
        let a = EthAddress([1; 20]);
        assert_eq!(
            invented_lock_id_for(&Guardian::Ethereum(a), 5),
            invented_lock_id(&a, 5)
        );
        assert_ne!(
            invented_lock_id_for(&Guardian::Secp256k1([1; 64]), 5),
            invented_lock_id_for(&Guardian::Secp256k1([2; 64]), 5)
        );
    }

    #[test]
    fn drill_gate_needs_drills_and_refuses_mainnet() {
        assert!(drill_gate(&params(true, false), "rogue-mint").is_ok());
        assert!(drill_gate(&params(true, true), "rogue-mint").is_err());
        assert!(drill_gate(&params(false, false), "rogue-mint").is_err());
        assert!(drill_gate(&params(true, false), "rogue-unlock").is_ok());
        let off = drill_gate(&params(false, false), "rogue-unlock").unwrap_err();
        assert!(off.to_string().contains("[devnet] drills = true"), "{off}");
        assert!(drill_gate(&params(true, true), "rogue-unlock").is_err());
    }

    /// `hawkeye burn` warns for a scheme-2 (Falcon) recipient only (§4.2): the contracts accept
    /// it, the node pays it once Falcon is active.
    #[test]
    fn burn_warns_for_falcon_recipients_only() {
        assert_eq!(recipient_warning(&YcashRecipient::p2pkh([1; 20])), None);
        assert_eq!(recipient_warning(&YcashRecipient::p2sh([1; 20])), None);
        assert_eq!(
            recipient_warning(&YcashRecipient::pqpkh(1, [1; 32]).unwrap()),
            None
        );
        let w = recipient_warning(&YcashRecipient::pqpkh(2, [1; 32]).unwrap()).unwrap();
        assert!(w.contains("Falcon"), "{w}");
        // the CLI decodes sq…/tq…/rq… and refuses the owner form (yb…/yt…/yr…)
        use hawkeye_core::address::{Network, encode_address, encode_pq_address};
        let r = YcashRecipient::pqpkh(1, [0xc5; 32]).unwrap();
        let sq = encode_address(&r, Network::Regtest);
        assert!(sq.starts_with("rq"));
        assert_eq!(decode_address(&sq, Network::Regtest).unwrap(), r);
        let owner = encode_pq_address(r.pq_key().unwrap(), Network::Regtest);
        assert!(owner.starts_with("yr"));
        assert!(decode_address(&owner, Network::Regtest).is_err());
    }

    #[test]
    fn replay_plan_carries_the_burns_memo_recipient_and_amount() {
        let p = params(true, false);
        let mut store = Store::open_in_memory().unwrap();
        let r = YcashRecipient::p2pkh([0x11; 20]);
        store
            .tx(|t| {
                t.insert_burn(&NewBurn {
                    key: BurnKey::new(p.deployment, 3),
                    tx_hash: [0xab; 32],
                    block_number: 9,
                    block_hash: [1; 32],
                    from: Destination::Ethereum(EthAddress([2; 20])),
                    amount: 400_000_000,
                    recipient: r.to_bytes(),
                    finalized: true,
                })
            })
            .unwrap();
        let plan = store.tx(|t| replay_plan(t, &p, 3, None)).unwrap();
        assert_eq!(plan.recipient_script, r.script());
        assert_eq!(plan.amount, 400_000_000);
        let memo = HawkeyeMemo::decode(&plan.memo).unwrap();
        assert_eq!(memo.kind, MemoKind::BurnRelease);
        assert_eq!(memo.reference, 3);
        assert_eq!(memo.data, [0xab; 32]);
        assert_eq!(memo.deployment, p.deployment);
        // an amount override; an unknown nonce
        let plan = store.tx(|t| replay_plan(t, &p, 3, Some(5))).unwrap();
        assert_eq!(plan.amount, 5);
        let e = store.tx(|t| replay_plan(t, &p, 4, None)).unwrap_err();
        assert!(
            e.to_string().contains("not in this attestor's ledger"),
            "{e}"
        );
    }

    #[test]
    fn replay_plan_refuses_an_unfinalized_burn() {
        let p = params(true, false);
        let mut store = Store::open_in_memory().unwrap();
        store
            .tx(|t| {
                t.insert_burn(&NewBurn {
                    key: BurnKey::new(p.deployment, 0),
                    tx_hash: [0xab; 32],
                    block_number: 9,
                    block_hash: [1; 32],
                    from: Destination::Ethereum(EthAddress([2; 20])),
                    amount: 1,
                    recipient: YcashRecipient::p2pkh([0x11; 20]).to_bytes(),
                    finalized: false,
                })
            })
            .unwrap();
        let e = store.tx(|t| replay_plan(t, &p, 0, None)).unwrap_err();
        assert!(e.to_string().contains("not finalized"), "{e}");
    }
}
