//! The status summary (`/status`, `hawkeye status`) and its Prometheus rendering (`/metrics`).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

/// One alarm: a condition an operator must look at (plan §3.1 item 4, §5.3, §5.4).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Alarm {
    /// Stable name (`supply`, `guardian-drift`, `exposure`, `matured-unmatched`, `roll-due`, …).
    pub name: String,
    /// Human-readable detail.
    pub detail: String,
    /// Ycash height at which it was raised.
    pub since: u32,
}

/// Chain heights.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Heights {
    /// The node's tip.
    pub tip: u64,
    /// The ledger's cursor.
    pub cursor: u64,
    /// `tip − cursor`.
    pub lag: u64,
}

/// The supply invariant (plan §3.1 item 4): wYEC supply ≤ Σ live `WYEC` vault value.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Supply {
    /// `WrappedYcash.totalSupply()`, base units (= zatoshi).
    pub wyec_total_supply: u128,
    /// Σ value of the set's live `WYEC` vaults, zatoshi.
    pub locked_vault_value: u64,
    /// The invariant holds.
    pub ok: bool,
}

/// The status summary.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Status {
    /// Hawkeye's version.
    pub version: String,
    /// `regtest` / `testnet` / `mainnet`.
    pub network: String,
    /// The set id (display order).
    pub set_id: String,
    /// This attestor's member key.
    pub member_key: String,
    /// The bridge's foreign chain: `ethereum` or `near` (`[foreign] kind`).
    pub foreign_kind: String,
    /// This attestor's guardian on the foreign chain: the member key's Ethereum address
    /// (EIP-55), or on NEAR its 64-byte secp256k1 key `0x` ‖ `x ‖ y`.
    pub guardian: String,
    /// The guardian, under its pre-NEAR name (kept for the Ethereum devnet scripts; equals
    /// `guardian`).
    pub eth_address: String,
    /// Ycash heights.
    pub ycash: Heights,
    /// Foreign-chain heights (final block, scan cursor): Ethereum block numbers or NEAR block
    /// heights.
    pub foreign: Heights,
    /// The foreign heights under their pre-NEAR name (kept for the Ethereum devnet scripts;
    /// equals `foreign`).
    pub ethereum: Heights,
    /// Lock counts by state.
    pub locks: BTreeMap<String, u64>,
    /// Burn counts by state.
    pub burns: BTreeMap<String, u64>,
    /// Intent counts by state.
    pub intents: BTreeMap<String, u64>,
    /// Vault counts by state.
    pub vaults: BTreeMap<String, u64>,
    /// Slash case counts by state.
    pub slash_cases: BTreeMap<String, u64>,
    /// Live members of the set.
    pub live_members: u64,
    /// The supply check.
    pub supply: Supply,
    /// Raised alarms.
    pub alarms: Vec<Alarm>,
    /// Ticks run by this process.
    pub ticks: u64,
    /// Errors of the last tick.
    pub last_errors: Vec<String>,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Prometheus text exposition of a status.
pub fn render_metrics(s: &Status) -> String {
    let mut o = String::new();
    let mut gauge = |name: &str, help: &str, rows: &[(String, f64)]| {
        let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} gauge");
        for (labels, v) in rows {
            let _ = writeln!(o, "{name}{labels} {v}");
        }
    };
    gauge(
        "hawkeye_ycash_height",
        "Ycash tip and ledger cursor",
        &[
            ("{kind=\"tip\"}".into(), s.ycash.tip as f64),
            ("{kind=\"cursor\"}".into(), s.ycash.cursor as f64),
        ],
    );
    gauge(
        "hawkeye_ycash_lag_blocks",
        "Ycash blocks not yet processed",
        &[(String::new(), s.ycash.lag as f64)],
    );
    gauge(
        "hawkeye_eth_block",
        "Ethereum finalized block and scan cursor",
        &[
            ("{kind=\"finalized\"}".into(), s.ethereum.tip as f64),
            ("{kind=\"cursor\"}".into(), s.ethereum.cursor as f64),
        ],
    );
    gauge(
        "hawkeye_eth_lag_blocks",
        "Finalized Ethereum blocks not yet scanned",
        &[(String::new(), s.ethereum.lag as f64)],
    );
    let chain = format!("chain=\"{}\"", esc(&s.foreign_kind));
    gauge(
        "hawkeye_foreign_block",
        "Foreign chain (Ethereum or NEAR) final block and scan cursor",
        &[
            (format!("{{{chain},kind=\"final\"}}"), s.foreign.tip as f64),
            (
                format!("{{{chain},kind=\"cursor\"}}"),
                s.foreign.cursor as f64,
            ),
        ],
    );
    gauge(
        "hawkeye_foreign_lag_blocks",
        "Final foreign-chain blocks not yet scanned",
        &[(format!("{{{chain}}}"), s.foreign.lag as f64)],
    );
    for (name, help, map) in [
        ("hawkeye_locks", "Locks by state", &s.locks),
        ("hawkeye_burns", "Burns by state", &s.burns),
        ("hawkeye_intents", "Intents by state", &s.intents),
        ("hawkeye_vaults", "Vaults by state", &s.vaults),
        (
            "hawkeye_slash_cases",
            "Slash cases by state",
            &s.slash_cases,
        ),
    ] {
        let rows: Vec<(String, f64)> = map
            .iter()
            .map(|(k, v)| (format!("{{state=\"{}\"}}", esc(k)), *v as f64))
            .collect();
        gauge(name, help, &rows);
    }
    gauge(
        "hawkeye_live_members",
        "Live members of the attestor set",
        &[(String::new(), s.live_members as f64)],
    );
    gauge(
        "hawkeye_wyec_total_supply",
        "wYEC total supply (base units)",
        &[(String::new(), s.supply.wyec_total_supply as f64)],
    );
    gauge(
        "hawkeye_locked_vault_value",
        "Value of the set's live WYEC vaults (zatoshi)",
        &[(String::new(), s.supply.locked_vault_value as f64)],
    );
    gauge(
        "hawkeye_supply_ok",
        "1 if wYEC supply <= locked vault value",
        &[(String::new(), f64::from(u8::from(s.supply.ok)))],
    );
    let alarms: Vec<(String, f64)> = s
        .alarms
        .iter()
        .map(|a| (format!("{{name=\"{}\"}}", esc(&a.name)), 1.0))
        .collect();
    gauge("hawkeye_alarm", "Raised alarms", &alarms);
    gauge(
        "hawkeye_ticks_total",
        "Engine ticks run",
        &[(String::new(), s.ticks as f64)],
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_text() {
        let mut s = Status::default();
        s.locks.insert("MINTED".into(), 2);
        s.alarms.push(Alarm {
            name: "supply".into(),
            detail: "x".into(),
            since: 1,
        });
        let m = render_metrics(&s);
        assert!(m.contains("hawkeye_locks{state=\"MINTED\"} 2"));
        assert!(m.contains("hawkeye_alarm{name=\"supply\"} 1"));
        assert!(m.contains("# TYPE hawkeye_supply_ok gauge"));
    }

    #[test]
    fn foreign_metrics_name_the_chain() {
        let s = Status {
            foreign_kind: "near".into(),
            foreign: Heights {
                tip: 9,
                cursor: 7,
                lag: 2,
            },
            ..Status::default()
        };
        let m = render_metrics(&s);
        assert!(m.contains("hawkeye_foreign_block{chain=\"near\",kind=\"final\"} 9"));
        assert!(m.contains("hawkeye_foreign_block{chain=\"near\",kind=\"cursor\"} 7"));
        assert!(m.contains("hawkeye_foreign_lag_blocks{chain=\"near\"} 2"));
    }
}
