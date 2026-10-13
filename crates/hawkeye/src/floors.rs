// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying file LICENSE or
// https://www.opensource.org/licenses/mit-license.php.

//! Mainnet floors on the policy parameters (audit 05/M-4; plan §2, §3.1, §4.1).
//!
//! These are **sanity bounds**, an order of magnitude below any sane value, not the calibrated
//! ones: the P8 values come from `yb-calibration` (plan Q-1) and sit well above them. Their job is
//! to refuse a devnet file copied to mainnet — two confirmations would let a routine Ycash reorg
//! turn a signed lock into minted wYEC with no YEC behind it; a `heartbeat_blocks` above the set's
//! `livenesswindow` would make every member DORMANT at once and open every vault's owner branch.
//!
//! - **Static** rules ([`static_rows`]) read the config alone;
//!   [`Config::settings`](crate::config::Config::settings) refuses a mainnet config that breaks one and returns a
//!   testnet one's breaches, with the absolute floors divided by [`TESTNET_DIVISOR`], as
//!   warnings. Regtest is unconstrained.
//! - **Live** rules ([`live_rows`]) need the node: `heartbeat_blocks ≤ livenesswindow / 4` (plan
//!   D-U5) and `max_lock` against one rate-limit window. `startup_checks` refuses the first on
//!   mainnet (warns elsewhere); the engine re-checks it with the guardian check (every 60 ticks:
//!   a `SET_PARAMS` can shrink the window) and raises `heartbeat-too-slow`.
//!
//! The contract's floors (`challengeWindow`, `mintCap`, threshold) are `hawkeye-eth::mode`'s,
//! applied by the adapter's `check_bridge` (audit 05/H-2).

use std::fmt;

use hawkeye_ycash::types::SetParams;
use serde::Serialize;

use crate::config::Params;

/// `C_Y` on mainnet: ≈ 25 min at 75 s, deeper than any Ycash reorg seen in years; the plan's
/// lock-absent rule and H-2's window floor assume 20 (plan proposal: 40).
pub const MAINNET_MIN_CONFIRMATIONS: u32 = 20;
/// The vault delay (challenge window) on mainnet: 6 h (plan proposal: 1,152 = 24 h). A cancel
/// needs `C_Y`-deep finality of the burn view plus its own inclusion.
pub const MAINNET_MIN_DELAY: u32 = 288;
/// The delay must also be at least this many times `C_Y`.
pub const DELAY_PER_CONFIRMATION: u32 = 4;
/// `MIN_OWNER_AGE` on mainnet: 3 months (plan §3.1 proposal: ≈ 841,000 = 2 years); stops a
/// devnet value (400).
pub const MAINNET_MIN_OWNER_AGE: u32 = 105_120;
/// `heartbeat_blocks ≤ livenesswindow / HEARTBEATS_PER_LIVENESS_WINDOW` (plan D-U5: three missed
/// heartbeats before dormancy).
pub const HEARTBEATS_PER_LIVENESS_WINDOW: u32 = 4;
/// `max_lock` is at most the coin's supply cap, 21,000,000 YEC.
pub const MAX_LOCK_ZAT: u64 = 21_000_000 * 100_000_000;
/// Testnet checks the absolute floors divided by this, as warnings.
pub const TESTNET_DIVISOR: u32 = 4;

/// One rule and how a value fares against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    /// The parameter (`bridge.confirmations`, …).
    pub param: &'static str,
    /// Its value.
    pub value: u64,
    /// The rule, in words (`>= 20 (MAINNET_MIN_CONFIRMATIONS)`).
    pub rule: String,
    /// The value meets it.
    pub ok: bool,
    /// Where the number comes from.
    pub why: &'static str,
}

impl fmt::Display for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ({})",
            self.param,
            self.value,
            if self.ok { "meets" } else { "breaks" },
            self.rule
        )
    }
}

fn row(param: &'static str, value: u64, rule: String, ok: bool, why: &'static str) -> Row {
    Row {
        param,
        value,
        rule,
        ok,
        why,
    }
}

/// The static rules for `p`, the absolute floors divided by `divisor` (1 on mainnet,
/// [`TESTNET_DIVISOR`] on testnet).
pub fn static_rows(p: &Params, divisor: u32) -> Vec<Row> {
    let d = divisor.max(1);
    let c = p.confirmations;
    let delay = u32::from(p.delay);
    let min_c = MAINNET_MIN_CONFIRMATIONS / d;
    let min_delay = MAINNET_MIN_DELAY / d;
    let min_age = MAINNET_MIN_OWNER_AGE / d;
    let roll_min = u64::from(delay) + u64::from(p.takeover) + 2 * u64::from(c);
    vec![
        row(
            "bridge.confirmations",
            c.into(),
            format!(">= {min_c} (MAINNET_MIN_CONFIRMATIONS)"),
            c >= min_c,
            "plan §2/§4.1: deeper than any Ycash reorg; a shallower signed lock is an exposure",
        ),
        row(
            "bridge.delay",
            delay.into(),
            format!(">= {min_delay} (MAINNET_MIN_DELAY)"),
            delay >= min_delay,
            "plan §2: the vault challenge window (mainnet proposal 1,152)",
        ),
        row(
            "bridge.delay",
            delay.into(),
            format!(
                ">= {DELAY_PER_CONFIRMATION} x confirmations = {}",
                DELAY_PER_CONFIRMATION * c
            ),
            delay >= DELAY_PER_CONFIRMATION.saturating_mul(c),
            "a cancel needs the burn view C_Y deep plus its own inclusion",
        ),
        row(
            "bridge.min_owner_age",
            p.min_owner_age.into(),
            format!(">= {min_age} (MAINNET_MIN_OWNER_AGE)"),
            p.min_owner_age >= min_age,
            "plan §3.1 (proposal ~841,000 = 2 years)",
        ),
        row(
            "bridge.takeover_blocks",
            p.takeover.into(),
            format!(">= confirmations = {c}"),
            p.takeover >= c,
            "a takeover faster than finality makes two leaders",
        ),
        row(
            "bridge.takeover_blocks",
            p.takeover.into(),
            format!("<= delay / 4 = {}", delay / 4),
            p.takeover <= delay / 4,
            "a slower takeover leaves the successor no time before cancels mature",
        ),
        row(
            "bridge.roll_margin",
            p.roll_margin.into(),
            format!(">= delay + takeover_blocks + 2 x confirmations = {roll_min}"),
            u64::from(p.roll_margin) >= roll_min,
            "a roll is posted, possibly taken over and released before ownerHeight",
        ),
        row(
            "bridge.heartbeat_blocks",
            p.heartbeat_blocks.into(),
            ">= 1 (0 disables heartbeats)".into(),
            p.heartbeat_blocks >= 1,
            "plan §2: silence makes the set DORMANT and opens every owner branch",
        ),
        row(
            "bridge.min_lock",
            p.min_lock,
            "> 0".into(),
            p.min_lock > 0,
            "dust locks cost a policy evaluation and a mint each",
        ),
        row(
            "bridge.max_lock",
            p.max_lock,
            format!("<= {MAX_LOCK_ZAT} zat (21,000,000 YEC)"),
            p.max_lock <= MAX_LOCK_ZAT,
            "the coin's supply cap",
        ),
    ]
}

/// What [`static_rows`] means on `network` (`mainnet` / `testnet` / `regtest`): `Err` with every
/// breach on mainnet, the breaches as warnings on testnet, nothing on regtest.
pub fn check_static(p: &Params, network: &str) -> Result<Vec<String>, String> {
    let breaches =
        |d: u32| -> Vec<Row> { static_rows(p, d).into_iter().filter(|r| !r.ok).collect() };
    match network {
        "mainnet" => {
            let b = breaches(1);
            if b.is_empty() {
                Ok(vec![])
            } else {
                Err(b
                    .iter()
                    .map(|r| {
                        format!(
                            "mainnet refuses {} {}: needs {} (plan §2/§3.1/§4.1, audit 05/M-4)",
                            r.param, r.value, r.rule
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; "))
            }
        }
        "testnet" => Ok(breaches(TESTNET_DIVISOR)
            .iter()
            .map(|r| {
                format!(
                    "testnet: {} {} is below the floor ({})",
                    r.param, r.value, r.rule
                )
            })
            .collect()),
        _ => Ok(vec![]),
    }
}

/// The live rules against the set's parameters and its locked value (zatoshi): the heartbeat
/// against `livenesswindow` (refused on mainnet), and `max_lock` against one rate-limit window
/// (a warning: a lock larger than a window's cap cannot be released in one burn, audit 05/M-2).
pub fn live_rows(p: &Params, set: &SetParams, locked_zat: u64) -> Vec<Row> {
    let max_hb = set.livenesswindow / HEARTBEATS_PER_LIVENESS_WINDOW;
    let mut rows = vec![row(
        "bridge.heartbeat_blocks",
        p.heartbeat_blocks.into(),
        format!(
            "1..= livenesswindow / {HEARTBEATS_PER_LIVENESS_WINDOW} = {max_hb} (the set's livenesswindow {})",
            set.livenesswindow
        ),
        p.heartbeat_blocks >= 1 && p.heartbeat_blocks <= max_hb,
        "plan D-U5: three missed heartbeats before the set is DORMANT",
    )];
    if set.ratelimitbps > 0 {
        let cap = u128::from(locked_zat) * u128::from(set.ratelimitbps) / 10_000;
        rows.push(row(
            "bridge.max_lock",
            p.max_lock,
            format!(
                "<= one rate-limit window's cap ~ {cap} zat ({} bps of {locked_zat} locked; a warning)",
                set.ratelimitbps
            ),
            cap == 0 || u128::from(p.max_lock) <= cap,
            "audit 05/M-2: a larger burn waits for the set's cap",
        ));
    }
    rows
}

/// The heartbeat row of [`live_rows`] (the one that refuses on mainnet), if it breaks.
pub fn heartbeat_breach(p: &Params, set: &SetParams) -> Option<Row> {
    live_rows(p, set, 0)
        .into_iter()
        .find(|r| r.param == "bridge.heartbeat_blocks" && !r.ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::sample_params;
    use hawkeye_ycash::types::SetParams;
    use hawkeye_ycash::{Amount, PubKey};

    fn mainnet_ok() -> Params {
        let mut p = sample_params(false, true);
        p.confirmations = 20;
        p.delay = 288;
        p.min_owner_age = 105_120;
        p.takeover = 20;
        p.roll_margin = 288 + 20 + 40;
        p.heartbeat_blocks = 288;
        p.min_lock = 1;
        p.max_lock = MAX_LOCK_ZAT;
        p
    }

    fn set(livenesswindow: u32, ratelimitbps: u32) -> SetParams {
        SetParams {
            seats: 7,
            unlockthreshold: 1,
            cancelthreshold: 1,
            slashthreshold: 4,
            open: false,
            ratelimitbps,
            ratewindow: 1_152,
            livenesswindow,
            bondmin: Amount(1),
            bondlockmin: 0,
            maturity: 16_128,
            admitkey: PubKey([2; 33]),
        }
    }

    #[test]
    fn floor_values_pass_and_every_row_refuses_below() {
        let p = mainnet_ok();
        assert!(
            static_rows(&p, 1).iter().all(|r| r.ok),
            "{:?}",
            static_rows(&p, 1)
        );
        assert_eq!(check_static(&p, "mainnet"), Ok(vec![]));
        type Bump = fn(&mut Params);
        let cases: [(&str, Bump); 10] = [
            ("bridge.confirmations 19", |p| {
                p.confirmations = 19;
                p.takeover = 19
            }),
            ("bridge.delay 287", |p| p.delay = 287),
            ("bridge.delay 300: needs >= 4 x confirmations = 320", |p| {
                p.confirmations = 80;
                p.takeover = 80;
                p.delay = 300;
                p.roll_margin = 10_000
            }),
            ("bridge.min_owner_age 400", |p| p.min_owner_age = 400),
            ("bridge.takeover_blocks 19", |p| p.takeover = 19),
            ("bridge.takeover_blocks 73", |p| p.takeover = 73),
            ("bridge.roll_margin 50", |p| p.roll_margin = 50),
            ("bridge.heartbeat_blocks 0", |p| p.heartbeat_blocks = 0),
            ("bridge.min_lock 0", |p| p.min_lock = 0),
            ("bridge.max_lock", |p| p.max_lock = MAX_LOCK_ZAT + 1),
        ];
        for (want, bump) in cases {
            let mut p = mainnet_ok();
            bump(&mut p);
            let e = check_static(&p, "mainnet").unwrap_err();
            assert!(
                e.contains(&format!("mainnet refuses {want}")),
                "{want}: {e}"
            );
            // regtest: nothing
            assert_eq!(check_static(&p, "regtest"), Ok(vec![]));
        }
    }

    #[test]
    fn devnet_values_refused_on_mainnet_warned_on_testnet() {
        let mut p = sample_params(false, true);
        (p.confirmations, p.delay, p.min_owner_age) = (2, 6, 400);
        (p.takeover, p.roll_margin, p.heartbeat_blocks) = (4, 50, 10);
        let e = check_static(&p, "mainnet").unwrap_err();
        assert!(
            e.contains(
                "mainnet refuses bridge.confirmations 2: needs >= 20 (MAINNET_MIN_CONFIRMATIONS)"
            ),
            "{e}"
        );
        let w = check_static(&p, "testnet").unwrap();
        assert!(
            w.iter().any(|w| w.contains("bridge.confirmations 2")),
            "{w:?}"
        );
        // the testnet floors are a quarter: 5 confirmations, 72 blocks of delay pass there
        (p.confirmations, p.delay, p.min_owner_age) = (5, 72, 26_280);
        (p.takeover, p.roll_margin) = (5, 92);
        assert_eq!(check_static(&p, "testnet"), Ok(vec![]));
        assert!(check_static(&p, "mainnet").is_err());
    }

    #[test]
    fn heartbeat_against_the_live_window() {
        let p = mainnet_ok(); // 288
        assert!(heartbeat_breach(&p, &set(8_064, 0)).is_none());
        assert!(
            heartbeat_breach(&p, &set(1_152, 0)).is_none(),
            "1152 / 4 = 288"
        );
        let r = heartbeat_breach(&p, &set(1_151, 0)).unwrap();
        assert!(r.rule.contains("livenesswindow 1151"), "{r}");
        let mut off = p.clone();
        off.heartbeat_blocks = 0;
        assert!(heartbeat_breach(&off, &set(8_064, 0)).is_some());
        // max_lock vs one window's cap: a warning row
        let rows = live_rows(&p, &set(8_064, 2_000), 1_000_000);
        assert!(!rows[1].ok, "{rows:?}");
        let mut small = p;
        small.max_lock = 200_000;
        assert!(live_rows(&small, &set(8_064, 2_000), 1_000_000)[1].ok);
    }
}
