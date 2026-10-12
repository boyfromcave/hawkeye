//! Foreign-chain accounts and guardians in the ledger (schema v4, NEAR plan NH4).
//!
//! One ledger serves one bridge, but the columns that name an account on the foreign chain (a
//! lock's destination, a mint's recipient, a burner, a proposal's proposer) are chain-neutral
//! text, prefixed by the chain so a value never depends on the bridge kind to be read back:
//!
//! | Value | Text |
//! |---|---|
//! | [`Account::Ethereum`] | `ethereum:0x` ‖ 40 lowercase hex digits |
//! | [`Account::Near`] | `near:` ‖ the account id (2–64 bytes, NEAR's rules) |
//! | [`Guardian::Ethereum`] | `ethereum:0x` ‖ 40 lowercase hex digits |
//! | [`Guardian::Secp256k1`] | `secp256k1:` ‖ 128 lowercase hex digits (the 64-byte `x ‖ y`) |
//!
//! Schema v1–v3 stored 20-byte Ethereum addresses as raw `BLOB`s; the v4 migration rewrites each
//! as `'ethereum:0x' || lower(hex(blob))`, which [`parse_account`] reads back to the same
//! address (lossless). A NEAR implicit EVM account (`0x` + 40 hex, a valid NEAR account id) is
//! `near:0x…`, never confused with an Ethereum address.

use hawkeye_core::{AccountId, EthAddress};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

/// An account on the foreign chain (`hawkeye-core`'s lock destination type).
pub use hawkeye_core::Destination as Account;
/// A guardian of the bridge contract.
pub use hawkeye_core::Guardian;

const ETH: &str = "ethereum:0x";
const NEAR: &str = "near:";
const SECP: &str = "secp256k1:";

/// The ledger text of an account.
pub fn account_text(a: &Account) -> String {
    match a {
        Account::Ethereum(e) => format!("{ETH}{}", hex::encode(e.0)),
        Account::Near(n) => format!("{NEAR}{n}"),
    }
}

fn eth_hex(h: &str) -> Option<EthAddress> {
    if h.len() != 40 || !h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(h).ok()?.try_into().ok().map(EthAddress)
}

/// Read an account back from its ledger text.
pub fn parse_account(s: &str) -> Option<Account> {
    if let Some(h) = s.strip_prefix(ETH) {
        eth_hex(h).map(Account::Ethereum)
    } else if let Some(n) = s.strip_prefix(NEAR) {
        AccountId::parse(n).ok().map(Account::Near)
    } else {
        None
    }
}

/// The ledger text of a guardian.
pub fn guardian_text(g: &Guardian) -> String {
    match g {
        Guardian::Ethereum(e) => format!("{ETH}{}", hex::encode(e.0)),
        Guardian::Secp256k1(k) => format!("{SECP}{}", hex::encode(k)),
    }
}

/// Read a guardian back from its ledger text.
pub fn parse_guardian(s: &str) -> Option<Guardian> {
    if let Some(h) = s.strip_prefix(ETH) {
        eth_hex(h).map(Guardian::Ethereum)
    } else if let Some(h) = s.strip_prefix(SECP) {
        if h.len() != 128 || h.bytes().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        hex::decode(h)
            .ok()?
            .try_into()
            .ok()
            .map(Guardian::Secp256k1)
    } else {
        None
    }
}

/// An account as a SQL value.
pub(crate) struct SqlAccount(pub Account);

impl ToSql for SqlAccount {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(account_text(&self.0)))
    }
}

impl FromSql for SqlAccount {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let s = value.as_str()?;
        parse_account(s)
            .map(SqlAccount)
            .ok_or_else(|| FromSqlError::Other(format!("not a ledger account: {s:?}").into()))
    }
}

/// A guardian as a SQL value.
pub(crate) struct SqlGuardian(pub Guardian);

impl ToSql for SqlGuardian {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(guardian_text(&self.0)))
    }
}

impl FromSql for SqlGuardian {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let s = value.as_str()?;
        parse_guardian(s)
            .map(SqlGuardian)
            .ok_or_else(|| FromSqlError::Other(format!("not a ledger guardian: {s:?}").into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let e = Account::Ethereum(EthAddress([0xab; 20]));
        assert_eq!(account_text(&e), format!("ethereum:0x{}", "ab".repeat(20)));
        assert_eq!(parse_account(&account_text(&e)), Some(e));
        for id in [
            "alice.near",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            &"a".repeat(64),
        ] {
            let n = Account::Near(AccountId::parse(id).unwrap());
            assert_eq!(account_text(&n), format!("near:{id}"));
            assert_eq!(parse_account(&account_text(&n)), Some(n));
        }
        let g = Guardian::Secp256k1([7; 64]);
        assert_eq!(parse_guardian(&guardian_text(&g)), Some(g));
        let g = Guardian::Ethereum(EthAddress([1; 20]));
        assert_eq!(parse_guardian(&guardian_text(&g)), Some(g));
        for bad in [
            "",
            "0xabab",
            "ethereum:0xAB",
            &format!("ethereum:0x{}", "AB".repeat(20)),
            "near:A",
            "near:",
            "secp256k1:00",
            "solana:x",
        ] {
            assert_eq!(parse_account(bad), None, "{bad}");
            assert_eq!(parse_guardian(bad), None, "{bad}");
        }
    }
}
