//! Sending signed transactions from an ed25519 access key, and the account set-up a devnet or a
//! sandbox test needs (NEAR plan NH5): create a funded account with a full-access key, deploy and
//! initialise a contract, call any method.
//!
//! [`send_actions`] is the one place a transaction is built, signed and sent; the `wyec-near`
//! client ([`crate::WyecNear`]) sends its calls through it too. [`Admin`] is for set-up only (the
//! `near-admin` example, the sandbox integration test): the daemon never creates accounts or
//! deploys.

use hawkeye_core::AccountId;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::keys::KeyFile;
use crate::rpc::{NearRpc, TxOutcome};
use crate::tx::{Action, FunctionCall, TGAS, Transaction};

/// 1 NEAR in yoctoNEAR.
pub const NEAR: u128 = 1_000_000_000_000_000_000_000_000;

/// Build, sign and send `actions` from `key` to `receiver`, wait until `FINAL`.
///
/// The nonce is the access key's nonce at the final block, never below `*last` (the last nonce
/// this sender used), plus one; a refused nonce (`InvalidNonce`) is re-read and retried once.
/// `*last` is updated whenever the transaction may have used its nonce (success, or a final
/// failure), so the next one takes a higher nonce.
pub async fn send_actions(
    rpc: &NearRpc,
    key: &KeyFile,
    last: &mut Option<u64>,
    receiver: &AccountId,
    actions: Vec<Action>,
) -> Result<TxOutcome> {
    let mut retried = false;
    loop {
        let ak = rpc
            .access_key(key.account_id.as_str(), &key.public_key_text())
            .await?;
        let nonce = ak.nonce.max(last.unwrap_or(0)) + 1;
        let tx = Transaction {
            signer_id: key.account_id.clone(),
            public_key: key.public_key(),
            nonce,
            receiver_id: receiver.clone(),
            block_hash: ak.block_hash,
            actions: actions.clone(),
        };
        let signed = tx.sign(key.signing_key())?;
        match rpc.send_tx(&signed.borsh()).await {
            Ok(o) => {
                *last = Some(nonce);
                return Ok(o);
            }
            Err(e) if e.is_invalid_nonce() && !retried => {
                retried = true;
                *last = None;
            }
            Err(e) => {
                // final and failed (a panic), or not known to have landed: either way the next
                // transaction takes a higher nonce
                *last = Some(nonce);
                return Err(e);
            }
        }
    }
}

/// An account that sends set-up transactions (create accounts, deploy, call).
#[derive(Debug)]
pub struct Admin {
    rpc: NearRpc,
    key: KeyFile,
    last: tokio::sync::Mutex<Option<u64>>,
}

impl Admin {
    /// `key`'s account over the node at `rpc_url`.
    pub fn new(rpc_url: &str, key: KeyFile) -> Result<Self> {
        Ok(Self {
            rpc: NearRpc::new(rpc_url)?,
            key,
            last: tokio::sync::Mutex::new(None),
        })
    }

    /// The sending account.
    pub fn account_id(&self) -> &AccountId {
        &self.key.account_id
    }

    /// The RPC client.
    pub fn rpc(&self) -> &NearRpc {
        &self.rpc
    }

    /// Send `actions` to `receiver`.
    pub async fn send(&self, receiver: &AccountId, actions: Vec<Action>) -> Result<TxOutcome> {
        let mut last = self.last.lock().await;
        send_actions(&self.rpc, &self.key, &mut last, receiver, actions).await
    }

    /// Create `account` (a sub-account of this one, e.g. `alice.test.near` from `test.near`)
    /// holding `deposit` yoctoNEAR, with `public_key` as its full-access key.
    pub async fn create_account(
        &self,
        account: &AccountId,
        deposit: u128,
        public_key: [u8; 32],
    ) -> Result<TxOutcome> {
        self.send(
            account,
            vec![
                Action::CreateAccount,
                Action::Transfer { deposit },
                Action::AddFullAccessKey {
                    public_key,
                    nonce: 0,
                },
            ],
        )
        .await
    }

    /// Create `account` as [`create_account`](Self::create_account) with a fresh key and return
    /// its credentials. `seed` is the ed25519 seed (the caller's randomness).
    pub async fn create_account_with_seed(
        &self,
        account: &AccountId,
        deposit: u128,
        seed: &[u8; 32],
    ) -> Result<(KeyFile, TxOutcome)> {
        let key = KeyFile::from_seed(account.clone(), seed);
        let o = self
            .create_account(account, deposit, key.public_key())
            .await?;
        Ok((key, o))
    }

    /// Deploy `code` to this account and, with `init`, call `init.0(init.1)` in the same
    /// transaction (so nobody can initialise it first).
    pub async fn deploy(&self, code: Vec<u8>, init: Option<(&str, &Value)>) -> Result<TxOutcome> {
        let mut actions = vec![Action::DeployContract { code }];
        if let Some((method, args)) = init {
            actions.push(Action::FunctionCall(FunctionCall {
                method_name: method.to_owned(),
                args: serde_json::to_vec(args).expect("JSON"),
                gas: 100 * TGAS,
                deposit: 0,
            }));
        }
        let me = self.key.account_id.clone();
        self.send(&me, actions).await
    }

    /// Call `method(args)` of `contract` with `deposit` yoctoNEAR and `gas`.
    pub async fn call(
        &self,
        contract: &AccountId,
        method: &str,
        args: &Value,
        deposit: u128,
        gas: u64,
    ) -> Result<TxOutcome> {
        self.send(
            contract,
            vec![Action::FunctionCall(FunctionCall {
                method_name: method.to_owned(),
                args: serde_json::to_vec(args).expect("JSON"),
                gas,
                deposit,
            })],
        )
        .await
    }

    /// Send `deposit` yoctoNEAR to `to`.
    pub async fn transfer(&self, to: &AccountId, deposit: u128) -> Result<TxOutcome> {
        self.send(to, vec![Action::Transfer { deposit }]).await
    }
}

/// `n` NEAR (decimal, up to 24 places: `"2"`, `"0.5"`) in yoctoNEAR.
pub fn parse_near(n: &str) -> Result<u128> {
    let bad = || Error::Decode(format!("{n:?} is not a NEAR amount"));
    let (int, frac) = n.split_once('.').unwrap_or((n, ""));
    if int.is_empty() && frac.is_empty() || frac.len() > 24 {
        return Err(bad());
    }
    let digits = |s: &str| s.is_empty() || s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || !digits(frac) {
        return Err(bad());
    }
    let i: u128 = if int.is_empty() {
        0
    } else {
        int.parse().map_err(|_| bad())?
    };
    let f: u128 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<24}").parse().map_err(|_| bad())?
    };
    i.checked_mul(NEAR)
        .and_then(|x| x.checked_add(f))
        .ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_amounts() {
        assert_eq!(parse_near("2").unwrap(), 2 * NEAR);
        assert_eq!(parse_near("0.5").unwrap(), NEAR / 2);
        assert_eq!(parse_near(".000000000000000000000001").unwrap(), 1);
        for bad in ["", ".", "1.0000000000000000000000001", "-1", "1e3", "x"] {
            assert!(parse_near(bad).is_err(), "{bad}");
        }
    }
}
