//! The async JSON-RPC client.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::amount::Amount;
use crate::error::{Error, RpcError};
use crate::primitives::{BlockHash, HexBytes, OutPoint, PubKey, SetId, Txid};
use crate::stock::{
    BlockSummary, BlockWithTxs, BlockchainInfo, PrevTx, SignRawResult, TxInfo, Unspent,
    ValidateAddress,
};
use crate::types::*;

/// How the client authenticates (`-rpcuser`/`-rpcpassword`, or the cookie the node writes).
#[derive(Clone, Debug)]
pub enum Auth {
    None,
    UserPass {
        user: String,
        password: String,
    },
    /// `<datadir>/.cookie` (mainnet) or `<datadir>/<network dir>/.cookie`; read on every call,
    /// so a restarted node's new cookie is picked up.
    CookieFile(PathBuf),
}

impl Auth {
    /// The cookie path for a data directory and a network: `main`, `test` (`testnet3/`) or
    /// `regtest` (`regtest/`), as `getblockchaininfo.chain` names them.
    pub fn cookie(datadir: impl AsRef<Path>, chain: &str) -> Self {
        let d = datadir.as_ref();
        let p = match chain {
            "main" | "mainnet" => d.join(".cookie"),
            "test" | "testnet" => d.join("testnet3").join(".cookie"),
            other => d.join(other).join(".cookie"),
        };
        Auth::CookieFile(p)
    }

    async fn header(&self) -> Result<Option<String>, Error> {
        let creds = match self {
            Auth::None => return Ok(None),
            Auth::UserPass { user, password } => format!("{user}:{password}"),
            Auth::CookieFile(p) => tokio::fs::read_to_string(p)
                .await
                .map_err(|source| Error::Cookie {
                    path: p.display().to_string(),
                    source,
                })?
                .trim()
                .to_owned(),
        };
        Ok(Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        )))
    }
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Option<ErrorObject>,
}

#[derive(Deserialize)]
struct ErrorObject {
    code: i64,
    #[serde(default)]
    message: String,
}

/// A typed client for one `ycashd`.
#[derive(Debug)]
pub struct YcashRpc {
    http: reqwest::Client,
    url: String,
    auth: Auth,
    next_id: AtomicU64,
}

/// Parameters with optional trailing ones: `None`s at the end are dropped (the node counts
/// parameters), `None`s in the middle become `null` (which every RPC here treats as absent).
fn params(list: Vec<Option<Value>>) -> Vec<Value> {
    let mut v: Vec<Value> = list.into_iter().map(|p| p.unwrap_or(Value::Null)).collect();
    while v.last() == Some(&Value::Null) {
        v.pop();
    }
    v
}

fn val<T: serde::Serialize>(method: &str, t: T) -> Result<Value, Error> {
    serde_json::to_value(t).map_err(|source| Error::Request {
        method: method.to_owned(),
        source,
    })
}

impl YcashRpc {
    /// A client for `url` (e.g. `http://127.0.0.1:18232/`), with a 120 s request timeout.
    pub fn new(url: impl Into<String>, auth: Auth) -> Result<Self, Error> {
        Self::with_timeout(url, auth, Duration::from_secs(120))
    }

    pub fn with_timeout(
        url: impl Into<String>,
        auth: Auth,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let http = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(YcashRpc {
            http,
            url: url.into(),
            auth,
            next_id: AtomicU64::new(1),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Call `method` and return its `result` as JSON, decimals kept as strings
    /// ([`crate::json`]).
    pub async fn call_value(&self, method: &str, params: Vec<Value>) -> Result<Value, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_string(
            &json!({"jsonrpc": "1.0", "id": id, "method": method, "params": params}),
        )
        .map_err(|source| Error::Request {
            method: method.to_owned(),
            source,
        })?;
        let mut req = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(h) = self.auth.header().await? {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        // The node answers errors with HTTP 500 (404 for an unknown method) and a JSON-RPC body.
        let parsed: Response = match crate::json::from_str(&text) {
            Ok(r) => r,
            Err(source) => {
                if status.is_success() {
                    return Err(Error::Decode {
                        method: method.to_owned(),
                        source,
                        body: truncate(&text),
                    });
                }
                return Err(Error::Status {
                    status: status.as_u16(),
                    body: truncate(&text),
                });
            }
        };
        if let Some(e) = parsed.error {
            return Err(RpcError::new(method, e.code, e.message).into());
        }
        if !status.is_success() {
            return Err(Error::Status {
                status: status.as_u16(),
                body: truncate(&text),
            });
        }
        Ok(parsed.result)
    }

    /// Call `method` and deserialize its result into `T`.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, Error> {
        let v = self.call_value(method, params).await?;
        serde_json::from_value::<T>(v.clone()).map_err(|source| Error::Decode {
            method: method.to_owned(),
            source,
            body: truncate(&v.to_string()),
        })
    }

    // ------------------------------------------------------------------ vault: read RPCs

    pub async fn vault_getinfo(&self) -> Result<VaultInfo, Error> {
        self.call("vault_getinfo", vec![]).await
    }

    pub async fn set_list(&self) -> Result<Vec<Set>, Error> {
        self.call("set_list", vec![]).await
    }

    /// Predicates at `height` (default: the next block). Error -5 `unknown set`.
    pub async fn set_getinfo(&self, setid: &SetId, height: Option<u32>) -> Result<SetInfo, Error> {
        let m = "set_getinfo";
        self.call(
            m,
            params(vec![Some(val(m, setid)?), height.map(Value::from)]),
        )
        .await
    }

    pub async fn vault_list(
        &self,
        filter: Option<&VaultListFilter>,
    ) -> Result<Vec<TemplateOut>, Error> {
        let m = "vault_list";
        self.call(m, params(vec![filter.map(|f| val(m, f)).transpose()?]))
            .await
    }

    pub async fn vault_decodescript(&self, script: &HexBytes) -> Result<DecodedScript, Error> {
        let m = "vault_decodescript";
        self.call(m, vec![val(m, script)?]).await
    }

    // ------------------------------------------------------------------ act RPCs

    pub async fn set_create(&self, p: &SetCreateParams) -> Result<SetCreateResult, Error> {
        let m = "set_create";
        self.call(m, vec![val(m, p)?]).await
    }

    pub async fn set_join(
        &self,
        setid: &SetId,
        bondamount: Amount,
        bondlocktime: u32,
        memberkey: Option<&PubKey>,
    ) -> Result<SetJoinResult, Error> {
        let m = "set_join";
        let ps = vec![
            Some(val(m, setid)?),
            Some(val(m, bondamount)?),
            Some(bondlocktime.into()),
            memberkey.map(|k| val(m, k)).transpose()?,
        ];
        self.call(m, params(ps)).await
    }

    pub async fn set_heartbeat(
        &self,
        setid: &SetId,
        memberkey: Option<&PubKey>,
    ) -> Result<HeartbeatResult, Error> {
        let m = "set_heartbeat";
        self.call(
            m,
            params(vec![
                Some(val(m, setid)?),
                memberkey.map(|k| val(m, k)).transpose()?,
            ]),
        )
        .await
    }

    pub async fn set_buildact(&self, act: &BuildAct) -> Result<ActResult, Error> {
        let m = "set_buildact";
        let p = act.params().map_err(|source| Error::Request {
            method: m.to_owned(),
            source,
        })?;
        self.call(m, vec![act.act_type().as_str().into(), p]).await
    }

    pub async fn set_signact(
        &self,
        hex: &HexBytes,
        setid: Option<&SetId>,
    ) -> Result<ActResult, Error> {
        let m = "set_signact";
        self.call(
            m,
            params(vec![
                Some(val(m, hex)?),
                setid.map(|s| val(m, s)).transpose()?,
            ]),
        )
        .await
    }

    pub async fn set_sendact(&self, hex: &HexBytes) -> Result<Txid, Error> {
        let m = "set_sendact";
        self.call(m, vec![val(m, hex)?]).await
    }

    pub async fn set_equivocation(&self, proof: &Proof) -> Result<Txid, Error> {
        let m = "set_equivocation";
        self.call(m, vec![val(m, proof)?]).await
    }

    // ------------------------------------------------------------------ vault RPCs

    pub async fn vault_lock(&self, p: &VaultLockParams) -> Result<VaultLockResult, Error> {
        let m = "vault_lock";
        self.call(m, vec![val(m, p)?]).await
    }

    /// The unsigned UNLOCK spend. Hawkeye inserts its memo here ([`crate::tx::insert_op_return`])
    /// before any `set_signunlock`.
    pub async fn vault_buildunlock(
        &self,
        vault: &OutPoint,
        recipients: &[Recipient],
    ) -> Result<BuildUnlockResult, Error> {
        let m = "vault_buildunlock";
        self.call(m, vec![val(m, vault)?, val(m, recipients)?])
            .await
    }

    /// Adds this wallet's unlock signatures. **Sign once**: a different spend of the same vault
    /// is refused with `set-sign-once` ([`RpcError::is_set_sign_once`]).
    pub async fn set_signunlock(&self, hex: &HexBytes) -> Result<SetSigResult, Error> {
        let m = "set_signunlock";
        self.call(m, vec![val(m, hex)?]).await
    }

    pub async fn vault_buildcancel(&self, intent: &OutPoint) -> Result<BuildCancelResult, Error> {
        let m = "vault_buildcancel";
        self.call(m, vec![val(m, intent)?]).await
    }

    pub async fn set_signcancel(&self, hex: &HexBytes) -> Result<SetSigResult, Error> {
        let m = "set_signcancel";
        self.call(m, vec![val(m, hex)?]).await
    }

    pub async fn vault_send(&self, hex: &HexBytes) -> Result<Txid, Error> {
        let m = "vault_send";
        self.call(m, vec![val(m, hex)?]).await
    }

    /// `recipient`: an address or a script in hex. Error -1 `matures at height h` before the delay.
    pub async fn vault_release(
        &self,
        intent: &OutPoint,
        recipient: Option<&str>,
    ) -> Result<Txid, Error> {
        let m = "vault_release";
        self.call(
            m,
            params(vec![Some(val(m, intent)?), recipient.map(Value::from)]),
        )
        .await
    }

    pub async fn vault_ownerspend(
        &self,
        outpoint: &OutPoint,
        address: &str,
    ) -> Result<OwnerSpendResult, Error> {
        let m = "vault_ownerspend";
        self.call(m, vec![val(m, outpoint)?, address.into()]).await
    }

    pub async fn vault_app(
        &self,
        vault: &OutPoint,
        recipients: Option<&[Recipient]>,
    ) -> Result<AppResult, Error> {
        let m = "vault_app";
        self.call(
            m,
            params(vec![
                Some(val(m, vault)?),
                recipients.map(|r| val(m, r)).transpose()?,
            ]),
        )
        .await
    }

    // ------------------------------------------------------------------ stock RPCs

    pub async fn getblockchaininfo(&self) -> Result<BlockchainInfo, Error> {
        self.call("getblockchaininfo", vec![]).await
    }

    pub async fn getblockcount(&self) -> Result<u32, Error> {
        self.call("getblockcount", vec![]).await
    }

    pub async fn getbestblockhash(&self) -> Result<BlockHash, Error> {
        self.call("getbestblockhash", vec![]).await
    }

    pub async fn getblockhash(&self, height: u32) -> Result<BlockHash, Error> {
        self.call("getblockhash", vec![height.into()]).await
    }

    /// `getblock <hash> 1`: the header fields and the txids.
    pub async fn getblock(&self, hash: &BlockHash) -> Result<BlockSummary, Error> {
        let m = "getblock";
        self.call(m, vec![val(m, hash)?, 1.into()]).await
    }

    /// `getblock <hash> 2`: every transaction decoded, with its `hex`.
    pub async fn getblock_txs(&self, hash: &BlockHash) -> Result<BlockWithTxs, Error> {
        let m = "getblock";
        self.call(m, vec![val(m, hash)?, 2.into()]).await
    }

    /// `getblock <hash> 0`: the serialized block.
    pub async fn getblock_hex(&self, hash: &BlockHash) -> Result<HexBytes, Error> {
        let m = "getblock";
        self.call(m, vec![val(m, hash)?, 0.into()]).await
    }

    /// `getrawtransaction <txid> 0` (mempool, or the chain with `-txindex`).
    pub async fn getrawtransaction(&self, txid: &Txid) -> Result<HexBytes, Error> {
        let m = "getrawtransaction";
        self.call(m, vec![val(m, txid)?, 0.into()]).await
    }

    /// `getrawtransaction <txid> 1 ( blockhash )`. `verbose` is numeric on this node.
    pub async fn getrawtransaction_verbose(
        &self,
        txid: &Txid,
        block: Option<&BlockHash>,
    ) -> Result<TxInfo, Error> {
        let m = "getrawtransaction";
        self.call(
            m,
            params(vec![
                Some(val(m, txid)?),
                Some(1.into()),
                block.map(|b| val(m, b)).transpose()?,
            ]),
        )
        .await
    }

    pub async fn getrawmempool(&self) -> Result<Vec<Txid>, Error> {
        self.call("getrawmempool", vec![false.into()]).await
    }

    pub async fn decoderawtransaction(&self, hex: &HexBytes) -> Result<TxInfo, Error> {
        let m = "decoderawtransaction";
        self.call(m, vec![val(m, hex)?]).await
    }

    pub async fn sendrawtransaction(
        &self,
        hex: &HexBytes,
        allow_high_fees: bool,
    ) -> Result<Txid, Error> {
        let m = "sendrawtransaction";
        self.call(
            m,
            params(vec![
                Some(val(m, hex)?),
                allow_high_fees.then_some(Value::Bool(true)),
            ]),
        )
        .await
    }

    /// `signrawtransaction "hex" ( prevtxs privkeys sighashtype branchid )`.
    pub async fn signrawtransaction(
        &self,
        hex: &HexBytes,
        prevtxs: Option<&[PrevTx]>,
        privkeys: Option<&[String]>,
        sighashtype: Option<&str>,
        branchid: Option<&str>,
    ) -> Result<SignRawResult, Error> {
        let m = "signrawtransaction";
        let ps = vec![
            Some(val(m, hex)?),
            prevtxs.map(|p| val(m, p)).transpose()?,
            privkeys.map(|p| val(m, p)).transpose()?,
            sighashtype.map(Value::from),
            branchid.map(Value::from),
        ];
        self.call(m, params(ps)).await
    }

    pub async fn validateaddress(&self, address: &str) -> Result<ValidateAddress, Error> {
        self.call("validateaddress", vec![address.into()]).await
    }

    pub async fn getnewaddress(&self) -> Result<String, Error> {
        self.call("getnewaddress", vec![]).await
    }

    /// `importprivkey "wif" ( "label" rescan )`; returns the key's address. Hawkeye enrols with
    /// `rescan = false` (plan §3.5).
    pub async fn importprivkey(
        &self,
        wif: &str,
        label: &str,
        rescan: bool,
    ) -> Result<String, Error> {
        self.call(
            "importprivkey",
            vec![wif.into(), label.into(), rescan.into()],
        )
        .await
    }

    /// `listunspent ( minconf maxconf ["address",...] )`.
    pub async fn listunspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<&[String]>,
    ) -> Result<Vec<Unspent>, Error> {
        let m = "listunspent";
        let ps = vec![
            minconf.map(Value::from),
            maxconf.map(Value::from),
            addresses.map(|a| val(m, a)).transpose()?,
        ];
        self.call(m, params(ps)).await
    }

    /// Regtest only: mine `n` blocks to the wallet.
    pub async fn generate(&self, n: u32) -> Result<Vec<BlockHash>, Error> {
        self.call("generate", vec![n.into()]).await
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 2000;
    if s.len() <= MAX {
        return s.to_owned();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes)", &s[..end], s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_none_dropped() {
        assert_eq!(
            params(vec![Some(1.into()), None, None]),
            vec![Value::from(1)]
        );
        assert_eq!(
            params(vec![Some(1.into()), None, Some(2.into())]),
            vec![Value::from(1), Value::Null, Value::from(2)]
        );
        assert!(params(vec![None]).is_empty());
    }

    #[test]
    fn cookie_paths() {
        let p = |c| match Auth::cookie("/d", c) {
            Auth::CookieFile(p) => p,
            _ => unreachable!(),
        };
        assert_eq!(p("main"), PathBuf::from("/d/.cookie"));
        assert_eq!(p("test"), PathBuf::from("/d/testnet3/.cookie"));
        assert_eq!(p("regtest"), PathBuf::from("/d/regtest/.cookie"));
    }
}
