//! A NEAR JSON-RPC client: the six methods Hawkeye uses.
//!
//! | Method | Use |
//! |---|---|
//! | `query` `call_function` | view calls at `finality: final`, or at a given block (the scanner) |
//! | `query` `view_access_key` | the relayer key's nonce |
//! | `block` | the final head (height, hash, time), a block's hash and parent |
//! | `EXPERIMENTAL_changes` `data_changes` | which receipts changed the contract's state in a block |
//! | `EXPERIMENTAL_receipt` | a receipt's function calls (method, arguments) |
//! | `send_tx` (`wait_until: FINAL`) | the relayer's transactions, returned once final |
//! | `status` | the earliest block the node keeps (a pruned height is never taken for a skipped one) |
//!
//! Hashes are base58 on the wire and `[u8; 32]` here. A contract panic (in a view or a
//! transaction) is [`Error::Panic`] with the contract's message; an unknown block (a skipped
//! height, or one the node no longer keeps) is an [`Error::Rpc`] whose
//! [`is_unknown_block`](Error::is_unknown_block) holds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};

use crate::error::{Error, Result, extract_panic, find_panic};

/// Which block a read is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRef {
    /// The latest final block (`finality: final`).
    Final,
    /// A block height.
    Height(u64),
    /// A block hash.
    Hash([u8; 32]),
}

impl BlockRef {
    fn params(self) -> Map<String, Value> {
        let mut m = Map::new();
        match self {
            BlockRef::Final => {
                m.insert("finality".into(), json!("final"));
            }
            BlockRef::Height(h) => {
                m.insert("block_id".into(), json!(h));
            }
            BlockRef::Hash(h) => {
                m.insert("block_id".into(), json!(b58(&h)));
            }
        }
        m
    }
}

/// A block header's fields Hawkeye reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// Height.
    pub height: u64,
    /// Hash.
    pub hash: [u8; 32],
    /// The parent's hash.
    pub prev_hash: [u8; 32],
    /// Unix nanoseconds.
    pub timestamp_ns: u64,
}

/// One state change of an account in a block (`data_update` / `data_deletion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChange {
    /// The receipt whose execution made it (`cause.type = receipt_processing`), if any.
    pub receipt: Option<[u8; 32]>,
    /// The storage key.
    pub key: Vec<u8>,
    /// A deletion (else an update).
    pub deleted: bool,
}

/// An account's state changes in one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockChanges {
    /// The block.
    pub block_hash: [u8; 32],
    /// The changes, in the node's order.
    pub changes: Vec<DataChange>,
}

/// A function call in a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptCall {
    /// The method.
    pub method_name: String,
    /// The raw arguments (JSON for `near-sdk`).
    pub args: Vec<u8>,
    /// yoctoNEAR attached.
    pub deposit: u128,
}

/// A receipt as `EXPERIMENTAL_receipt` prints it, reduced to its function calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptView {
    /// The receipt id.
    pub id: [u8; 32],
    /// Who sent it (the transaction's signer for a direct call).
    pub predecessor_id: String,
    /// Where it executes.
    pub receiver_id: String,
    /// Its `FunctionCall` actions, in order (other actions are left out).
    pub calls: Vec<ReceiptCall>,
}

/// A transaction that reached `FINAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutcome {
    /// The transaction hash.
    pub tx_hash: [u8; 32],
    /// The function call's return value (`SuccessValue`, decoded from base64).
    pub value: Vec<u8>,
    /// The block of the (first) receipt's execution, where the call took effect.
    pub receipt_block: [u8; 32],
    /// That receipt's id.
    pub receipt_id: Option<[u8; 32]>,
}

/// An access key's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessKey {
    /// Its nonce (the next transaction uses a higher one).
    pub nonce: u64,
    /// The block the answer is at (a recent hash for a transaction).
    pub block_hash: [u8; 32],
    /// That block's height.
    pub block_height: u64,
}

/// Base58 of a hash.
pub fn b58(h: &[u8]) -> String {
    bs58::encode(h).into_string()
}

/// A base58 hash.
pub fn hash_from_b58(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s)
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Decode(format!("{s:?} is not a base58 32-byte hash")))
}

fn field<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur
            .get(*p)
            .ok_or_else(|| Error::Decode(format!("missing {}", path.join("."))))?;
    }
    Ok(cur)
}

fn as_u64(v: &Value, what: &str) -> Result<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| Error::Decode(format!("{what} is not a u64: {v}")))
}

fn as_u128(v: &Value, what: &str) -> Result<u128> {
    match v {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| Error::Decode(format!("{what} is not a u128: {v}")))
}

fn as_str<'a>(v: &'a Value, what: &str) -> Result<&'a str> {
    v.as_str()
        .ok_or_else(|| Error::Decode(format!("{what} is not a string: {v}")))
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| Error::Decode(format!("{what}: base64: {e}")))
}

/// A JSON-RPC error object as an [`Error`]: a contract panic inside it becomes [`Error::Panic`].
pub fn rpc_error(e: &Value) -> Error {
    if let Some(p) = find_panic(e) {
        return Error::Panic(p);
    }
    let name = e
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("ERROR")
        .to_owned();
    let cause = e
        .get("cause")
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut message = e
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if let Some(d) = e.get("data") {
        let d = d
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| d.to_string());
        message = format!("{message}: {d}");
    }
    if let Some(info) = e.get("cause").and_then(|c| c.get("info")) {
        message = format!("{message} {info}");
    }
    Error::Rpc {
        name,
        cause,
        message,
        data: e.get("data").cloned(),
    }
}

/// A transaction's final `status` as the call's result: `SuccessValue` → its bytes; a
/// `Failure` → [`Error::Panic`] for a contract panic, else [`Error::TxFailed`].
pub fn outcome_status(status: &Value) -> Result<Vec<u8>> {
    if let Some(v) = status.get("SuccessValue") {
        return b64(v.as_str().unwrap_or(""), "SuccessValue");
    }
    if let Some(f) = status.get("Failure") {
        return Err(match find_panic(f) {
            Some(p) => Error::Panic(p),
            None => Error::TxFailed(f.to_string()),
        });
    }
    if status.get("SuccessReceiptId").is_some() {
        return Ok(vec![]);
    }
    Err(Error::Decode(format!("unknown status {status}")))
}

/// The JSON-RPC client.
#[derive(Debug)]
pub struct NearRpc {
    url: String,
    http: reqwest::Client,
    id: AtomicU64,
}

impl NearRpc {
    /// A client of the node at `url` (`http://127.0.0.1:3030`, `https://rpc.testnet.near.org`).
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(Self {
            url: url.into(),
            http,
            id: AtomicU64::new(1),
        })
    }

    /// The endpoint.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// One JSON-RPC call.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let body =
            json!({"jsonrpc": "2.0", "id": id.to_string(), "method": method, "params": params});
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(format!("{method}: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Http(format!("{method}: {e}")))?;
        let v: Value = serde_json::from_str(&text).map_err(|_| {
            Error::Http(format!(
                "{method}: HTTP {status}, not JSON: {:.200}",
                text.trim()
            ))
        })?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(rpc_error(e));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| Error::Decode(format!("{method}: no result")))
    }

    /// A view call: `method(args)` of `account` at `block`, its JSON result.
    pub async fn view(
        &self,
        block: BlockRef,
        account: &str,
        method: &str,
        args: &Value,
    ) -> Result<Value> {
        let mut p = block.params();
        p.insert("request_type".into(), json!("call_function"));
        p.insert("account_id".into(), json!(account));
        p.insert("method_name".into(), json!(method));
        p.insert(
            "args_base64".into(),
            json!(B64.encode(serde_json::to_vec(args).expect("JSON"))),
        );
        let r = self.call("query", Value::Object(p)).await?;
        // nodes before 1.x answered a failed view as a result with an `error` string
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            return Err(match extract_panic(e) {
                Some(p) => Error::Panic(p),
                None => Error::Rpc {
                    name: "QUERY_ERROR".into(),
                    cause: None,
                    message: e.to_owned(),
                    data: None,
                },
            });
        }
        let bytes: Vec<u8> = serde_json::from_value(field(&r, &["result"])?.clone())
            .map_err(|e| Error::Decode(format!("{method}: result bytes: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            Error::Decode(format!(
                "{method}: result is not JSON ({e}): {:.200}",
                String::from_utf8_lossy(&bytes)
            ))
        })
    }

    /// A block's header.
    pub async fn block(&self, block: BlockRef) -> Result<BlockHeader> {
        let r = self.call("block", Value::Object(block.params())).await?;
        let h = field(&r, &["header"])?;
        let timestamp_ns = match h.get("timestamp_nanosec") {
            Some(t) => as_u64(t, "timestamp_nanosec")?,
            None => as_u64(field(h, &["timestamp"])?, "timestamp")?,
        };
        Ok(BlockHeader {
            height: as_u64(field(h, &["height"])?, "height")?,
            hash: hash_from_b58(as_str(field(h, &["hash"])?, "hash")?)?,
            prev_hash: hash_from_b58(as_str(field(h, &["prev_hash"])?, "prev_hash")?)?,
            timestamp_ns,
        })
    }

    /// The lowest block height the node still keeps (`status` → `sync_info
    /// .earliest_block_height`): below it a non-archival node has garbage-collected the blocks.
    pub async fn earliest_block_height(&self) -> Result<u64> {
        let r = self.call("status", json!([])).await?;
        as_u64(
            field(&r, &["sync_info", "earliest_block_height"])?,
            "earliest_block_height",
        )
    }

    /// The state changes of `account` in block `height` (`None`: the node has no such block).
    pub async fn data_changes(&self, height: u64, account: &str) -> Result<Option<BlockChanges>> {
        let r = match self
            .call(
                "EXPERIMENTAL_changes",
                json!({"changes_type": "data_changes", "account_ids": [account],
                       "key_prefix_base64": "", "block_id": height}),
            )
            .await
        {
            Ok(r) => r,
            Err(e) if e.is_unknown_block() => return Ok(None),
            Err(e) => return Err(e),
        };
        let block_hash = hash_from_b58(as_str(field(&r, &["block_hash"])?, "block_hash")?)?;
        let mut changes = vec![];
        for c in field(&r, &["changes"])?
            .as_array()
            .ok_or_else(|| Error::Decode("changes is not an array".into()))?
        {
            let receipt = match c.get("cause").and_then(|c| c.get("receipt_hash")) {
                Some(h) => Some(hash_from_b58(as_str(h, "receipt_hash")?)?),
                None => None,
            };
            let kind = as_str(field(c, &["type"])?, "type")?;
            let key = b64(
                as_str(field(c, &["change", "key_base64"])?, "key_base64")?,
                "key",
            )?;
            changes.push(DataChange {
                receipt,
                key,
                deleted: kind == "data_deletion",
            });
        }
        Ok(Some(BlockChanges {
            block_hash,
            changes,
        }))
    }

    /// A receipt's function calls.
    pub async fn receipt(&self, id: &[u8; 32]) -> Result<ReceiptView> {
        let r = self
            .call("EXPERIMENTAL_receipt", json!({"receipt_id": b58(id)}))
            .await?;
        let mut calls = vec![];
        if let Some(actions) = r
            .get("receipt")
            .and_then(|x| x.get("Action"))
            .and_then(|x| x.get("actions"))
            .and_then(Value::as_array)
        {
            for a in actions {
                if let Some(f) = a.get("FunctionCall") {
                    calls.push(ReceiptCall {
                        method_name: as_str(field(f, &["method_name"])?, "method_name")?.to_owned(),
                        args: b64(as_str(field(f, &["args"])?, "args")?, "args")?,
                        deposit: as_u128(field(f, &["deposit"])?, "deposit")?,
                    });
                }
            }
        }
        Ok(ReceiptView {
            id: *id,
            predecessor_id: as_str(field(&r, &["predecessor_id"])?, "predecessor_id")?.to_owned(),
            receiver_id: as_str(field(&r, &["receiver_id"])?, "receiver_id")?.to_owned(),
            calls,
        })
    }

    /// An access key's nonce, at the final block.
    pub async fn access_key(&self, account: &str, public_key: &str) -> Result<AccessKey> {
        let r = self
            .call(
                "query",
                json!({"request_type": "view_access_key", "finality": "final",
                       "account_id": account, "public_key": public_key}),
            )
            .await?;
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            return Err(Error::Rpc {
                name: "QUERY_ERROR".into(),
                cause: Some("UNKNOWN_ACCESS_KEY".into()),
                message: e.to_owned(),
                data: None,
            });
        }
        Ok(AccessKey {
            nonce: as_u64(field(&r, &["nonce"])?, "nonce")?,
            block_hash: hash_from_b58(as_str(field(&r, &["block_hash"])?, "block_hash")?)?,
            block_height: as_u64(field(&r, &["block_height"])?, "block_height")?,
        })
    }

    /// Send a signed transaction (`borsh(SignedTransaction)`) and wait until it is final. A
    /// panic or a failed action is an error; the transaction is then final and failed.
    pub async fn send_tx(&self, signed: &[u8]) -> Result<TxOutcome> {
        let r = self
            .call(
                "send_tx",
                json!({"signed_tx_base64": B64.encode(signed), "wait_until": "FINAL"}),
            )
            .await?;
        let tx_hash = hash_from_b58(as_str(field(&r, &["transaction", "hash"])?, "hash")?)?;
        let value = outcome_status(field(&r, &["status"])?)?;
        let first = r
            .get("receipts_outcome")
            .and_then(Value::as_array)
            .and_then(|a| a.first());
        let (receipt_block, receipt_id) = match first {
            Some(o) => (
                hash_from_b58(as_str(field(o, &["block_hash"])?, "block_hash")?)?,
                Some(hash_from_b58(as_str(field(o, &["id"])?, "id")?)?),
            ),
            None => (
                hash_from_b58(as_str(
                    field(&r, &["transaction_outcome", "block_hash"])?,
                    "block_hash",
                )?)?,
                None,
            ),
        };
        Ok(TxOutcome {
            tx_hash,
            value,
            receipt_block,
            receipt_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_and_statuses_map() {
        // a view panic in nearcore 2.x's error shape
        let e = json!({"name": "HANDLER_ERROR", "cause": {"name": "CONTRACT_EXECUTION_ERROR",
            "info": {"vm_error": "wasm execution failed with error: FunctionCallError(ExecutionError(\"Smart contract panicked: wyec: lock_id must be 32 bytes of hex\"))"}},
            "code": -32000, "message": "Server error", "data": "…"});
        match rpc_error(&e) {
            Error::Panic(p) => assert_eq!(p, "wyec: lock_id must be 32 bytes of hex"),
            other => panic!("{other:?}"),
        }
        let e = json!({"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_BLOCK", "info": {}},
            "message": "Server error", "data": "DB Not Found Error: BLOCK HEIGHT: 7"});
        assert!(rpc_error(&e).is_unknown_block());
        // a final failed call, a success, a non-panic failure
        let f = json!({"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError":
            {"ExecutionError": "Smart contract panicked: wyec: proposal pending"}}}}});
        let err = outcome_status(&f).unwrap_err();
        assert_eq!(err.revert_name(), Some("ProposalPending"));
        assert_eq!(
            outcome_status(&json!({"SuccessValue": "Mw=="})).unwrap(),
            b"3"
        );
        assert_eq!(outcome_status(&json!({"SuccessValue": ""})).unwrap(), b"");
        let gas = json!({"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError":
            {"ExecutionError": "Exceeded the prepaid gas."}}}}});
        assert!(matches!(outcome_status(&gas), Err(Error::TxFailed(_))));
        assert!(outcome_status(&json!({"Unknown": 1})).is_err());
    }

    #[test]
    fn hashes_and_block_refs() {
        let h = [7u8; 32];
        assert_eq!(hash_from_b58(&b58(&h)).unwrap(), h);
        assert!(hash_from_b58("0OIl").is_err());
        assert!(hash_from_b58(&b58(&[1; 31])).is_err());
        assert_eq!(
            Value::Object(BlockRef::Final.params()),
            json!({"finality": "final"})
        );
        assert_eq!(
            Value::Object(BlockRef::Height(9).params()),
            json!({"block_id": 9})
        );
        assert_eq!(
            Value::Object(BlockRef::Hash(h).params()),
            json!({"block_id": b58(&h)})
        );
    }
}
