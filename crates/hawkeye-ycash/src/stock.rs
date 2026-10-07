//! Shapes of the stock RPCs Hawkeye calls, as ycash-dd v4.5.0 (`upgrade/vault`) prints them
//! (`src/rpc/blockchain.cpp`, `src/rpc/rawtransaction.cpp`, `src/rpc/misc.cpp`,
//! `src/wallet/rpcwallet.cpp`). Fields Hawkeye does not use are ignored on read.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::amount::{Amount, lenient_f64};
use crate::primitives::{BlockHash, Hash256, HexBytes, Txid};

/// `getblockchaininfo` (`src/rpc/blockchain.cpp:1132`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockchainInfo {
    /// `main`, `test` or `regtest`.
    pub chain: String,
    pub blocks: u32,
    pub headers: i64,
    pub bestblockhash: BlockHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_block_download_complete: Option<bool>,
    #[serde(with = "lenient_f64")]
    pub difficulty: f64,
    #[serde(with = "lenient_f64")]
    pub verificationprogress: f64,
    pub chainwork: String,
    pub pruned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimatedheight: Option<i64>,
    /// Scheduled network upgrades keyed by branch id hex (`"6d5b7a31"` for `UPGRADE_VAULT`).
    #[serde(default)]
    pub upgrades: BTreeMap<String, UpgradeInfo>,
    pub consensus: ConsensusBranches,
}

/// A `getblockchaininfo.upgrades` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeInfo {
    pub name: String,
    pub activationheight: i64,
    /// `disabled`, `pending` or `active`.
    pub status: String,
    #[serde(default)]
    pub info: String,
}

/// `getblockchaininfo.consensus`: branch ids (hex) of the tip and the next block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusBranches {
    pub chaintip: String,
    pub nextblock: String,
}

/// `getblock` verbosity 1 (`tx` = txids) and 2 (`tx` = [`TxInfo`]), `src/rpc/blockchain.cpp:229`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Block<T> {
    pub hash: BlockHash,
    /// -1 when the block is not on the active chain.
    pub confirmations: i64,
    pub size: u64,
    pub height: u32,
    pub version: i64,
    pub merkleroot: Hash256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalsaplingroot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chainhistoryroot: Option<String>,
    pub tx: Vec<T>,
    pub time: i64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    pub bits: String,
    #[serde(with = "lenient_f64")]
    pub difficulty: f64,
    pub chainwork: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previousblockhash: Option<BlockHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nextblockhash: Option<BlockHash>,
}

/// A `getblock` verbosity-1 block.
pub type BlockSummary = Block<Txid>;
/// A `getblock` verbosity-2 block.
pub type BlockWithTxs = Block<TxInfo>;

/// `scriptSig` of a non-coinbase input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: HexBytes,
}

/// A `vin` entry of a decoded transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInInfo {
    /// The coinbase scriptSig (coinbase inputs only; then `txid`/`vout`/`scriptSig` are absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<Txid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vout: Option<u32>,
    #[serde(default, rename = "scriptSig", skip_serializing_if = "Option::is_none")]
    pub script_sig: Option<ScriptSig>,
    /// With `-spentindex` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Amount>,
    #[serde(default, rename = "valueSat", skip_serializing_if = "Option::is_none")]
    pub value_sat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub sequence: u32,
}

/// `scriptPubKey` of an output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptPubKeyInfo {
    pub asm: String,
    pub hex: HexBytes,
    #[serde(default, rename = "reqSigs", skip_serializing_if = "Option::is_none")]
    pub req_sigs: Option<u32>,
    /// `pubkeyhash`, `scripthash`, `nulldata`, `nonstandard`, …
    #[serde(rename = "type")]
    pub script_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
}

/// A `vout` entry of a decoded transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutInfo {
    pub value: Amount,
    #[serde(rename = "valueZat")]
    pub value_zat: i64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKeyInfo,
}

/// `getrawtransaction <txid> 1`, `decoderawtransaction`, and `getblock <h> 2`'s `tx[]`
/// (`TxToJSON`, `src/rpc/rawtransaction.cpp:159`). Shielded descriptions are kept as JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TxInfo {
    pub txid: Txid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub overwintered: bool,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versiongroupid: Option<String>,
    pub locktime: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiryheight: Option<u32>,
    /// The raw transaction (always present in this node's `TxToJSON`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<HexBytes>,
    pub vin: Vec<TxInInfo>,
    pub vout: Vec<TxOutInfo>,
    #[serde(default)]
    pub vjoinsplit: Vec<serde_json::Value>,
    #[serde(
        default,
        rename = "valueBalance",
        skip_serializing_if = "Option::is_none"
    )]
    pub value_balance: Option<Amount>,
    #[serde(
        default,
        rename = "valueBalanceZat",
        skip_serializing_if = "Option::is_none"
    )]
    pub value_balance_zat: Option<i64>,
    #[serde(
        default,
        rename = "vShieldedSpend",
        skip_serializing_if = "Option::is_none"
    )]
    pub v_shielded_spend: Option<Vec<serde_json::Value>>,
    #[serde(
        default,
        rename = "vShieldedOutput",
        skip_serializing_if = "Option::is_none"
    )]
    pub v_shielded_output: Option<Vec<serde_json::Value>>,
    /// The block (with `getrawtransaction` of a confirmed transaction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<BlockHash>,
    /// -1 when the block is not on the active chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<i64>,
}

impl TxInfo {
    /// Decode `hex` with the crate's codec.
    pub fn decode(&self) -> Option<Result<crate::tx::Transaction, crate::tx::CodecError>> {
        self.hex
            .as_ref()
            .map(|h| crate::tx::Transaction::decode(h.as_slice()))
    }
}

/// `signrawtransaction`'s `prevtxs` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevTx {
    pub txid: Txid,
    pub vout: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: HexBytes,
    #[serde(
        default,
        rename = "redeemScript",
        skip_serializing_if = "Option::is_none"
    )]
    pub redeem_script: Option<HexBytes>,
    pub amount: Amount,
}

/// `signrawtransaction`'s result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRawResult {
    pub hex: HexBytes,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<SignRawError>,
}

/// A script verification error of `signrawtransaction`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRawError {
    pub txid: Txid,
    pub vout: u32,
    #[serde(rename = "scriptSig")]
    pub script_sig: HexBytes,
    pub sequence: u32,
    pub error: String,
}

/// `validateaddress` (transparent addresses; `src/rpc/misc.cpp:194`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidateAddress {
    pub isvalid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(
        default,
        rename = "scriptPubKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub script_pub_key: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ismine: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iswatchonly: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isscript: Option<bool>,
    /// The key of a wallet P2PKH address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iscompressed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// A `listunspent` row (`src/wallet/rpcwallet.cpp:2532`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unspent {
    pub txid: Txid,
    pub vout: u32,
    pub generated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(
        default,
        rename = "redeemScript",
        skip_serializing_if = "Option::is_none"
    )]
    pub redeem_script: Option<HexBytes>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: HexBytes,
    pub amount: Amount,
    #[serde(rename = "amountZat")]
    pub amount_zat: i64,
    pub confirmations: i64,
    pub spendable: bool,
}
