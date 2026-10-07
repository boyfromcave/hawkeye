//! Conversions between the adapters' types and `hawkeye-core`'s.

use anyhow::{Result, anyhow};
use hawkeye_core::policy::TxOut as CoreTxOut;
use hawkeye_core::{IntentParams, OutPoint as CoreOutPoint, VaultParams};
use hawkeye_eth::{Address, B256};
use hawkeye_ycash::types::{IntentFields, VaultFields};
use hawkeye_ycash::{Hash256, OutPoint as RpcOutPoint};

/// RPC outpoint → core outpoint (both internal order).
pub fn op_core(o: &RpcOutPoint) -> CoreOutPoint {
    CoreOutPoint::new(o.txid.0, o.vout)
}

/// Core outpoint → RPC outpoint.
pub fn op_rpc(o: &CoreOutPoint) -> RpcOutPoint {
    RpcOutPoint::new(Hash256::from_internal(o.txid), o.vout)
}

/// The outputs of a decoded transaction as the policy and matcher take them.
pub fn outputs(tx: &hawkeye_ycash::tx::Transaction) -> Vec<CoreTxOut> {
    tx.outputs
        .iter()
        .map(|o| CoreTxOut {
            value: u64::try_from(o.value).unwrap_or(0),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect()
}

fn tag4(tag: &[u8]) -> Result<[u8; 4]> {
    tag.try_into()
        .map_err(|_| anyhow!("tag is {} bytes, not 4", tag.len()))
}

/// An intent's fields as the node prints them → core parameters.
pub fn intent_params(f: &IntentFields) -> Result<IntentParams> {
    Ok(IntentParams {
        tag: tag4(&f.tag.0)?,
        recipient_hash: f.recipienthash.0,
        vault_hash: f.vaulthash.0,
        delay: u16::try_from(f.delay).map_err(|_| anyhow!("delay out of range"))?,
        cancel_set_id: f.cancelsetid.0,
        set_id: f.setid.0,
        owner_key: f.ownerkey.0,
    })
}

/// A vault's fields as the node prints them → core parameters.
pub fn vault_params(f: &VaultFields) -> Result<VaultParams> {
    Ok(VaultParams {
        tag: tag4(&f.tag.0)?,
        set_id: f.setid.0,
        cancel_set_id: f.cancelsetid.0,
        delay: u16::try_from(f.delay).map_err(|_| anyhow!("delay out of range"))?,
        owner_height: f.ownerheight,
        app_height: f.appheight,
        owner_key: f.ownerkey.0,
    })
}

/// A core Ethereum address → alloy.
pub fn addr(a: &hawkeye_core::EthAddress) -> Address {
    Address::from(a.0)
}

/// An alloy address → core.
pub fn eth_addr(a: &Address) -> hawkeye_core::EthAddress {
    hawkeye_core::EthAddress(a.0.0)
}

/// 32 bytes → `B256`.
pub fn b256(h: &[u8; 32]) -> B256 {
    B256::from(*h)
}
