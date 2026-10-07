//! The finalized-block event scanner (plan §1.3, §5.3 step 2, §5.4).
//!
//! Hawkeye acts only on burns in **finalized** Ethereum blocks. The scanner reads the bridge's logs
//! in `[from, finalized]` in chunks with `eth_getLogs`, decodes `BurnToYcash`, `Minted`,
//! `GuardiansChanged`, `Paused`/`Unpaused` and the CR-W1 double's `MintProposed`/`MintChallenged`,
//! and returns them in chain order with their position.
//!
//! "Finalized" is the node's `finalized` tag. A node without one (some dev chains and L2s answer
//! the tag with an error or nothing) falls back to `latest − fallback_depth` when a fallback is
//! configured; [`Finality::Depth`] uses only the depth. A depth is a heuristic, not finality:
//! blocks within it can still reorg, so a deployment that relies on it needs the engine's reorg
//! handling (plan §5.4). Anvil reports `finalized = latest − 2 × slots_in_an_epoch` (anvil 1.7.1:
//! `safe` is one epoch back, `finalized` two); start it with `--slots-in-an-epoch 1` for tests.

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use serde::{Deserialize, Serialize};

use crate::bindings::{OptimisticMintBridge, WyecBridge};
use crate::client::EthClient;
use crate::{Error, Result};

/// Which blocks the scanner treats as final.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Finality {
    /// The `finalized` block tag; if the node has none, `latest − fallback_depth` when set,
    /// otherwise [`Error::NoFinalized`].
    Finalized { fallback_depth: Option<u64> },
    /// `latest − depth` only (for nodes known to lack the tag).
    Depth { depth: u64 },
}

impl Default for Finality {
    fn default() -> Self {
        Finality::Finalized {
            fallback_depth: None,
        }
    }
}

/// Where a log sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogMeta {
    pub block_number: u64,
    pub block_hash: B256,
    pub tx_hash: B256,
    pub log_index: u64,
}

/// A decoded bridge event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    /// `BurnToYcash(nonce, from, amount, ycashRecipient)`: a burn to release on Ycash.
    Burn {
        nonce: U256,
        from: Address,
        amount: U256,
        ycash_recipient: B256,
    },
    /// `Minted(lockId, to, amount)` (threshold mint or optimistic execute).
    Minted {
        lock_id: B256,
        to: Address,
        amount: U256,
    },
    /// `GuardiansChanged(guardians, threshold)` (rotation; also emitted by the constructor).
    GuardiansChanged {
        guardians: Vec<Address>,
        threshold: u8,
    },
    /// `Paused(account)` / `Unpaused(account)`.
    Paused { paused: bool, account: Address },
    /// CR-W1 double: `MintProposed(lockId, to, amount, proposer, executableAt)`.
    MintProposed {
        lock_id: B256,
        to: Address,
        amount: U256,
        proposer: Address,
        executable_at: u64,
    },
    /// CR-W1 double: `MintChallenged(lockId, challenger, proposer)`.
    MintChallenged {
        lock_id: B256,
        challenger: Address,
        proposer: Address,
    },
}

/// An event and where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedEvent {
    pub meta: LogMeta,
    pub event: BridgeEvent,
}

/// The topic-0 values the scanner asks for.
pub fn topics() -> Vec<B256> {
    vec![
        WyecBridge::BurnToYcash::SIGNATURE_HASH,
        WyecBridge::Minted::SIGNATURE_HASH,
        WyecBridge::GuardiansChanged::SIGNATURE_HASH,
        WyecBridge::Paused::SIGNATURE_HASH,
        WyecBridge::Unpaused::SIGNATURE_HASH,
        OptimisticMintBridge::MintProposed::SIGNATURE_HASH,
        OptimisticMintBridge::MintChallenged::SIGNATURE_HASH,
    ]
}

/// Decodes one bridge log. `Ok(None)` for a topic the scanner does not know.
pub fn decode_log(log: &Log) -> Result<Option<ScannedEvent>> {
    let Some(t0) = log.topic0().copied() else {
        return Ok(None);
    };
    let meta = LogMeta {
        block_number: log
            .block_number
            .ok_or_else(|| pending_log("block number"))?,
        block_hash: log.block_hash.ok_or_else(|| pending_log("block hash"))?,
        tx_hash: log.transaction_hash.ok_or_else(|| pending_log("tx hash"))?,
        log_index: log.log_index.ok_or_else(|| pending_log("log index"))?,
    };
    let event = match t0 {
        WyecBridge::BurnToYcash::SIGNATURE_HASH => {
            let e = decode::<WyecBridge::BurnToYcash>(log, "BurnToYcash")?;
            BridgeEvent::Burn {
                nonce: e.nonce,
                from: e.from,
                amount: e.amount,
                ycash_recipient: e.ycashRecipient,
            }
        }
        WyecBridge::Minted::SIGNATURE_HASH => {
            let e = decode::<WyecBridge::Minted>(log, "Minted")?;
            BridgeEvent::Minted {
                lock_id: e.lockId,
                to: e.to,
                amount: e.amount,
            }
        }
        WyecBridge::GuardiansChanged::SIGNATURE_HASH => {
            let e = decode::<WyecBridge::GuardiansChanged>(log, "GuardiansChanged")?;
            BridgeEvent::GuardiansChanged {
                guardians: e.guardians,
                threshold: e.threshold,
            }
        }
        WyecBridge::Paused::SIGNATURE_HASH => BridgeEvent::Paused {
            paused: true,
            account: decode::<WyecBridge::Paused>(log, "Paused")?.account,
        },
        WyecBridge::Unpaused::SIGNATURE_HASH => BridgeEvent::Paused {
            paused: false,
            account: decode::<WyecBridge::Unpaused>(log, "Unpaused")?.account,
        },
        OptimisticMintBridge::MintProposed::SIGNATURE_HASH => {
            let e = decode::<OptimisticMintBridge::MintProposed>(log, "MintProposed")?;
            BridgeEvent::MintProposed {
                lock_id: e.lockId,
                to: e.to,
                amount: e.amount,
                proposer: e.proposer,
                executable_at: e.executableAt,
            }
        }
        OptimisticMintBridge::MintChallenged::SIGNATURE_HASH => {
            let e = decode::<OptimisticMintBridge::MintChallenged>(log, "MintChallenged")?;
            BridgeEvent::MintChallenged {
                lock_id: e.lockId,
                challenger: e.challenger,
                proposer: e.proposer,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(ScannedEvent { meta, event }))
}

fn pending_log(what: &str) -> Error {
    Error::Rpc(format!(
        "log without {what} (pending log in a finalized range?)"
    ))
}

fn decode<E: SolEvent>(log: &Log, event: &'static str) -> Result<E> {
    log.log_decode::<E>()
        .map(|l| l.inner.data)
        .map_err(|e| Error::BadLog {
            event,
            tx: log.transaction_hash,
            reason: e.to_string(),
        })
}

/// Events of `[from, to]` and the range they cover.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanBatch {
    pub from: u64,
    /// Inclusive; `to < from` means nothing new was final.
    pub to: u64,
    pub events: Vec<ScannedEvent>,
}

impl EthClient {
    /// The highest block this client treats as final (see [`Finality`]).
    pub async fn finalized_block_number(&self) -> Result<u64> {
        match self.finality {
            Finality::Depth { depth } => self.latest_minus(depth).await,
            Finality::Finalized { fallback_depth } => {
                let fin = self
                    .provider
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await;
                match (fin, fallback_depth) {
                    (Ok(Some(b)), _) => Ok(b.header.number),
                    (_, Some(depth)) => self.latest_minus(depth).await,
                    (Ok(None), None) => Err(Error::NoFinalized),
                    (Err(e), None) => Err(Error::Rpc(format!("finalized block: {e}"))),
                }
            }
        }
    }

    async fn latest_minus(&self, depth: u64) -> Result<u64> {
        Ok(self
            .provider
            .get_block_number()
            .await?
            .saturating_sub(depth))
    }

    /// All bridge events in `[from, to]` (inclusive), in chain order, read in chunks of the
    /// configured span; a failing chunk is retried at half the span down to one block (providers
    /// cap `eth_getLogs` by range or result count). The caller chooses `to` (normally
    /// [`finalized_block_number`](Self::finalized_block_number)).
    pub async fn scan(&self, from: u64, to: u64) -> Result<Vec<ScannedEvent>> {
        let mut out = Vec::new();
        let mut start = from;
        let mut span = self.log_chunk.max(1);
        while start <= to {
            let end = start.saturating_add(span - 1).min(to);
            let filter = Filter::new()
                .address(self.bridge)
                .event_signature(topics())
                .from_block(start)
                .to_block(end);
            match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in &logs {
                        if log.removed {
                            continue;
                        }
                        if let Some(ev) = decode_log(log)? {
                            out.push(ev);
                        }
                    }
                    start = end + 1;
                    span = self.log_chunk.max(1);
                }
                Err(_) if span > 1 => span /= 2,
                Err(e) => return Err(e.into()),
            }
        }
        out.sort_by_key(|e| (e.meta.block_number, e.meta.log_index));
        Ok(out)
    }
}

/// A resumable cursor over final blocks: each [`poll`](Scanner::poll) returns the events of the
/// blocks that became final since the last one. The engine persists [`next_block`](Scanner::next_block)
/// with what it did with the events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scanner {
    next_block: u64,
}

impl Scanner {
    /// Starts at `start_block` (the deployment block, or the persisted cursor).
    pub fn new(start_block: u64) -> Self {
        Self {
            next_block: start_block,
        }
    }

    /// The first block not yet scanned.
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// Scans `[next_block, finalized]` and advances past it. An empty batch with `to < from` when
    /// nothing new is final.
    pub async fn poll(&mut self, client: &EthClient) -> Result<ScanBatch> {
        let fin = client.finalized_block_number().await?;
        let from = self.next_block;
        if fin < from {
            return Ok(ScanBatch {
                from,
                to: fin,
                events: Vec::new(),
            });
        }
        let events = client.scan(from, fin).await?;
        self.next_block = fin + 1;
        Ok(ScanBatch {
            from,
            to: fin,
            events,
        })
    }
}
