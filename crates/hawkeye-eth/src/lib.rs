//! Hawkeye's Ethereum adapter (plan §6, phase H3).
//!
//! - [`bindings`]: `sol!` bindings generated from the forge-built artifacts of wyec at the pinned
//!   commit (`abi/`).
//! - [`eip712`]: the bridge's EIP-712 digests (`Mint`, `Challenge`, the admin acts), the
//!   attestor's signature, recovery and the ascending-signer ordering `sigs[]` needs.
//! - [`EthClient`]: connect over HTTP JSON-RPC, check the chain id and the bridge/token pair, read
//!   guardians / threshold / paused / `consumed(lockId)` / proposals / rate limit / `burnNonce` /
//!   supply, submit mints in either [`MintMode`] (`mint`, or `proposeMint` → `challengeMint` /
//!   `executeMint`), burn (CLI, devnet), admin acts.
//! - [`scanner`]: the finalized-block log scanner for `BurnToYcash`, `Minted`,
//!   `MintProposed`/`MintChallenged` and the admin events.
//! - [`deploy`](mod@deploy): the deployment file and an in-process predicted-address deployer.
//!
//! Hawkeye reaches Ethereum only through standard JSON-RPC (`eth_chainId`, `eth_call`,
//! `eth_getLogs`, `eth_getBlockByNumber`, `eth_sendRawTransaction`, receipts; HK-10).

pub mod bindings;
pub mod client;
pub mod deploy;
pub mod eip712;
mod error;
pub mod mode;
pub mod scanner;

pub use alloy::primitives::{Address, B256, Bytes, U256};
pub use alloy::signers::local::PrivateKeySigner;
pub use client::{
    Burned, EthClient, EthConfig, GuardianSet, Mined, MintSubmitted, Proposal, ProposalStatus,
    wallet_provider,
};
pub use deploy::{DeployParams, Deployment, deploy};
pub use error::{Error, Result};
pub use mode::MintMode;
pub use scanner::{BridgeEvent, Finality, LogMeta, ScanBatch, ScannedEvent, Scanner};
