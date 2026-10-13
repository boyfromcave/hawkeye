//! Hawkeye, the wYEC bridge attestor (plan `docs/hawkeye-bridge-plan.md`): the engine (§5,
//! phase H4) and the daemon, API and CLI (phase H5).
//!
//! | Module | Contents |
//! |---|---|
//! | [`config`] | `hawkeye.toml` and its checked form |
//! | [`keys`] | the member key: compressed key, WIF, Ethereum signer |
//! | [`engine`] | the tick: Ycash follower, mint, burns, watcher, slash, heartbeat, status |
//! | [`foreign`] | the foreign-chain adapter (`ForeignChain`; Ethereum today, NEAR plan §4) |
//! | [`attribution`] | set-signature attribution behind a trait |
//! | [`peers`] | the peer channel client and the API's wire types |
//! | [`restore`] | ledger-restore detection (review L-2): the sign-record high-water mark |
//! | [`peer_auth`] | the peer channel's member-key request / response authentication (HK-13) |
//! | [`api`] | the axum status / peer API |
//! | [`status`] | the status summary and Prometheus rendering |
//! | [`daemon`] | connect, start-up checks, the run loop |
//! | [`cli`] | the one-shot commands |
//! | [`convert`] | type conversions between the adapters and `hawkeye-core` |

pub mod api;
pub mod attribution;
pub mod audit;
pub mod cli;
pub mod config;
pub mod convert;
pub mod daemon;
pub mod engine;
pub mod floors;
pub mod foreign;
pub mod keys;
pub mod peer_auth;
pub mod peers;
pub mod restore;
pub mod status;
