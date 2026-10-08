//! `hawkeye.toml` (plan §6 "Config"): the file as written ([`Config`]) and its checked, resolved
//! form ([`Settings`]).
//!
//! Relative paths in the file (`eth.deployment`, `store.path`, `keys.keystore`,
//! `ycash.cookie_file`) resolve against the directory of the config file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hawkeye_core::address::Network;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::{Deployment as CoreDeployment, EthAddress, SecretKey};
use hawkeye_eth::{Deployment, Finality, MintMode};
use hawkeye_ycash::{Amount, Auth, Hash256};
use serde::Deserialize;

/// The config file as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[network]`.
    pub network: NetworkSection,
    /// `[ycash]`.
    pub ycash: YcashSection,
    /// `[eth]`.
    pub eth: EthSection,
    /// `[bridge]`.
    pub bridge: BridgeSection,
    /// `[keys]`.
    #[serde(default)]
    pub keys: KeysSection,
    /// `[store]`.
    #[serde(default)]
    pub store: StoreSection,
    /// `[api]`.
    #[serde(default)]
    pub api: ApiSection,
    /// `[policy]`.
    #[serde(default)]
    pub policy: PolicySection,
    /// `[peers]`.
    #[serde(default)]
    pub peers: PeersSection,
    /// `[devnet]`.
    #[serde(default)]
    pub devnet: DevnetSection,
    /// `[log]`.
    #[serde(default)]
    pub log: LogSection,
}

/// `[network]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// `regtest`, `testnet` or `mainnet`.
    pub name: String,
}

/// `[ycash]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YcashSection {
    /// `http://127.0.0.1:18232`.
    pub rpc_url: String,
    /// `-rpcuser`.
    pub rpc_user: Option<String>,
    /// `-rpcpassword`.
    pub rpc_password: Option<String>,
    /// The node's `.cookie` file (instead of user/password).
    pub cookie_file: Option<PathBuf>,
    /// Extension: the first Ycash height the follower reads (default: the upgrade's activation
    /// height, or the tip if unscheduled).
    pub start_height: Option<u32>,
}

/// `[eth]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthSection {
    /// HTTP JSON-RPC endpoint.
    pub rpc_url: String,
    /// `deployments/<chainid>.json` as `eth/script/Deploy.s.sol` writes it.
    pub deployment: PathBuf,
    /// `"finalized"` (the default when `depth` is absent).
    pub finality: Option<String>,
    /// `latest − depth` (alone: depth-only; with `finality = "finalized"`: the fallback when the
    /// node has no `finalized` tag).
    pub depth: Option<u64>,
}

/// `[bridge]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeSection {
    /// The attestor set id (display hex, as the RPCs print it).
    pub set_id: String,
    /// The vaults' `delay`: the challenge window D.
    pub delay: u16,
    /// `C_Y`.
    pub confirmations: u32,
    /// `MIN_OWNER_AGE`.
    pub min_owner_age: u32,
    /// `ROLL_MARGIN`.
    pub roll_margin: u32,
    /// `TAKEOVER`.
    pub takeover_blocks: u32,
    /// Heartbeat every this many Ycash blocks.
    pub heartbeat_blocks: u32,
    /// `MIN_LOCK` in YEC (decimal string).
    pub min_lock: String,
    /// `MAX_LOCK` in YEC.
    pub max_lock: String,
    /// `threshold` or `optimistic`.
    pub mint_mode: String,
    /// `k` for `threshold`.
    pub mint_threshold: Option<u8>,
}

/// `[keys]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysSection {
    /// The member key as 64 hex digits (dev only: refused on mainnet).
    pub secret_hex: Option<String>,
    /// An Ethereum keystore v3 file holding the member key.
    pub keystore: Option<PathBuf>,
    /// The environment variable holding the keystore password.
    pub password_env: Option<String>,
}

/// `[store]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSection {
    /// The SQLite ledger.
    #[serde(default = "default_store")]
    pub path: PathBuf,
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            path: default_store(),
        }
    }
}

fn default_store() -> PathBuf {
    PathBuf::from("hawkeye.db")
}

/// `[api]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    /// Listen address of the status/peer API.
    #[serde(default = "default_listen")]
    pub listen: String,
}

impl Default for ApiSection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:7801".into()
}

/// `[policy]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    /// Drive slash votes automatically (default: true off mainnet, false on mainnet).
    pub auto_slash: Option<bool>,
}

/// `[peers]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeersSection {
    /// Other attestors' API base URLs.
    #[serde(default)]
    pub urls: Vec<String>,
}

/// `[devnet]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetSection {
    /// Allow the drill commands (`rogue-unlock`).
    #[serde(default)]
    pub drills: bool,
}

/// `[log]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// `error`, `warn`, `info`, `debug`, `trace`.
    #[serde(default = "default_level")]
    pub level: String,
    /// `text` or `json`.
    #[serde(default = "default_format")]
    pub format: String,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
        }
    }
}

fn default_level() -> String {
    "info".into()
}

fn default_format() -> String {
    "text".into()
}

/// Where the member key comes from.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// `secret_hex`.
    Hex(String),
    /// A keystore and the variable holding its password.
    Keystore {
        /// The file.
        path: PathBuf,
        /// The environment variable.
        password_env: String,
    },
}

/// The checked configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The Ycash network.
    pub network: Network,
    /// `regtest` / `testnet` / `mainnet`.
    pub network_name: String,
    /// ycashd URL.
    pub ycash_url: String,
    /// ycashd authentication.
    pub ycash_auth: Auth,
    /// First height to follow from (extension).
    pub ycash_start_height: Option<u32>,
    /// Ethereum endpoint.
    pub eth_url: String,
    /// The deployment file's contents.
    pub deployment: Deployment,
    /// Finality rule for the scanner.
    pub finality: Finality,
    /// Engine parameters.
    pub params: Params,
    /// The key source.
    pub key: Option<KeySource>,
    /// The ledger file.
    pub store_path: PathBuf,
    /// API listen address.
    pub listen: SocketAddr,
    /// Peer API URLs.
    pub peers: Vec<String>,
    /// Log level.
    pub log_level: String,
    /// Log as JSON.
    pub log_json: bool,
}

/// The engine's parameters (everything the tick reads from configuration).
#[derive(Debug, Clone)]
pub struct Params {
    /// The Ycash network (address prefixes).
    pub network: Network,
    /// Mainnet: the stricter start-up rules.
    pub mainnet: bool,
    /// The attestor set, internal byte order.
    pub set_id: Hash32,
    /// The bridge deployment (memos, burns).
    pub deployment: CoreDeployment,
    /// The first Ethereum block to scan.
    pub eth_start_block: u64,
    /// The vaults' delay.
    pub delay: u16,
    /// `C_Y`.
    pub confirmations: u32,
    /// `MIN_OWNER_AGE`.
    pub min_owner_age: u32,
    /// `ROLL_MARGIN`.
    pub roll_margin: u32,
    /// `TAKEOVER`.
    pub takeover: u32,
    /// Heartbeat interval in blocks.
    pub heartbeat_blocks: u32,
    /// `MIN_LOCK`, zatoshi.
    pub min_lock: u64,
    /// `MAX_LOCK`, zatoshi.
    pub max_lock: u64,
    /// The mint mode.
    pub mint_mode: MintMode,
    /// Drive slash votes.
    pub auto_slash: bool,
    /// Drills allowed.
    pub drills: bool,
    /// The first Ycash height to follow (default: the upgrade's activation height).
    pub ycash_start_height: Option<u32>,
}

impl Params {
    /// The lock policy of §4.1.
    pub fn lock_policy(&self) -> hawkeye_core::policy::LockPolicy {
        hawkeye_core::policy::LockPolicy {
            set_id: self.set_id,
            delay: self.delay,
            min_owner_age: self.min_owner_age,
            min_lock: self.min_lock,
            max_lock: self.max_lock,
            min_confirmations: self.confirmations,
        }
    }

    /// The set id as the RPCs take it.
    pub fn set_hash(&self) -> Hash256 {
        Hash256::from_internal(self.set_id)
    }
}

/// A regtest [`Params`] for unit tests.
#[cfg(test)]
pub(crate) fn sample_params(drills: bool, mainnet: bool) -> Params {
    Params {
        network: Network::Regtest,
        mainnet,
        set_id: [7; 32],
        deployment: CoreDeployment {
            chain_id: 31337,
            bridge: EthAddress([0x5f; 20]),
        },
        eth_start_block: 1,
        delay: 6,
        confirmations: 2,
        min_owner_age: 400,
        roll_margin: 50,
        takeover: 4,
        heartbeat_blocks: 10,
        min_lock: 10_000_000,
        max_lock: 100_000_000_000,
        mint_mode: MintMode::Threshold { k: 1 },
        auto_slash: true,
        drills,
        ycash_start_height: None,
    }
}

impl Config {
    /// Read and parse a config file.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("config {}", path.display()))
    }

    /// Parse config text.
    pub fn parse(text: &str) -> Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// Check and resolve; `base` is the directory relative paths resolve against.
    pub fn settings(&self, base: &Path) -> Result<Settings> {
        let resolve = |p: &Path| {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };
        let (network, mainnet) = match self.network.name.as_str() {
            "regtest" => (Network::Regtest, false),
            "testnet" => (Network::Testnet, false),
            "mainnet" => (Network::Mainnet, true),
            other => bail!("network.name {other:?}: regtest, testnet or mainnet"),
        };
        let ycash_auth = match (
            &self.ycash.rpc_user,
            &self.ycash.rpc_password,
            &self.ycash.cookie_file,
        ) {
            (Some(u), Some(p), None) => Auth::UserPass {
                user: u.clone(),
                password: p.clone(),
            },
            (None, None, Some(c)) => Auth::CookieFile(resolve(c)),
            (None, None, None) => Auth::None,
            _ => bail!("ycash: give rpc_user and rpc_password, or cookie_file"),
        };
        let deployment = Deployment::read(resolve(&self.eth.deployment))
            .map_err(|e| anyhow!("eth.deployment: {e}"))?;
        let finality = match (self.eth.finality.as_deref(), self.eth.depth) {
            (None, Some(depth)) => Finality::Depth { depth },
            (None | Some("finalized"), fallback_depth) => Finality::Finalized { fallback_depth },
            (Some(other), _) => bail!("eth.finality {other:?}: only \"finalized\" (or use depth)"),
        };
        let set_id = self
            .bridge
            .set_id
            .parse::<Hash256>()
            .map_err(|e| anyhow!("bridge.set_id: {e}"))?
            .0;
        let zat = |what: &str, s: &str| -> Result<u64> {
            let a = Amount::parse_decimal(s).map_err(|e| anyhow!("bridge.{what}: {e}"))?;
            u64::try_from(a.zat()).map_err(|_| anyhow!("bridge.{what} is negative"))
        };
        let min_lock = zat("min_lock", &self.bridge.min_lock)?;
        let max_lock = zat("max_lock", &self.bridge.max_lock)?;
        ensure!(min_lock <= max_lock, "bridge.min_lock > bridge.max_lock");
        ensure!(self.bridge.delay >= 1, "bridge.delay must be at least 1");
        ensure!(
            self.bridge.confirmations >= 1,
            "bridge.confirmations must be at least 1"
        );
        let mint_mode = match self.bridge.mint_mode.as_str() {
            "threshold" => MintMode::Threshold {
                k: self.bridge.mint_threshold.unwrap_or(deployment.threshold),
            },
            "optimistic" => MintMode::Optimistic,
            other => bail!("bridge.mint_mode {other:?}: threshold or optimistic"),
        };
        let chain_id = if mainnet {
            hawkeye_eth::mode::MAINNET
        } else {
            deployment.chain_id
        };
        mint_mode
            .check_allowed(chain_id)
            .map_err(|e| anyhow!("bridge.mint_mode: {e} (plan §3.3)"))?;
        if mainnet && matches!(mint_mode, MintMode::Threshold { k } if k < 2) {
            bail!("mainnet refuses mint_mode threshold with k < 2 (plan §3.3)");
        }
        let key = match (&self.keys.secret_hex, &self.keys.keystore) {
            (Some(h), None) => {
                ensure!(
                    !mainnet,
                    "mainnet refuses keys.secret_hex: use an encrypted keystore"
                );
                Some(KeySource::Hex(h.clone()))
            }
            (None, Some(p)) => Some(KeySource::Keystore {
                path: resolve(p),
                password_env: self
                    .keys
                    .password_env
                    .clone()
                    .unwrap_or_else(|| "HAWKEYE_KEYSTORE_PASSWORD".into()),
            }),
            (None, None) => None,
            (Some(_), Some(_)) => bail!("keys: give secret_hex or keystore, not both"),
        };
        if mainnet {
            ensure!(!self.devnet.drills, "mainnet refuses [devnet] drills");
            ensure!(
                !matches!(finality, Finality::Depth { .. }),
                "mainnet refuses a depth-only Ethereum finality"
            );
        }
        let listen: SocketAddr = self
            .api
            .listen
            .parse()
            .map_err(|e| anyhow!("api.listen {:?}: {e}", self.api.listen))?;
        let log_json = match self.log.format.as_str() {
            "text" => false,
            "json" => true,
            other => bail!("log.format {other:?}: text or json"),
        };
        let params = Params {
            network,
            mainnet,
            set_id,
            deployment: CoreDeployment {
                chain_id: deployment.chain_id,
                bridge: EthAddress(deployment.bridge.into()),
            },
            eth_start_block: deployment.deploy_block,
            delay: self.bridge.delay,
            confirmations: self.bridge.confirmations,
            min_owner_age: self.bridge.min_owner_age,
            roll_margin: self.bridge.roll_margin,
            takeover: self.bridge.takeover_blocks,
            heartbeat_blocks: self.bridge.heartbeat_blocks,
            min_lock,
            max_lock,
            mint_mode,
            auto_slash: self.policy.auto_slash.unwrap_or(!mainnet),
            drills: self.devnet.drills,
            ycash_start_height: self.ycash.start_height,
        };
        Ok(Settings {
            network,
            network_name: self.network.name.clone(),
            ycash_url: self.ycash.rpc_url.clone(),
            ycash_auth,
            ycash_start_height: self.ycash.start_height,
            eth_url: self.eth.rpc_url.clone(),
            deployment,
            finality,
            params,
            key,
            store_path: resolve(&self.store.path),
            listen,
            peers: self.peers.urls.clone(),
            log_level: self.log.level.clone(),
            log_json,
        })
    }
}

impl Settings {
    /// Load the member key.
    pub fn load_key(&self) -> Result<SecretKey> {
        match &self.key {
            None => bail!("[keys] has no secret_hex or keystore"),
            Some(KeySource::Hex(h)) => SecretKey::from_hex(h.trim_start_matches("0x"))
                .map_err(|e| anyhow!("keys.secret_hex: {e}")),
            Some(KeySource::Keystore { path, password_env }) => {
                let pw = std::env::var(password_env)
                    .with_context(|| format!("keystore password variable {password_env}"))?;
                let signer =
                    alloy::signers::local::PrivateKeySigner::decrypt_keystore(path, pw.as_bytes())
                        .map_err(|e| anyhow!("keystore {}: {e}", path.display()))?;
                let bytes: [u8; 32] = signer.credential().to_bytes().into();
                SecretKey::from_bytes(&bytes).map_err(|e| anyhow!("keystore key: {e}"))
            }
        }
    }
}

/// The directory a config path's relative paths resolve against.
pub fn base_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT: &str = r#"{"chainId":31337,"bridge":"0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "token":"0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512","deployBlock":1,"guardians":[],"threshold":1}"#;

    fn sample(network: &str, extra: &str) -> String {
        format!(
            r#"
[network]
name = "{network}"
[ycash]
rpc_url = "http://127.0.0.1:18232"
rpc_user = "u"
rpc_password = "p"
[eth]
rpc_url = "http://127.0.0.1:8545"
deployment = "31337.json"
finality = "finalized"
[bridge]
set_id = "{set}"
delay = 6
confirmations = 2
min_owner_age = 400
roll_margin = 50
takeover_blocks = 4
heartbeat_blocks = 10
min_lock = "0.1"
max_lock = "1000"
mint_mode = "threshold"
mint_threshold = 1
[keys]
secret_hex = "{key}"
[store]
path = "hawkeye.db"
[api]
listen = "127.0.0.1:7801"
[policy]
auto_slash = true
[peers]
urls = ["http://127.0.0.1:7802", "http://127.0.0.1:7803"]
[devnet]
drills = true
[log]
level = "info"
format = "text"
{extra}
"#,
            set = "11".repeat(32),
            key = "01".repeat(32)
        )
    }

    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("31337.json"), DEPLOYMENT).unwrap();
        d
    }

    #[test]
    fn full_contract_parses() {
        let d = dir();
        let c = Config::parse(&sample("regtest", "")).unwrap();
        let s = c.settings(d.path()).unwrap();
        assert_eq!(s.params.min_lock, 10_000_000);
        assert_eq!(s.params.max_lock, 100_000_000_000);
        assert_eq!(s.params.mint_mode, MintMode::Threshold { k: 1 });
        assert_eq!(s.params.set_id, [0x11; 32]);
        assert_eq!(s.store_path, d.path().join("hawkeye.db"));
        assert_eq!(s.peers.len(), 2);
        assert!(s.params.auto_slash && s.params.drills);
        assert!(matches!(
            s.finality,
            Finality::Finalized {
                fallback_depth: None
            }
        ));
        s.load_key().unwrap();
    }

    #[test]
    fn mainnet_refuses_dev_options() {
        let d = dir();
        let c = Config::parse(&sample("mainnet", "")).unwrap();
        let e = c.settings(d.path()).unwrap_err().to_string();
        assert!(e.contains("mint_mode") || e.contains("secret_hex"), "{e}");
    }

    #[test]
    fn unknown_keys_refused() {
        assert!(Config::parse(&sample("regtest", "[bogus]\nx = 1")).is_err());
    }
}
