//! `hawkeye.toml` (plan §6 "Config"): the file as written ([`Config`]) and its checked, resolved
//! form ([`Settings`]).
//!
//! The foreign chain is `[foreign] kind` (`"ethereum"`, the default when the section is absent,
//! so every existing config keeps working, with `[eth]`; or `"near"`, with `[near]`, NEAR plan
//! §4 item 4), and the bridge's vault tag is `[bridge] tag` (default: the kind's, `"WYEC"` or
//! `"NYEC"`; NEAR plan §0 item 2).
//!
//! Relative paths in the file (`eth.deployment`, `near.relayer_key_file`, `store.path`,
//! `keys.keystore`, `ycash.cookie_file`) resolve against the directory of the config file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hawkeye_core::address::Network;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::{AccountId, Deployment as CoreDeployment, EthAddress, SecretKey};
use hawkeye_eth::{Deployment, Finality, MintMode};
use hawkeye_ycash::{Amount, Auth, Hash256};
use serde::Deserialize;

use crate::foreign::BridgeKind;

/// The config file as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[network]`.
    pub network: NetworkSection,
    /// `[ycash]`.
    pub ycash: YcashSection,
    /// `[foreign]` (absent: Ethereum).
    #[serde(default)]
    pub foreign: ForeignSection,
    /// `[eth]` (required when `foreign.kind = "ethereum"`).
    pub eth: Option<EthSection>,
    /// `[near]` (required when `foreign.kind = "near"`).
    pub near: Option<NearSection>,
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

/// `[foreign]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignSection {
    /// `"ethereum"` (default) or `"near"`.
    pub kind: Option<String>,
}

/// `[near]` (NEAR plan §4 item 4): the `wyec-near` deployment and the operator's relayer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NearSection {
    /// NEAR JSON-RPC endpoint (`https://rpc.mainnet.near.org`, `http://127.0.0.1:3030`).
    pub rpc_url: String,
    /// The network id bound into every digest (`mainnet`, `testnet`, `sandbox`, …): the
    /// contract's `config().network_id`.
    pub network_id: String,
    /// The `wyec-near` contract account.
    pub contract_id: String,
    /// The operator's NEAR account that sends (and pays for) this attestor's transactions.
    pub relayer_account: String,
    /// Its credentials JSON (`account_id`, `public_key`, `private_key`, as near-cli writes it).
    pub relayer_key_file: PathBuf,
    /// The first NEAR block height to scan: the contract's deployment block.
    pub start_block: u64,
    /// Gas attached to each call, TGas (default 100; NEAR's per-transaction maximum is 300).
    pub gas_tgas: Option<u64>,
}

/// The checked `[near]` section.
#[derive(Debug, Clone)]
pub struct NearSettings {
    /// RPC endpoint.
    pub rpc_url: String,
    /// The digest domain: network id and contract account.
    pub domain: hawkeye_core::near::Domain,
    /// The relayer account.
    pub relayer_account: AccountId,
    /// Its key file (resolved).
    pub relayer_key_file: PathBuf,
    /// Gas per call.
    pub gas: u64,
    /// First block to scan.
    pub start_block: u64,
}

/// The default `[near] gas_tgas`.
pub const DEFAULT_NEAR_GAS_TGAS: u64 = 100;

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
    /// The bridge's vault tag: four printable ASCII characters (default `"WYEC"`; NEAR's bridge
    /// is `"NYEC"`). Every vault, intent and lock Hawkeye follows carries it.
    pub tag: Option<String>,
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
    /// `optimistic` (the Foundation's model: one attestor proposes, any attestor challenges
    /// within the contract's window, anyone executes) or `threshold` (k-of-n `mint`, immediate).
    pub mint_mode: String,
    /// `k` for `threshold` (default: the deployment's threshold). Also the floor the contract's
    /// threshold is held to: on mainnet it must be ≥ 2 in every mode (plan §3.3).
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
    /// The foreign chain (`[foreign] kind`).
    pub foreign: BridgeKind,
    /// Ethereum endpoint (empty on NEAR).
    pub eth_url: String,
    /// The `[eth]` deployment file's contents (Ethereum only).
    pub deployment: Option<Deployment>,
    /// Finality rule for the Ethereum scanner (NEAR is always read at `final`).
    pub finality: Finality,
    /// `[near]` (NEAR only).
    pub near: Option<NearSettings>,
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
    /// The bridge (`[foreign] kind`): its vault tag (`[bridge] tag`, the only vaults and intents
    /// this Hawkeye follows), lock destination and memo magic, as `hawkeye-core` defines them.
    pub bridge_kind: BridgeKind,
    /// The bridge deployment (memos, burns): Ethereum `(chainId, bridge)`, NEAR the hashed
    /// `(network_id, contract_id)` (NEAR plan §2.2).
    pub deployment: CoreDeployment,
    /// The first foreign block to scan (Ethereum: the deployment block; NEAR: `[near]
    /// start_block`).
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

    /// The bridge's vault tag (`WYEC`, `NYEC`).
    pub fn tag(&self) -> [u8; 4] {
        self.bridge_kind.tag()
    }

    /// The vault tag as text (`vault_list`'s filter, messages): it is printable ASCII.
    pub fn tag_text(&self) -> String {
        tag_text(&self.tag())
    }
}

/// A vault tag as text (lossy for a non-ASCII tag, which [`parse_tag`] refuses).
pub fn tag_text(tag: &[u8; 4]) -> String {
    String::from_utf8_lossy(tag).into_owned()
}

/// A configured vault tag: exactly four printable ASCII characters (`"WYEC"`, `"NYEC"`). A
/// module tag with a NUL byte (`YED\0`) is not a bridge's.
pub fn parse_tag(s: &str) -> Result<[u8; 4]> {
    let b: [u8; 4] = s
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow!("{s:?} is {} bytes, not 4", s.len()))?;
    ensure!(
        b.iter().all(u8::is_ascii_graphic),
        "{s:?} is not four printable ASCII characters"
    );
    Ok(b)
}

/// A regtest [`Params`] for unit tests.
#[cfg(test)]
pub(crate) fn sample_params(drills: bool, mainnet: bool) -> Params {
    Params {
        network: Network::Regtest,
        mainnet,
        set_id: [7; 32],
        bridge_kind: BridgeKind::Ethereum,
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
        let foreign = match self.foreign.kind.as_deref() {
            None => BridgeKind::Ethereum,
            Some(k) => k.parse().map_err(|e| anyhow!("foreign.kind {k:?}: {e}"))?,
        };
        let (eth, near) =
            match foreign {
                BridgeKind::Ethereum => (
                    Some(self.eth.as_ref().ok_or_else(|| {
                        anyhow!("foreign.kind \"ethereum\" needs an [eth] section")
                    })?),
                    None,
                ),
                BridgeKind::Near => {
                    ensure!(
                        self.eth.is_none(),
                        "foreign.kind \"near\": remove the [eth] section"
                    );
                    (
                        None,
                        Some(self.near.as_ref().ok_or_else(|| {
                            anyhow!("foreign.kind \"near\" needs a [near] section")
                        })?),
                    )
                }
            };
        if foreign == BridgeKind::Ethereum {
            ensure!(
                self.near.is_none(),
                "foreign.kind \"ethereum\": remove the [near] section"
            );
        }
        // hawkeye-core's lock policy and intent matcher judge the vaults of the bridge kind's
        // tag (Ethereum WYEC, NEAR NYEC): another tag would refuse every lock
        if let Some(t) = &self.bridge.tag {
            let tag = parse_tag(t).map_err(|e| anyhow!("bridge.tag {e}"))?;
            ensure!(
                tag == foreign.tag(),
                "bridge.tag {t:?}: the {foreign} bridge's vault tag is {:?}",
                tag_text(&foreign.tag())
            );
        }
        let deployment = eth
            .map(|eth| {
                Deployment::read(resolve(&eth.deployment))
                    .map_err(|e| anyhow!("eth.deployment: {e}"))
            })
            .transpose()?;
        let finality = match eth.map(|e| (e.finality.as_deref(), e.depth)) {
            None => Finality::Finalized {
                fallback_depth: None,
            },
            Some((None, Some(depth))) => Finality::Depth { depth },
            Some((None | Some("finalized"), fallback_depth)) => {
                Finality::Finalized { fallback_depth }
            }
            Some((Some(other), _)) => {
                bail!("eth.finality {other:?}: only \"finalized\" (or use depth)")
            }
        };
        let near = near
            .map(|n| -> Result<NearSettings> {
                let contract_id = AccountId::parse(&n.contract_id)
                    .map_err(|e| anyhow!("near.contract_id {:?}: {e}", n.contract_id))?;
                let relayer_account = AccountId::parse(&n.relayer_account)
                    .map_err(|e| anyhow!("near.relayer_account {:?}: {e}", n.relayer_account))?;
                let domain = hawkeye_core::near::Domain::new(&n.network_id, contract_id)
                    .map_err(|e| anyhow!("near.network_id: {e}"))?;
                ensure!(
                    mainnet == (n.network_id == "mainnet"),
                    "near.network_id {:?} with network.name {:?}: a mainnet bridge pairs Ycash \
                     mainnet with NEAR mainnet, and only those",
                    n.network_id,
                    self.network.name
                );
                let tgas = n.gas_tgas.unwrap_or(DEFAULT_NEAR_GAS_TGAS);
                ensure!(
                    (1..=300).contains(&tgas),
                    "near.gas_tgas {tgas}: between 1 and 300"
                );
                Ok(NearSettings {
                    rpc_url: n.rpc_url.clone(),
                    domain,
                    relayer_account,
                    relayer_key_file: resolve(&n.relayer_key_file),
                    gas: tgas * hawkeye_near::tx::TGAS,
                    start_block: n.start_block,
                })
            })
            .transpose()?;
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
        // the bridge deployment: the [eth] deployment file, or the NEAR domain's hashed ids
        let (core_deployment, start_block) = match (&deployment, &near) {
            (Some(d), _) => (
                CoreDeployment {
                    chain_id: d.chain_id,
                    bridge: EthAddress(d.bridge.into()),
                },
                d.deploy_block,
            ),
            (None, Some(n)) => (n.domain.deployment(), n.start_block),
            (None, None) => bail!("no foreign deployment"),
        };
        let mint_mode = match self.bridge.mint_mode.as_str() {
            "threshold" => MintMode::Threshold {
                k: match (self.bridge.mint_threshold, &deployment) {
                    (Some(k), _) => k,
                    (None, Some(d)) => d.threshold,
                    (None, None) => bail!(
                        "bridge.mint_threshold is required for a NEAR bridge in threshold mode \
                         (no deployment file to default it from)"
                    ),
                },
            },
            "optimistic" => MintMode::Optimistic,
            other => bail!("bridge.mint_mode {other:?}: threshold or optimistic"),
        };
        let chain_id = if mainnet {
            hawkeye_eth::mode::MAINNET
        } else {
            core_deployment.chain_id
        };
        mint_mode
            .check_allowed(chain_id)
            .map_err(|e| anyhow!("bridge.mint_mode: {e} (plan §3.3)"))?;
        if mainnet {
            // Plan §3.3: the contract's threshold path mints at once, so with k = 1 one key would
            // skip the optimistic window. Refused whatever the mode; the live contract is checked
            // again at start-up.
            if let Some(k) = self.bridge.mint_threshold
                && k < hawkeye_eth::mode::MAINNET_MIN_THRESHOLD
            {
                bail!(
                    "mainnet refuses bridge.mint_threshold {k} < 2 in every mint mode (plan §3.3)"
                );
            }
            if let Some(d) = &deployment {
                hawkeye_eth::mode::check_contract_threshold(chain_id, d.threshold)
                    .map_err(|e| anyhow!("eth.deployment: {e} (plan §3.3)"))?;
            }
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
            bridge_kind: foreign,
            deployment: core_deployment,
            eth_start_block: start_block,
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
            foreign,
            eth_url: eth.map(|e| e.rpc_url.clone()).unwrap_or_default(),
            deployment,
            finality,
            near,
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
    use hawkeye_core::template::TAG_WYEC;

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

    /// Plan §3.3: on mainnet the threshold must be ≥ 2 in every mode — the configured
    /// `mint_threshold` and the deployment's (contract) threshold alike.
    #[test]
    fn mainnet_threshold_rule_in_every_mode() {
        let d = tempfile::tempdir().unwrap();
        let dep = |threshold: u8| {
            std::fs::write(
                d.path().join("31337.json"),
                DEPLOYMENT.replace(r#""threshold":1"#, &format!(r#""threshold":{threshold}"#)),
            )
            .unwrap();
        };
        let mainnet = |mode: &str, k: Option<u8>| {
            let text = sample("mainnet", "")
                .replace(
                    "mint_mode = \"threshold\"",
                    &format!("mint_mode = \"{mode}\""),
                )
                .replace(
                    "mint_threshold = 1\n",
                    &k.map_or(String::new(), |k| format!("mint_threshold = {k}\n")),
                )
                .replace(
                    &format!("secret_hex = \"{}\"", "01".repeat(32)),
                    "keystore = \"k.json\"",
                )
                .replace("drills = true", "drills = false");
            Config::parse(&text).unwrap().settings(d.path())
        };
        dep(2);
        let s = mainnet("optimistic", None).unwrap();
        assert_eq!(s.params.mint_mode, MintMode::Optimistic);
        assert!(s.params.mainnet);
        mainnet("threshold", Some(2)).unwrap();
        // a configured k of 1 is refused in both modes
        let e = mainnet("optimistic", Some(1)).unwrap_err().to_string();
        assert!(e.contains("mint_threshold 1 < 2 in every mint mode"), "{e}");
        assert!(mainnet("threshold", Some(1)).is_err());
        // a bridge deployed at threshold 1 is refused in both modes
        dep(1);
        let e = format!("{:#}", mainnet("optimistic", None).unwrap_err());
        assert!(e.contains("threshold is 1"), "{e}");
        assert!(mainnet("threshold", Some(2)).is_err());
        // off mainnet both are allowed (development)
        let s = Config::parse(
            &sample("regtest", "")
                .replace("mint_mode = \"threshold\"", "mint_mode = \"optimistic\""),
        )
        .unwrap()
        .settings(d.path())
        .unwrap();
        assert_eq!(s.params.mint_mode, MintMode::Optimistic);
    }

    /// `[foreign]` absent is Ethereum (existing configs and the devnet unchanged); `"near"` needs
    /// `[near]` and no `[eth]`; anything else, or Ethereum without `[eth]`, is refused.
    #[test]
    fn foreign_kind() {
        let d = dir();
        let s = Config::parse(&sample("regtest", ""))
            .unwrap()
            .settings(d.path())
            .unwrap();
        assert_eq!(s.foreign, BridgeKind::Ethereum);
        let s = Config::parse(&sample("regtest", "[foreign]\nkind = \"ethereum\""))
            .unwrap()
            .settings(d.path())
            .unwrap();
        assert_eq!(s.foreign, BridgeKind::Ethereum);
        let e = Config::parse(&sample("regtest", "[foreign]\nkind = \"near\""))
            .unwrap()
            .settings(d.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("remove the [eth] section"), "{e}");
        let e = Config::parse(&sample("regtest", "[foreign]\nkind = \"solana\""))
            .unwrap()
            .settings(d.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("foreign.kind"), "{e}");
        let no_eth = sample("regtest", "").replace(
            "[eth]\nrpc_url = \"http://127.0.0.1:8545\"\ndeployment = \"31337.json\"\nfinality = \"finalized\"\n",
            "",
        );
        let e = Config::parse(&no_eth)
            .unwrap()
            .settings(d.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("needs an [eth] section"), "{e}");
    }

    fn near_sample(network: &str, net_id: &str, extra_bridge: &str) -> String {
        sample(network, "")
            .replace(
                "[eth]\nrpc_url = \"http://127.0.0.1:8545\"\ndeployment = \"31337.json\"\nfinality = \"finalized\"\n",
                &format!(
                    "[foreign]\nkind = \"near\"\n[near]\nrpc_url = \"http://127.0.0.1:3030\"\n\
                     network_id = \"{net_id}\"\ncontract_id = \"wyec.test.near\"\n\
                     relayer_account = \"hawkeye1.test.near\"\nrelayer_key_file = \"keys/hawkeye1.json\"\n\
                     start_block = 42\n"
                ),
            )
            .replace("[bridge]\n", &format!("[bridge]\n{extra_bridge}"))
    }

    /// `[near]` (NEAR plan §4 item 4): the deployment is the hashed domain, the relayer key file
    /// resolves against the config's directory, gas defaults to 100 TGas, the tag must be NYEC,
    /// and mainnet pairs with NEAR mainnet only.
    #[test]
    fn near_section() {
        let d = dir();
        let s = Config::parse(&near_sample("regtest", "sandbox", ""))
            .unwrap()
            .settings(d.path())
            .unwrap();
        assert_eq!(s.foreign, BridgeKind::Near);
        assert_eq!(s.params.bridge_kind, BridgeKind::Near);
        assert_eq!(s.params.tag(), *b"NYEC");
        assert!(s.deployment.is_none() && s.eth_url.is_empty());
        let n = s.near.as_ref().unwrap();
        assert_eq!(n.relayer_key_file, d.path().join("keys/hawkeye1.json"));
        assert_eq!(n.gas, 100_000_000_000_000);
        assert_eq!(n.relayer_account.as_str(), "hawkeye1.test.near");
        assert_eq!(s.params.eth_start_block, 42);
        assert_eq!(s.params.deployment, n.domain.deployment());
        assert_eq!(
            s.params.deployment.chain_id,
            hawkeye_core::near::chain_id("sandbox")
        );
        assert_eq!(s.params.mint_mode, MintMode::Threshold { k: 1 });
        // the tag: NYEC accepted, WYEC refused
        let with_tag = |t: &str| {
            Config::parse(&near_sample(
                "regtest",
                "sandbox",
                &format!("tag = \"{t}\"\n"),
            ))
            .unwrap()
            .settings(d.path())
        };
        assert!(with_tag("NYEC").is_ok());
        let e = with_tag("WYEC").unwrap_err().to_string();
        assert!(e.contains("vault tag is \"NYEC\""), "{e}");
        // threshold mode needs an explicit k (no deployment file)
        let e = Config::parse(
            &near_sample("regtest", "sandbox", "").replace("mint_threshold = 1\n", ""),
        )
        .unwrap()
        .settings(d.path())
        .unwrap_err()
        .to_string();
        assert!(e.contains("mint_threshold is required"), "{e}");
        // gas bounds, account ids, the network pairing
        let e = Config::parse(
            &near_sample("regtest", "sandbox", "")
                .replace("start_block = 42\n", "start_block = 42\ngas_tgas = 301\n"),
        )
        .unwrap()
        .settings(d.path())
        .unwrap_err()
        .to_string();
        assert!(e.contains("gas_tgas"), "{e}");
        let e =
            Config::parse(&near_sample("regtest", "sandbox", "").replace("wyec.test.near", "Wyec"))
                .unwrap()
                .settings(d.path())
                .unwrap_err()
                .to_string();
        assert!(e.contains("near.contract_id"), "{e}");
        let e = Config::parse(&near_sample("regtest", "mainnet", ""))
            .unwrap()
            .settings(d.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("mainnet bridge pairs"), "{e}");
        // [near] without the kind, or the kind without [near]
        let e = Config::parse(&format!(
            "{}\n[near]\nrpc_url = \"x\"\nnetwork_id = \"sandbox\"\ncontract_id = \"w.near\"\n\
             relayer_account = \"r.near\"\nrelayer_key_file = \"k.json\"\nstart_block = 1\n",
            sample("regtest", "")
        ))
        .unwrap()
        .settings(d.path())
        .unwrap_err()
        .to_string();
        assert!(e.contains("remove the [near] section"), "{e}");
        let e = Config::parse(&sample("regtest", "").replace(
            "[eth]\nrpc_url = \"http://127.0.0.1:8545\"\ndeployment = \"31337.json\"\nfinality = \"finalized\"\n",
            "[foreign]\nkind = \"near\"\n",
        ))
        .unwrap()
        .settings(d.path())
        .unwrap_err()
        .to_string();
        assert!(e.contains("needs a [near] section"), "{e}");
    }

    /// `[bridge] tag`: `WYEC` by default; four printable ASCII characters.
    #[test]
    fn bridge_tag() {
        let d = dir();
        let s = Config::parse(&sample("regtest", ""))
            .unwrap()
            .settings(d.path())
            .unwrap();
        assert_eq!(s.params.tag(), *b"WYEC");
        assert_eq!(s.params.tag_text(), "WYEC");
        let with = |tag: &str| {
            Config::parse(
                &sample("regtest", "")
                    .replace("[bridge]\n", &format!("[bridge]\ntag = \"{tag}\"\n")),
            )
            .unwrap()
            .settings(d.path())
        };
        assert_eq!(with("WYEC").unwrap().params.tag(), TAG_WYEC);
        // a well-formed tag of another bridge: not the Ethereum bridge's
        let e = with("NYEC").unwrap_err().to_string();
        assert!(e.contains("vault tag is \"WYEC\""), "{e}");
        for bad in ["WYE", "WYECX", "WY C", "YED\\u0000", "WYÉ"] {
            let e = with(bad).unwrap_err().to_string();
            assert!(e.contains("bridge.tag"), "{bad}: {e}");
        }
        assert_eq!(parse_tag("WYEC").unwrap(), TAG_WYEC);
    }

    /// The samples in `config/` stay valid: the NEAR one resolves completely (nothing to read
    /// from disk); the Ethereum one parses (its deployment file is written by a deploy).
    #[test]
    fn example_configs() {
        let d = dir();
        let near = Config::parse(include_str!("../../../config/near-sandbox.example.toml"))
            .unwrap()
            .settings(d.path())
            .unwrap();
        assert_eq!(near.foreign, BridgeKind::Near);
        assert_eq!(near.params.mint_mode, MintMode::Optimistic);
        assert_eq!(
            near.near.unwrap().relayer_key_file,
            d.path().join("keys/hawkeye1.test.near.json")
        );
        let eth =
            Config::parse(include_str!("../../../config/ethereum-anvil.example.toml")).unwrap();
        assert_eq!(eth.foreign.kind.as_deref(), Some("ethereum"));
        assert!(eth.near.is_none() && eth.eth.is_some());
    }

    #[test]
    fn unknown_keys_refused() {
        assert!(Config::parse(&sample("regtest", "[bogus]\nx = 1")).is_err());
    }
}
