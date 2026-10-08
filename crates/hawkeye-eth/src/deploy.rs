//! Deployment: the `deployments/<chainid>.json` file `eth/script/Deploy.s.sol` writes, and an
//! in-process deployer with the same predicted-address order (for anvil tests and the devnet).

use std::path::Path;

use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider};
use serde::{Deserialize, Serialize};

use alloy::primitives::U256;

use crate::bindings::{WrappedYcash, WyecBridge};
use crate::{Error, MintMode, Result};

/// `eth/deployments/<chainid>.json`, as `Deploy.s.sol` writes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub chain_id: u64,
    pub bridge: Address,
    pub token: Address,
    /// The first block the deployment can be in: where a log scanner starts.
    pub deploy_block: u64,
    pub guardians: Vec<Address>,
    pub threshold: u8,
    /// The mode the attestors are meant to run (`"optimistic"` or `"threshold"`), recorded by the
    /// deployer for their configs; the bridge serves both. Absent (pre-CR-W1 files) = threshold.
    #[serde(default = "threshold_mode")]
    pub mint_mode: String,
    /// The bridge's immutable `challengeWindow`, seconds (0 in pre-CR-W1 files).
    #[serde(default)]
    pub challenge_window: u64,
    /// The initial mint rate limit, base units per `cap_window` (0 = none).
    #[serde(default)]
    pub mint_cap: u128,
    /// The rate-limit window, seconds.
    #[serde(default)]
    pub cap_window: u64,
}

/// What [`deploy`] deploys: the constructor's arguments and the mode recorded in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployParams {
    pub guardians: Vec<Address>,
    pub threshold: u8,
    /// Seconds, > 0.
    pub challenge_window: u64,
    /// Base units per `cap_window`; 0 = no limit.
    pub mint_cap: u128,
    /// Seconds; > 0 when `mint_cap > 0`.
    pub cap_window: u64,
    /// Recorded as `mintMode`.
    pub mode: MintMode,
}

impl DeployParams {
    /// `guardians` at `threshold`, a `challenge_window`, no rate limit, mode recorded as `mode`.
    pub fn new(
        guardians: &[Address],
        threshold: u8,
        challenge_window: u64,
        mode: MintMode,
    ) -> Self {
        Self {
            guardians: guardians.to_vec(),
            threshold,
            challenge_window,
            mint_cap: 0,
            cap_window: 0,
            mode,
        }
    }
}

fn threshold_mode() -> String {
    "threshold".into()
}

impl Deployment {
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let s = std::fs::read_to_string(path)
            .map_err(|e| Error::DeploymentFile(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&s)
            .map_err(|e| Error::DeploymentFile(format!("{}: {e}", path.display())))
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let s =
            serde_json::to_string_pretty(self).map_err(|e| Error::DeploymentFile(e.to_string()))?;
        std::fs::write(path, s + "\n")
            .map_err(|e| Error::DeploymentFile(format!("{}: {e}", path.display())))
    }
}

/// Deploys wYEC as wyec-contract-design.md §8 prescribes: the bridge first, constructed with the
/// token address predicted from the deployer's next nonce, then the token; asserts the prediction.
/// The same checks as `eth/script/Deploy.s.sol`: threshold in `1..=guardians`, ≥ 2 on mainnet
/// (plan §3.3), a non-zero challenge window, a cap only with a window. The provider must carry
/// the deployer's wallet; nothing else may send from it meanwhile.
pub async fn deploy(
    provider: &DynProvider,
    deployer: Address,
    p: &DeployParams,
) -> Result<Deployment> {
    let chain_id = provider.get_chain_id().await?;
    if p.threshold == 0 || usize::from(p.threshold) > p.guardians.len() {
        return Err(Error::Config(format!(
            "threshold {} for {} guardians",
            p.threshold,
            p.guardians.len()
        )));
    }
    crate::mode::check_contract_threshold(chain_id, p.threshold)?;
    if p.challenge_window == 0 {
        return Err(Error::Config("challenge window must be > 0".into()));
    }
    if p.mint_cap != 0 && p.cap_window == 0 {
        return Err(Error::Config(
            "cap window must be > 0 with a mint cap".into(),
        ));
    }
    let deploy_block = provider.get_block_number().await? + 1;
    let nonce = provider.get_transaction_count(deployer).pending().await?;
    let predicted = deployer.create(nonce + 1);

    let bridge = *WyecBridge::deploy(
        provider,
        predicted,
        p.guardians.clone(),
        p.threshold,
        p.challenge_window,
        U256::from(p.mint_cap),
        U256::from(p.cap_window),
    )
    .await?
    .address();
    let token = *WrappedYcash::deploy(provider, bridge).await?.address();
    if token != predicted {
        return Err(Error::Prediction {
            predicted,
            got: token,
        });
    }
    Ok(Deployment {
        chain_id,
        bridge,
        token,
        deploy_block,
        guardians: p.guardians.clone(),
        threshold: p.threshold,
        mint_mode: match p.mode {
            MintMode::Optimistic => "optimistic".into(),
            MintMode::Threshold { .. } => "threshold".into(),
        },
        challenge_window: p.challenge_window,
        mint_cap: p.mint_cap,
        cap_window: p.cap_window,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `Deploy.s.sol` writes (eth/README.md shows one).
    #[test]
    fn parses_forge_output() {
        let j = r#"{
          "bridge": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
          "capWindow": 86400,
          "chainId": 31337,
          "challengeWindow": 12,
          "deployBlock": 1,
          "guardians": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"],
          "mintCap": 100000000000,
          "mintMode": "optimistic",
          "threshold": 2,
          "token": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
        }"#;
        let d: Deployment = serde_json::from_str(j).unwrap();
        assert_eq!(d.chain_id, 31337);
        assert_eq!(d.deploy_block, 1);
        assert_eq!(d.guardians.len(), 2);
        assert_eq!(d.threshold, 2);
        assert_eq!(d.mint_mode, "optimistic");
        assert_eq!(d.challenge_window, 12);
        assert_eq!(d.mint_cap, 100_000_000_000);
        assert_eq!(d.cap_window, 86_400);
        // anvil account 0, nonces 0 and 1
        let dep: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        assert_eq!(dep.create(0), d.bridge);
        assert_eq!(dep.create(1), d.token);
        // a pre-CR-W1 file (no mode, window or limit) still reads, as threshold mode
        let old: Deployment = serde_json::from_str(
            r#"{"bridge": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "chainId": 31337,
                "deployBlock": 1, "guardians": [], "threshold": 1,
                "token": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"}"#,
        )
        .unwrap();
        assert_eq!(
            (old.mint_mode.as_str(), old.challenge_window, old.mint_cap),
            ("threshold", 0, 0)
        );
    }
}
