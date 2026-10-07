//! Deployment: the `deployments/<chainid>.json` file `eth/script/Deploy.s.sol` writes, and an
//! in-process deployer with the same predicted-address order (for anvil tests and the devnet).

use std::path::Path;

use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider};
use serde::{Deserialize, Serialize};

use crate::bindings::{OptimisticMintBridge, WrappedYcash, WyecBridge};
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
    /// `"threshold"` or `"optimistic"` (the CR-W1 double, anvil only). Absent = threshold.
    #[serde(default = "threshold_mode")]
    pub mint_mode: String,
    /// Seconds; 0 unless optimistic.
    #[serde(default)]
    pub challenge_window: u64,
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
/// `MintMode::Optimistic` deploys the CR-W1 **test double** and is refused off chain id 31337.
/// The provider must carry the deployer's wallet; nothing else may send from it meanwhile.
pub async fn deploy(
    provider: &DynProvider,
    deployer: Address,
    guardians: &[Address],
    threshold: u8,
    mode: MintMode,
    challenge_window: u64,
) -> Result<Deployment> {
    let chain_id = provider.get_chain_id().await?;
    if mode == MintMode::Optimistic && chain_id != 31_337 {
        return Err(Error::Config(
            "the optimistic bridge is a test double: anvil only".into(),
        ));
    }
    let deploy_block = provider.get_block_number().await? + 1;
    let nonce = provider.get_transaction_count(deployer).pending().await?;
    let predicted = deployer.create(nonce + 1);

    let bridge = match mode {
        MintMode::Optimistic => *OptimisticMintBridge::deploy(
            provider,
            predicted,
            guardians.to_vec(),
            threshold,
            challenge_window,
        )
        .await?
        .address(),
        MintMode::Threshold { .. } => {
            *WyecBridge::deploy(provider, predicted, guardians.to_vec(), threshold)
                .await?
                .address()
        }
    };
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
        guardians: guardians.to_vec(),
        threshold,
        mint_mode: match mode {
            MintMode::Optimistic => "optimistic".into(),
            MintMode::Threshold { .. } => "threshold".into(),
        },
        challenge_window: if mode == MintMode::Optimistic {
            challenge_window
        } else {
            0
        },
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
          "chainId": 31337,
          "challengeWindow": 0,
          "deployBlock": 1,
          "guardians": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"],
          "mintMode": "threshold",
          "threshold": 1,
          "token": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
        }"#;
        let d: Deployment = serde_json::from_str(j).unwrap();
        assert_eq!(d.chain_id, 31337);
        assert_eq!(d.deploy_block, 1);
        assert_eq!(d.guardians.len(), 2);
        assert_eq!(d.threshold, 1);
        // anvil account 0, nonces 0 and 1
        let dep: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        assert_eq!(dep.create(0), d.bridge);
        assert_eq!(dep.create(1), d.token);
    }
}
