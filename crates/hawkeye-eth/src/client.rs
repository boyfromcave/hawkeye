//! [`EthClient`]: one bridge deployment over standard Ethereum JSON-RPC (HTTP).

use std::time::Duration;

use alloy::contract::{CallBuilder, CallDecoder};
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, TxHash, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::reqwest::Url;

use crate::bindings::{OptimisticMintBridge, WrappedYcash, WyecBridge};
use crate::eip712;
use crate::scanner::Finality;
use crate::{Error, MintMode, Result};

/// Where and what to connect to.
#[derive(Clone, Debug)]
pub struct EthConfig {
    /// HTTP(S) JSON-RPC endpoint.
    pub url: String,
    /// The chain id the endpoint must report (`eth_chainId`); a mismatch refuses to connect.
    pub chain_id: u64,
    /// The `WyecBridge` (or, on anvil, the optimistic double).
    pub bridge: Address,
    /// The wYEC token; when set it must equal `bridge.token()` and have `bridge()` == `bridge`.
    pub token: Option<Address>,
    /// Which blocks count as final for the scanner.
    pub finality: Finality,
    /// Initial block span of one `eth_getLogs` request (halved on error down to one block).
    pub log_chunk: u64,
    /// How long to wait for a submitted transaction's receipt.
    pub receipt_timeout: Duration,
}

impl EthConfig {
    /// Defaults: `finalized` tag without fallback, 2,000-block log chunks, 120 s receipt timeout.
    pub fn new(url: impl Into<String>, chain_id: u64, bridge: Address) -> Self {
        Self {
            url: url.into(),
            chain_id,
            bridge,
            token: None,
            finality: Finality::default(),
            log_chunk: 2_000,
            receipt_timeout: Duration::from_secs(120),
        }
    }
}

/// A mined transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mined {
    pub tx: TxHash,
    pub block_number: u64,
}

/// A mined `burn`, with the nonce the bridge assigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Burned {
    pub mined: Mined,
    pub nonce: U256,
}

/// A pending optimistic proposal (CR-W1 double).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub amount: U256,
    pub to: Address,
    pub proposer: Address,
    /// Unix seconds from which `executeMint` succeeds.
    pub executable_at: u64,
}

/// What [`EthClient::submit_mint`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintSubmitted {
    /// `mint` with k signatures: minted.
    Minted(Mined),
    /// `proposeMint`: the proposal is open until `executable_at`.
    Proposed { mined: Mined, executable_at: u64 },
}

/// The guardian set as the contract holds it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianSet {
    /// In contract order (the order of the last `setGuardians`, not sorted).
    pub guardians: Vec<Address>,
    pub threshold: u8,
    pub admin_nonce: U256,
}

/// One wYEC deployment: reads, the scanner (see `scanner`) and, with a wallet, submissions.
#[derive(Clone, Debug)]
pub struct EthClient {
    pub(crate) provider: DynProvider,
    pub(crate) chain_id: u64,
    pub(crate) bridge: Address,
    pub(crate) token: Address,
    pub(crate) sender: Option<Address>,
    pub(crate) finality: Finality,
    pub(crate) log_chunk: u64,
    receipt_timeout: Duration,
}

impl EthClient {
    /// Connects, checks `eth_chainId`, that both contracts have code, and that bridge and token
    /// point at each other. With `wallet`, transactions are signed locally and sent from it.
    pub async fn connect(cfg: &EthConfig, wallet: Option<PrivateKeySigner>) -> Result<Self> {
        if cfg.log_chunk == 0 {
            return Err(Error::Config("log_chunk must be at least 1".into()));
        }
        let sender = wallet.as_ref().map(|w| w.address());
        let provider = match wallet {
            Some(w) => wallet_provider(&cfg.url, w)?,
            None => ProviderBuilder::new()
                .connect_http(parse_url(&cfg.url)?)
                .erased(),
        };
        Self::from_provider(provider, cfg, sender).await
    }

    /// As [`connect`](Self::connect) over an existing provider (`sender`: the provider's wallet
    /// address, if it has one).
    pub async fn from_provider(
        provider: DynProvider,
        cfg: &EthConfig,
        sender: Option<Address>,
    ) -> Result<Self> {
        let got = provider.get_chain_id().await?;
        if got != cfg.chain_id {
            return Err(Error::WrongChain {
                expected: cfg.chain_id,
                got,
            });
        }
        if provider.get_code_at(cfg.bridge).await?.is_empty() {
            return Err(Error::NoCode(cfg.bridge));
        }
        let bridge_token = WyecBridge::new(cfg.bridge, &provider)
            .token()
            .call()
            .await?;
        let token = cfg.token.unwrap_or(bridge_token);
        if provider.get_code_at(token).await?.is_empty() {
            return Err(Error::NoCode(token));
        }
        let token_bridge = WrappedYcash::new(token, &provider).bridge().call().await?;
        if bridge_token != token || token_bridge != cfg.bridge {
            return Err(Error::PairMismatch {
                bridge: cfg.bridge,
                bridge_token,
                token,
                token_bridge,
            });
        }
        Ok(Self {
            provider,
            chain_id: cfg.chain_id,
            bridge: cfg.bridge,
            token,
            sender,
            finality: cfg.finality,
            log_chunk: cfg.log_chunk,
            receipt_timeout: cfg.receipt_timeout,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn bridge_address(&self) -> Address {
        self.bridge
    }
    pub fn token_address(&self) -> Address {
        self.token
    }
    /// The wallet address transactions are sent from, if any.
    pub fn sender(&self) -> Option<Address> {
        self.sender
    }
    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }
    pub fn bridge(&self) -> WyecBridge::WyecBridgeInstance<DynProvider> {
        WyecBridge::new(self.bridge, self.provider.clone())
    }
    pub fn token(&self) -> WrappedYcash::WrappedYcashInstance<DynProvider> {
        WrappedYcash::new(self.token, self.provider.clone())
    }
    /// The bridge as the CR-W1 optimistic double (calls fail on the real WyecBridge).
    pub fn optimistic(&self) -> OptimisticMintBridge::OptimisticMintBridgeInstance<DynProvider> {
        OptimisticMintBridge::new(self.bridge, self.provider.clone())
    }

    // ------------------------------------------------------------------ digests

    /// The EIP-712 Mint digest for this deployment.
    pub fn mint_digest(&self, lock_id: B256, amount: U256, to: Address) -> B256 {
        eip712::mint_digest(self.chain_id, self.bridge, lock_id, amount, to)
    }

    // ------------------------------------------------------------------ reads

    pub async fn latest_block_number(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }

    /// The current guardians (contract order), threshold and admin nonce.
    pub async fn guardian_set(&self) -> Result<GuardianSet> {
        let b = self.bridge();
        let n = b.guardianCount().call().await?;
        let n =
            u64::try_from(n).map_err(|_| Error::Rpc(format!("guardianCount {n} out of range")))?;
        let mut guardians = Vec::with_capacity(n as usize);
        for i in 0..n {
            guardians.push(b.guardians(U256::from(i)).call().await?);
        }
        Ok(GuardianSet {
            guardians,
            threshold: b.threshold().call().await?,
            admin_nonce: b.adminNonce().call().await?,
        })
    }

    pub async fn guardians(&self) -> Result<Vec<Address>> {
        Ok(self.guardian_set().await?.guardians)
    }
    pub async fn threshold(&self) -> Result<u8> {
        Ok(self.bridge().threshold().call().await?)
    }
    pub async fn is_guardian(&self, who: Address) -> Result<bool> {
        Ok(self.bridge().isGuardian(who).call().await?)
    }
    pub async fn paused(&self) -> Result<bool> {
        Ok(self.bridge().paused().call().await?)
    }
    /// Whether `lockId` has been minted (the contract's replay key).
    pub async fn consumed(&self, lock_id: B256) -> Result<bool> {
        Ok(self.bridge().consumed(lock_id).call().await?)
    }
    /// The nonce the next burn will get (= number of burns so far).
    pub async fn burn_nonce(&self) -> Result<U256> {
        Ok(self.bridge().burnNonce().call().await?)
    }
    pub async fn admin_nonce(&self) -> Result<U256> {
        Ok(self.bridge().adminNonce().call().await?)
    }
    pub async fn total_supply(&self) -> Result<U256> {
        Ok(self.token().totalSupply().call().await?)
    }
    pub async fn balance_of(&self, who: Address) -> Result<U256> {
        Ok(self.token().balanceOf(who).call().await?)
    }

    /// The pending optimistic proposal for `lockId`, if any (CR-W1 double).
    pub async fn proposal(&self, lock_id: B256) -> Result<Option<Proposal>> {
        let p = self.optimistic().proposals(lock_id).call().await?;
        Ok((p.proposer != Address::ZERO).then_some(Proposal {
            amount: p.amount,
            to: p.to,
            proposer: p.proposer,
            executable_at: p.executableAt,
        }))
    }

    /// The optimistic double's challenge window, seconds.
    pub async fn challenge_window(&self) -> Result<u64> {
        Ok(self.optimistic().challengeWindow().call().await?)
    }

    // ------------------------------------------------------------------ mint

    /// `mint(lockId, amount, to, sigs)`: the signatures are recovered against this deployment's
    /// Mint digest and passed in ascending signer order. Anyone may submit; the sender pays gas.
    pub async fn mint<S: AsRef<[u8]>>(
        &self,
        lock_id: B256,
        amount: U256,
        to: Address,
        sigs: &[S],
    ) -> Result<Mined> {
        let sorted = eip712::sort_signatures(self.mint_digest(lock_id, amount, to), sigs)?;
        let sigs: Vec<Bytes> = sorted.into_iter().map(|s| s.signature).collect();
        let r = self
            .send(self.bridge().mint(lock_id, amount, to, sigs))
            .await?;
        mined(&r)
    }

    /// Submits a mint the configured way: `Threshold { k }` needs at least `k` signatures and
    /// calls `mint`; `Optimistic` calls `proposeMint` with the first signature.
    pub async fn submit_mint<S: AsRef<[u8]>>(
        &self,
        mode: MintMode,
        lock_id: B256,
        amount: U256,
        to: Address,
        sigs: &[S],
    ) -> Result<MintSubmitted> {
        mode.check_allowed(self.chain_id)?;
        if sigs.len() < mode.signatures_needed() {
            return Err(Error::TooFewSignatures {
                got: sigs.len(),
                need: mode.signatures_needed(),
            });
        }
        match mode {
            MintMode::Threshold { .. } => Ok(MintSubmitted::Minted(
                self.mint(lock_id, amount, to, sigs).await?,
            )),
            MintMode::Optimistic => {
                let (mined, executable_at) = self
                    .propose_mint(lock_id, amount, to, sigs[0].as_ref())
                    .await?;
                Ok(MintSubmitted::Proposed {
                    mined,
                    executable_at,
                })
            }
        }
    }

    /// `proposeMint(lockId, amount, to, sig)` (CR-W1 double). Returns the proposal's
    /// `executableAt` from its `MintProposed` log.
    pub async fn propose_mint(
        &self,
        lock_id: B256,
        amount: U256,
        to: Address,
        sig: &[u8],
    ) -> Result<(Mined, u64)> {
        eip712::recover(self.mint_digest(lock_id, amount, to), sig)?;
        let r = self
            .send(
                self.optimistic()
                    .proposeMint(lock_id, amount, to, Bytes::copy_from_slice(sig)),
            )
            .await?;
        let ev = r
            .decoded_log::<OptimisticMintBridge::MintProposed>()
            .ok_or(Error::MissingLog {
                event: "MintProposed",
                tx: r.transaction_hash,
            })?;
        Ok((mined(&r)?, ev.data.executableAt))
    }

    /// `challengeMint(lockId)` (CR-W1 double): the sender must be a guardian.
    pub async fn challenge_mint(&self, lock_id: B256) -> Result<Mined> {
        mined(&self.send(self.optimistic().challengeMint(lock_id)).await?)
    }

    /// `executeMint(lockId)` (CR-W1 double): anyone, after the window.
    pub async fn execute_mint(&self, lock_id: B256) -> Result<Mined> {
        mined(&self.send(self.optimistic().executeMint(lock_id)).await?)
    }

    // ------------------------------------------------------------------ burn (CLI / devnet)

    /// `burn(amount, ycashRecipient)` from the wallet: no allowance needed. The recipient is the
    /// plan §4.2 bytes32; this adapter does not validate it (`hawkeye-core` does, before calling).
    pub async fn burn(&self, amount: U256, ycash_recipient: B256) -> Result<Burned> {
        let r = self
            .send(self.bridge().burn(amount, ycash_recipient))
            .await?;
        let ev = r
            .decoded_log::<WyecBridge::BurnToYcash>()
            .ok_or(Error::MissingLog {
                event: "BurnToYcash",
                tx: r.transaction_hash,
            })?;
        Ok(Burned {
            mined: mined(&r)?,
            nonce: ev.data.nonce,
        })
    }

    // ------------------------------------------------------------------ admin acts

    /// `setPaused(paused, sigs)`; `sigs` over [`eip712::set_paused_digest`] at the current
    /// `adminNonce`, sorted here.
    pub async fn set_paused<S: AsRef<[u8]>>(&self, paused: bool, sigs: &[S]) -> Result<Mined> {
        let nonce = self.admin_nonce().await?;
        let d = eip712::set_paused_digest(self.chain_id, self.bridge, paused, nonce);
        let sigs = sorted_bytes(d, sigs)?;
        mined(&self.send(self.bridge().setPaused(paused, sigs)).await?)
    }

    /// `setGuardians(guardians, threshold, sigs)`; `sigs` over
    /// [`eip712::set_guardians_digest`] at the current `adminNonce`, sorted here.
    pub async fn set_guardians<S: AsRef<[u8]>>(
        &self,
        guardians: &[Address],
        threshold: u8,
        sigs: &[S],
    ) -> Result<Mined> {
        let nonce = self.admin_nonce().await?;
        let d =
            eip712::set_guardians_digest(self.chain_id, self.bridge, guardians, threshold, nonce);
        let sigs = sorted_bytes(d, sigs)?;
        mined(
            &self
                .send(
                    self.bridge()
                        .setGuardians(guardians.to_vec(), threshold, sigs),
                )
                .await?,
        )
    }

    /// `setBridge(newBridge, sigs)`; retires this bridge.
    pub async fn set_bridge<S: AsRef<[u8]>>(
        &self,
        new_bridge: Address,
        sigs: &[S],
    ) -> Result<Mined> {
        let nonce = self.admin_nonce().await?;
        let d = eip712::set_bridge_digest(self.chain_id, self.bridge, new_bridge, nonce);
        let sigs = sorted_bytes(d, sigs)?;
        mined(&self.send(self.bridge().setBridge(new_bridge, sigs)).await?)
    }

    // ------------------------------------------------------------------ internals

    /// Sends (after the node's gas estimate, which surfaces a revert with its decoded reason) and
    /// waits for the receipt.
    async fn send<D: CallDecoder>(
        &self,
        call: CallBuilder<&DynProvider, D, Ethereum>,
    ) -> Result<TransactionReceipt> {
        if self.sender.is_none() {
            return Err(Error::ReadOnly);
        }
        let pending = call.send().await?;
        let tx = *pending.tx_hash();
        let receipt = pending
            .with_timeout(Some(self.receipt_timeout))
            .get_receipt()
            .await?;
        if !receipt.status() {
            return Err(Error::Reverted {
                reason: "transaction reverted on chain".into(),
                tx: Some(tx),
            });
        }
        Ok(receipt)
    }
}

/// An HTTP provider that signs with `signer`: gas estimation (EIP-1559 fees), chain id, and
/// **simple** nonce management (the `pending` transaction count, fetched per transaction).
///
/// Not alloy's default cached nonce manager: it reserves a nonce concurrently with gas
/// estimation, so a call that reverts at estimation (a replayed `lockId`, a challenged proposal)
/// burns a nonce and every later transaction from the account waits forever behind the gap.
/// Hawkeye sends one transaction at a time per account, so re-reading the count costs nothing.
pub fn wallet_provider(url: &str, signer: PrivateKeySigner) -> Result<DynProvider> {
    Ok(ProviderBuilder::new()
        .disable_recommended_fillers()
        .with_gas_estimation()
        .with_simple_nonce_management()
        .fetch_chain_id()
        .wallet(signer)
        .connect_http(parse_url(url)?)
        .erased())
}

fn parse_url(url: &str) -> Result<Url> {
    url.parse()
        .map_err(|e| Error::Config(format!("url {url:?}: {e}")))
}

fn sorted_bytes<S: AsRef<[u8]>>(digest: B256, sigs: &[S]) -> Result<Vec<Bytes>> {
    Ok(eip712::sort_signatures(digest, sigs)?
        .into_iter()
        .map(|s| s.signature)
        .collect())
}

fn mined(r: &TransactionReceipt) -> Result<Mined> {
    Ok(Mined {
        tx: r.transaction_hash,
        block_number: r
            .block_number
            .ok_or_else(|| Error::Rpc("receipt without block number".into()))?,
    })
}
