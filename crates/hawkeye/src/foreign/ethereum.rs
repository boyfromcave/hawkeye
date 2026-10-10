//! [`EthereumChain`]: the wyec `WyecBridge` + `WrappedYcash` deployment behind
//! [`ForeignChain`] — a thin mapping of [`hawkeye_eth::EthClient`] (alloy, standard JSON-RPC) to
//! the neutral types, with the EIP-712 attestation scheme of main plan §4.4.
//!
//! Nothing here decides anything: the calls, their order, the error texts and the revert names
//! are the ones the engine made directly before the adapter existed (NEAR plan NH3, "no
//! behaviour change").

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use anyhow::anyhow;
use hawkeye_core::bytes::Hash32;
use hawkeye_core::eip712::Domain;
use hawkeye_core::{Deployment, EthAddress, PubKey33, SecretKey};
use hawkeye_eth::bindings::WyecBridge;
use hawkeye_eth::{BridgeEvent, EthClient, EthConfig, MintMode, MintSubmitted, U256};

use super::{
    Account, AttestationScheme, BoxFut, BridgeInfo, BridgeKind, Burned, EventMeta, ForeignChain,
    ForeignError, ForeignEvent, ForeignResult, Guardian, Mined, Proposal, ProposalStatus, Proposed,
    ScanBatch, Scanned, TxId,
};
use crate::config::Settings;
use crate::convert::{addr, b256, eth_addr};
use crate::keys::eth_signer;

/// One wyec deployment on an Ethereum chain, with the member key's account as the sender.
#[derive(Clone, Debug)]
pub struct EthereumChain {
    client: EthClient,
    scheme: Eip712Scheme,
}

/// The EIP-712 attestation scheme of one `WyecBridge` (main plan §4.4): digests under the
/// domain `(chainId, bridge)`, 65-byte `r ‖ s ‖ v` signatures with `v ∈ {27, 28}`, guardians
/// identified by the member key's Ethereum address.
#[derive(Clone, Copy, Debug)]
pub struct Eip712Scheme {
    domain: Domain,
}

impl Eip712Scheme {
    /// The scheme of the bridge at `bridge` on chain `chain_id`.
    pub fn new(chain_id: u64, bridge: EthAddress) -> Self {
        Self {
            domain: Domain::new(chain_id, bridge),
        }
    }
}

impl EthereumChain {
    /// Over a connected client (its chain id and bridge are the EIP-712 domain).
    pub fn new(client: EthClient) -> Self {
        let scheme = Eip712Scheme::new(client.chain_id(), eth_addr(&client.bridge_address()));
        Self { client, scheme }
    }

    /// Connect the configured deployment (`[eth]`), sending from `key`'s account.
    pub async fn connect(s: &Settings, key: &SecretKey) -> anyhow::Result<Self> {
        let mut ec = EthConfig::new(
            s.eth_url.clone(),
            s.deployment.chain_id,
            s.deployment.bridge,
        );
        ec.token = Some(s.deployment.token);
        ec.finality = s.finality;
        let client = EthClient::connect(&ec, Some(eth_signer(key)?))
            .await
            .map_err(|e| anyhow!("ethereum {}: {e}", s.eth_url))?;
        Ok(Self::new(client))
    }

    /// The underlying client.
    pub fn client(&self) -> &EthClient {
        &self.client
    }
}

/// `hawkeye_eth`'s error, its text kept; a revert keeps its decoded reason.
fn fe(e: hawkeye_eth::Error) -> ForeignError {
    match &e {
        hawkeye_eth::Error::Reverted { reason, .. } => {
            ForeignError::revert(e.to_string(), reason.clone())
        }
        _ => ForeignError::new(e.to_string()),
    }
}

fn core_err(e: hawkeye_core::Error) -> ForeignError {
    ForeignError::new(e.to_string())
}

/// A `U256` amount or limit as `u128`, saturating.
fn sat(v: U256) -> u128 {
    u128::try_from(v).unwrap_or(u128::MAX)
}

fn account(a: &alloy::primitives::Address) -> Account {
    Account::Ethereum(eth_addr(a))
}

fn guardian(a: &alloy::primitives::Address) -> Guardian {
    Guardian::Ethereum(eth_addr(a))
}

/// The address of an Ethereum account (an account of another chain is refused).
fn eth_of(a: &Account) -> ForeignResult<EthAddress> {
    a.ethereum()
        .copied()
        .ok_or_else(|| ForeignError::new(format!("{a} is not an Ethereum address")))
}

fn mined(m: hawkeye_eth::Mined) -> Mined {
    Mined {
        tx: TxId(m.tx.0),
        height: m.block_number,
    }
}

fn event(ev: &BridgeEvent) -> ForeignEvent {
    match ev {
        BridgeEvent::Burn {
            nonce,
            from,
            amount,
            ycash_recipient,
        } => ForeignEvent::Burn {
            nonce: u64::try_from(*nonce).unwrap_or(u64::MAX),
            from: account(from),
            amount: sat(*amount),
            ycash_recipient: ycash_recipient.0,
        },
        BridgeEvent::Minted {
            lock_id,
            to,
            amount,
        } => ForeignEvent::Minted {
            lock_id: lock_id.0,
            to: account(to),
            amount: sat(*amount),
        },
        BridgeEvent::MintProposed {
            lock_id,
            proposal_id,
            proposer,
            to,
            amount,
            eta,
        } => ForeignEvent::MintProposed {
            lock_id: lock_id.0,
            proposal_id: *proposal_id,
            proposer: guardian(proposer),
            to: account(to),
            amount: sat(*amount),
            eta: *eta,
        },
        BridgeEvent::MintChallenged {
            lock_id,
            proposal_id,
            challenger,
        } => ForeignEvent::MintChallenged {
            lock_id: lock_id.0,
            proposal_id: *proposal_id,
            challenger: guardian(challenger),
        },
        BridgeEvent::GuardiansChanged {
            guardians,
            threshold,
        } => ForeignEvent::GuardiansChanged {
            count: guardians.len(),
            threshold: *threshold,
        },
        BridgeEvent::MintLimitChanged {
            mint_cap,
            cap_window,
        } => ForeignEvent::MintLimitChanged {
            mint_cap: sat(*mint_cap),
            cap_window: sat(*cap_window),
        },
        BridgeEvent::Paused { paused, account: a } => ForeignEvent::Paused {
            paused: *paused,
            by: account(a),
        },
    }
}

impl AttestationScheme for Eip712Scheme {
    fn guardian_of(&self, member: &PubKey33) -> ForeignResult<Guardian> {
        hawkeye_core::eth::address_from_pubkey(member)
            .map(Guardian::Ethereum)
            .map_err(core_err)
    }

    fn mint_digest(&self, lock_id: &Hash32, amount: u64, to: &Account) -> ForeignResult<Hash32> {
        Ok(self.domain.mint_digest(lock_id, amount, &eth_of(to)?))
    }

    fn challenge_digest(&self, lock_id: &Hash32, proposal_id: u128) -> Hash32 {
        self.domain.challenge_digest(lock_id, proposal_id)
    }

    fn sign(&self, key: &SecretKey, digest: &Hash32) -> ForeignResult<[u8; 65]> {
        hawkeye_core::eth::sign_digest(key, digest).map_err(core_err)
    }

    fn recover(&self, digest: &Hash32, sig: &[u8]) -> ForeignResult<Guardian> {
        hawkeye_core::eth::recover_address(digest, sig)
            .map(Guardian::Ethereum)
            .map_err(core_err)
    }

    fn parse_account(&self, text: &str) -> ForeignResult<Account> {
        EthAddress::parse(text)
            .map(Account::Ethereum)
            .map_err(core_err)
    }
}

impl AttestationScheme for EthereumChain {
    fn guardian_of(&self, member: &PubKey33) -> ForeignResult<Guardian> {
        self.scheme.guardian_of(member)
    }

    fn mint_digest(&self, lock_id: &Hash32, amount: u64, to: &Account) -> ForeignResult<Hash32> {
        self.scheme.mint_digest(lock_id, amount, to)
    }

    fn challenge_digest(&self, lock_id: &Hash32, proposal_id: u128) -> Hash32 {
        self.scheme.challenge_digest(lock_id, proposal_id)
    }

    fn sign(&self, key: &SecretKey, digest: &Hash32) -> ForeignResult<[u8; 65]> {
        self.scheme.sign(key, digest)
    }

    fn recover(&self, digest: &Hash32, sig: &[u8]) -> ForeignResult<Guardian> {
        self.scheme.recover(digest, sig)
    }

    fn parse_account(&self, text: &str) -> ForeignResult<Account> {
        self.scheme.parse_account(text)
    }
}

impl ForeignChain for EthereumChain {
    fn kind(&self) -> BridgeKind {
        BridgeKind::Ethereum
    }

    fn deployment(&self) -> Deployment {
        Deployment {
            chain_id: self.client.chain_id(),
            bridge: eth_addr(&self.client.bridge_address()),
        }
    }

    fn check_bridge(&self, mainnet: bool) -> BoxFut<'_, BridgeInfo> {
        Box::pin(async move {
            let threshold = self
                .client
                .threshold()
                .await
                .map_err(|e| ForeignError::new(format!("bridge threshold: {e}")))?;
            let challenge_window = self.client.challenge_window().await.map_err(|e| {
                ForeignError::new(format!(
                    "bridge challengeWindow (is it the wyec CR-W1 bridge?): {e}"
                ))
            })?;
            let chain = if mainnet {
                hawkeye_eth::mode::MAINNET
            } else {
                self.client.chain_id()
            };
            hawkeye_eth::mode::check_contract_threshold(chain, threshold)
                .map_err(|e| ForeignError::new(format!("{e} (plan §3.3)")))?;
            Ok(BridgeInfo {
                threshold,
                challenge_window,
            })
        })
    }

    fn finalized_height(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { self.client.finalized_block_number().await.map_err(fe) })
    }

    fn scan(&self, from: u64, to: u64) -> BoxFut<'_, ScanBatch> {
        Box::pin(async move {
            let events = self.client.scan(from, to).await.map_err(fe)?;
            let to_hash = self
                .client
                .provider()
                .get_block_by_number(BlockNumberOrTag::Number(to))
                .await
                .map_err(|e| ForeignError::new(e.to_string()))?
                .ok_or_else(|| ForeignError::new(format!("block {to} not found")))?
                .header
                .hash;
            Ok(ScanBatch {
                events: events
                    .iter()
                    .map(|ev| Scanned {
                        meta: EventMeta {
                            height: ev.meta.block_number,
                            block_hash: ev.meta.block_hash.0,
                            tx: TxId(ev.meta.tx_hash.0),
                            index: ev.meta.log_index,
                        },
                        event: event(&ev.event),
                    })
                    .collect(),
                to_hash: to_hash.0,
            })
        })
    }

    fn now(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { self.client.latest_timestamp().await.map_err(fe) })
    }

    fn guardians(&self) -> BoxFut<'_, Vec<Guardian>> {
        Box::pin(async move {
            Ok(self
                .client
                .guardians()
                .await
                .map_err(fe)?
                .iter()
                .map(guardian)
                .collect())
        })
    }

    fn threshold(&self) -> BoxFut<'_, u8> {
        Box::pin(async move { self.client.threshold().await.map_err(fe) })
    }

    fn challenge_window(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { self.client.challenge_window().await.map_err(fe) })
    }

    fn consumed(&self, lock_id: Hash32) -> BoxFut<'_, bool> {
        Box::pin(async move { self.client.consumed(b256(&lock_id)).await.map_err(fe) })
    }

    fn proposal(&self, lock_id: Hash32) -> BoxFut<'_, Option<Proposal>> {
        Box::pin(async move {
            Ok(self
                .client
                .proposal(b256(&lock_id))
                .await
                .map_err(fe)?
                .map(|p| Proposal {
                    id: p.id,
                    amount: sat(p.amount),
                    to: account(&p.to),
                    proposer: guardian(&p.proposer),
                    eta: p.eta,
                }))
        })
    }

    fn proposal_status(&self, lock_id: Hash32) -> BoxFut<'_, ProposalStatus> {
        Box::pin(async move {
            Ok(
                match self
                    .client
                    .proposal_status(b256(&lock_id))
                    .await
                    .map_err(fe)?
                {
                    hawkeye_eth::ProposalStatus::None => ProposalStatus::None,
                    hawkeye_eth::ProposalStatus::Pending => ProposalStatus::Pending,
                    hawkeye_eth::ProposalStatus::Ready => ProposalStatus::Ready,
                    hawkeye_eth::ProposalStatus::Void => ProposalStatus::Void,
                },
            )
        })
    }

    fn vetoed(&self, lock_id: Hash32, who: Guardian) -> BoxFut<'_, bool> {
        Box::pin(async move {
            let who = who
                .ledger_eth()
                .ok_or_else(|| ForeignError::new(format!("{who} is not an Ethereum guardian")))?;
            self.client
                .vetoed(b256(&lock_id), addr(&who))
                .await
                .map_err(fe)
        })
    }

    fn mint_available(&self) -> BoxFut<'_, u128> {
        Box::pin(async move { self.client.mint_available().await.map(sat).map_err(fe) })
    }

    fn total_supply(&self) -> BoxFut<'_, u128> {
        Box::pin(async move { self.client.total_supply().await.map(sat).map_err(fe) })
    }

    fn paused(&self) -> BoxFut<'_, bool> {
        Box::pin(async move { self.client.paused().await.map_err(fe) })
    }

    fn mint_signatures(&self, tx: TxId) -> BoxFut<'_, Vec<Vec<u8>>> {
        Box::pin(async move {
            let tx = self
                .client
                .provider()
                .get_transaction_by_hash(b256(&tx.0))
                .await
                .map_err(|e| ForeignError::new(e.to_string()))?;
            Ok(match tx {
                Some(tx) => {
                    let input = tx.input();
                    if let Ok(c) = WyecBridge::mintCall::abi_decode(input) {
                        c.sigs.into_iter().map(|b| b.to_vec()).collect()
                    } else if let Ok(c) = WyecBridge::proposeMintCall::abi_decode(input) {
                        vec![c.sig.to_vec()]
                    } else {
                        vec![]
                    }
                }
                None => vec![],
            })
        })
    }

    fn threshold_mint(
        &self,
        k: u8,
        lock_id: Hash32,
        amount: u64,
        to: Account,
        sigs: Vec<[u8; 65]>,
    ) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            let to = eth_of(&to)?;
            match self
                .client
                .submit_mint(
                    MintMode::Threshold { k },
                    b256(&lock_id),
                    U256::from(amount),
                    addr(&to),
                    &sigs,
                )
                .await
                .map_err(fe)?
            {
                MintSubmitted::Minted(m) => Ok(mined(m)),
                MintSubmitted::Proposed { .. } => Err(ForeignError::new(
                    "the threshold mint opened a proposal instead",
                )),
            }
        })
    }

    fn propose_mint(
        &self,
        lock_id: Hash32,
        amount: u64,
        to: Account,
        sig: [u8; 65],
    ) -> BoxFut<'_, Proposed> {
        Box::pin(async move {
            let to = eth_of(&to)?;
            match self
                .client
                .propose_mint(b256(&lock_id), U256::from(amount), addr(&to), &sig)
                .await
                .map_err(fe)?
            {
                MintSubmitted::Proposed {
                    mined: m,
                    proposal_id,
                    eta,
                } => Ok(Proposed {
                    mined: mined(m),
                    proposal_id,
                    eta,
                }),
                MintSubmitted::Minted(_) => {
                    Err(ForeignError::new("proposeMint returned no proposal"))
                }
            }
        })
    }

    fn challenge_mint(
        &self,
        lock_id: Hash32,
        proposal_id: u128,
        sig: [u8; 65],
    ) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            self.client
                .challenge_mint(b256(&lock_id), proposal_id, &sig)
                .await
                .map(mined)
                .map_err(fe)
        })
    }

    fn execute_mint(&self, lock_id: Hash32) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            self.client
                .execute_mint(b256(&lock_id))
                .await
                .map(mined)
                .map_err(fe)
        })
    }

    fn burn(&self, amount: u64, ycash_recipient: Hash32) -> BoxFut<'_, Burned> {
        Box::pin(async move {
            let b = self
                .client
                .burn(U256::from(amount), b256(&ycash_recipient))
                .await
                .map_err(fe)?;
            Ok(Burned {
                mined: mined(b.mined),
                nonce: u64::try_from(b.nonce).unwrap_or(u64::MAX),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hawkeye_eth::B256;

    /// The neutral transaction id prints as alloy prints a `B256` (the CLI's `txhash`, logs).
    #[test]
    fn tx_ids_print_as_alloy_does() {
        let h = [0x5a; 32];
        assert_eq!(TxId(h).to_string(), B256::from(h).to_string());
        let mut g = [0u8; 32];
        g[0] = 0x01;
        g[31] = 0xff;
        assert_eq!(TxId(g).to_string(), B256::from(g).to_string());
    }

    /// The neutral rule constants are the Ethereum adapter's.
    #[test]
    fn constants_agree() {
        assert_eq!(
            super::super::MAINNET_MIN_THRESHOLD,
            hawkeye_eth::mode::MAINNET_MIN_THRESHOLD
        );
        let c = hawkeye_core::BridgeKind::Ethereum;
        assert_eq!(c.memo_magic(), hawkeye_core::memo::MEMO_MAGIC);
        assert_eq!(c.tag(), hawkeye_core::template::TAG_WYEC);
    }

    /// Accounts and guardians print as alloy prints an `Address` (EIP-55).
    #[test]
    fn accounts_print_as_alloy_does() {
        let a = alloy::primitives::Address::from([0xcd; 20]);
        assert_eq!(account(&a).to_string(), a.to_string());
        assert_eq!(guardian(&a).to_string(), a.to_string());
    }

    /// Reverts keep their decoded reason; other errors keep their text.
    #[test]
    fn errors_keep_text_and_reason() {
        let e = fe(hawkeye_eth::Error::Reverted {
            reason: "ProposalPending(ProposalPending { lockId: 0x00 })".into(),
            tx: None,
        });
        assert!(e.is_revert("ProposalPending"));
        assert!(!e.is_revert("LockConsumed"));
        assert!(e.to_string().starts_with("reverted: ProposalPending"));
        let e = fe(hawkeye_eth::Error::Rpc("boom".into()));
        assert_eq!(e.to_string(), "rpc: boom");
        assert!(!e.is_revert("boom"));
    }

    /// The EIP-712 scheme through the trait equals the core domain's digests and signatures,
    /// and recovers to the member key's guardian address.
    #[test]
    fn attestation_scheme_is_eip712() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        let bridge = EthAddress([0x5f; 20]);
        let domain = Domain::new(31337, bridge);
        let to = EthAddress([0x11; 20]);
        let lock = [3u8; 32];
        let scheme = Eip712Scheme::new(31337, bridge);
        let d = scheme
            .mint_digest(&lock, 5, &Account::Ethereum(to))
            .unwrap();
        assert_eq!(d, domain.mint_digest(&lock, 5, &to));
        assert_eq!(
            scheme.challenge_digest(&lock, 9),
            domain.challenge_digest(&lock, 9)
        );
        let sig = scheme.sign(&key, &d).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28);
        assert_eq!(
            scheme.recover(&d, &sig).unwrap(),
            scheme.guardian_of(&key.public_key()).unwrap()
        );
        assert_eq!(
            scheme.guardian_of(&key.public_key()).unwrap(),
            Guardian::Ethereum(key.eth_address())
        );
        assert!(
            scheme
                .mint_digest(
                    &lock,
                    5,
                    &Account::Near(hawkeye_core::AccountId::parse("a.near").unwrap())
                )
                .is_err()
        );
        assert_eq!(
            scheme.parse_account(&to.to_checksum()).unwrap(),
            Account::Ethereum(to)
        );
    }
}
