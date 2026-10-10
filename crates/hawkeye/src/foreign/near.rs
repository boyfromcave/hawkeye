//! [`NearChain`]: the `wyec-near` contract (`near/`, NEAR plan §3) behind [`ForeignChain`] — a
//! mapping of [`hawkeye_near::WyecNear`] (standard NEAR JSON-RPC) to the neutral types, with the
//! Borsh-SHA256 attestation scheme of NEAR plan §2.3 ([`NearScheme`]).
//!
//! What differs from Ethereum, and how the engine still sees one bridge:
//!
//! - **Sender.** Transactions are sent and paid by the operator's relayer account (its ed25519
//!   key, `[near] relayer_key_file`), never by the member key; the member key only attests. The
//!   relayer's envelope is rebuilt on a retry; the attestation inside it is the engine's
//!   sign-once record.
//! - **Scan.** By final block height, through the contract's state changes and receipts
//!   ([`WyecNear::scan`]); a burn's "transaction" id is `SHA256(borsh(BurnRecord))`, the `HKN1`
//!   memo's `data` (so the ledger, the memo and the matcher need nothing NEAR-specific), and a
//!   mint's or proposal's is its receipt id (what [`ForeignChain::mint_signatures`] reads back).
//! - **Errors.** The contract's panic messages map to the Ethereum bridge's error names the engine
//!   matches (`wyec: lock consumed` → `LockConsumed`, …; `hawkeye_near::error::PANIC_NAMES`).

use std::path::Path;

use anyhow::{Context, anyhow};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::near::{self as cnear, BridgeMessage, Domain};
use hawkeye_core::{AccountId, Deployment, PubKey33, SecretKey};
use hawkeye_near::contract::{self as wc, NearEvent, sort_signatures};
use hawkeye_near::{BlockRef, KeyFile, WyecNear};

use super::{
    Account, AttestationScheme, BoxFut, BridgeInfo, BridgeKind, Burned, EventMeta, ForeignChain,
    ForeignError, ForeignEvent, ForeignResult, Guardian, MAINNET_MIN_THRESHOLD, Mined, Proposal,
    ProposalStatus, Proposed, ScanBatch, Scanned, TxId,
};
use crate::config::Settings;

/// Most NEAR blocks one scan covers (the scanner reads block by block: ~1 RPC call per height,
/// more for a height that touched the contract; NEAR makes about one block a second).
pub const NEAR_MAX_SCAN_BLOCKS: u64 = 300;

/// The attestation scheme of one `wyec-near` deployment (NEAR plan §2.3, N-6): digests
/// `SHA256("HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖ borsh(msg))`, 65-byte
/// `r ‖ s ‖ v` signatures with `v ∈ {0, 1}`, guardians identified by the 64-byte uncompressed
/// member key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearScheme {
    domain: Domain,
}

impl NearScheme {
    /// The scheme of `domain`.
    pub fn new(domain: Domain) -> Self {
        Self { domain }
    }

    /// The digest domain.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

/// One `wyec-near` deployment, with the operator's relayer as the sender.
#[derive(Debug)]
pub struct NearChain {
    client: WyecNear,
    scheme: NearScheme,
}

fn core_err(e: hawkeye_core::Error) -> ForeignError {
    ForeignError::new(e.to_string())
}

/// `hawkeye_near`'s error, its text kept; a contract panic keeps its name and message
/// (`LockConsumed(wyec: lock consumed)`), which [`ForeignError::is_revert`] matches.
pub fn fe(e: hawkeye_near::Error) -> ForeignError {
    match (e.revert_name(), &e) {
        (Some(name), hawkeye_near::Error::Panic(m)) => {
            ForeignError::revert(e.to_string(), format!("{name}({m})"))
        }
        _ => ForeignError::new(e.to_string()),
    }
}

fn near_of(a: &Account) -> ForeignResult<&AccountId> {
    a.near()
        .ok_or_else(|| ForeignError::new(format!("{a} is not a NEAR account")))
}

fn key_of(g: &Guardian) -> ForeignResult<&[u8; 64]> {
    match g {
        Guardian::Secp256k1(k) => Ok(k),
        Guardian::Ethereum(_) => Err(ForeignError::new(format!("{g} is not a NEAR guardian"))),
    }
}

fn proposal_id(id: u128) -> ForeignResult<u64> {
    u64::try_from(id).map_err(|_| ForeignError::new(format!("proposal id {id} is above u64")))
}

fn mined(o: &wc::CallOutcome) -> Mined {
    Mined {
        tx: TxId(o.tx),
        height: o.height,
    }
}

fn event(e: &NearEvent) -> ForeignEvent {
    match e {
        NearEvent::Burn(r) => ForeignEvent::Burn {
            nonce: r.nonce,
            from: Account::Near(r.from.clone()),
            amount: r.amount,
            ycash_recipient: r.ycash_recipient,
        },
        NearEvent::Minted {
            lock_id,
            receiver_id,
            amount,
        } => ForeignEvent::Minted {
            lock_id: *lock_id,
            to: Account::Near(receiver_id.clone()),
            amount: *amount,
        },
        NearEvent::Proposed {
            lock_id,
            proposal_id,
            proposer,
            receiver_id,
            amount,
            eta,
        } => ForeignEvent::MintProposed {
            lock_id: *lock_id,
            proposal_id: u128::from(*proposal_id),
            proposer: Guardian::Secp256k1(*proposer),
            to: Account::Near(receiver_id.clone()),
            amount: *amount,
            eta: *eta,
        },
        NearEvent::Challenged {
            lock_id,
            proposal_id,
            challenger,
        } => ForeignEvent::MintChallenged {
            lock_id: *lock_id,
            proposal_id: u128::from(*proposal_id),
            challenger: Guardian::Secp256k1(*challenger),
        },
        NearEvent::GuardiansChanged { count, threshold } => ForeignEvent::GuardiansChanged {
            count: *count,
            threshold: *threshold,
        },
        NearEvent::MintLimitChanged {
            mint_cap,
            cap_window,
        } => ForeignEvent::MintLimitChanged {
            mint_cap: *mint_cap,
            cap_window: u128::from(*cap_window),
        },
        NearEvent::Paused { paused, by } => ForeignEvent::Paused {
            paused: *paused,
            by: match AccountId::parse(by) {
                Ok(a) => Account::Near(a),
                // a predecessor is always a valid account id; never reached
                Err(_) => Account::Ethereum(hawkeye_core::EthAddress::ZERO),
            },
        },
    }
}

impl NearChain {
    /// Over a client of the deployment.
    pub fn new(client: WyecNear) -> Self {
        let scheme = NearScheme::new(client.domain().clone());
        Self { client, scheme }
    }

    /// Connect the configured deployment (`[near]`), sending from the relayer key file.
    pub fn connect(s: &Settings) -> anyhow::Result<Self> {
        Self::connect_with(s, None)
    }

    /// As [`connect`](Self::connect), sending from `key_file` instead of the relayer's (the
    /// CLI's `burn --near-key`).
    pub fn connect_with(s: &Settings, key_file: Option<&Path>) -> anyhow::Result<Self> {
        let n = s
            .near
            .as_ref()
            .ok_or_else(|| anyhow!("no [near] section: the bridge is not on NEAR"))?;
        let path = key_file.unwrap_or(&n.relayer_key_file);
        let key = KeyFile::read(path).map_err(|e| anyhow!("{e}"))?;
        if key_file.is_none() && key.account_id != n.relayer_account {
            anyhow::bail!(
                "near.relayer_key_file {} is the key of {}, not of near.relayer_account {}",
                path.display(),
                key.account_id,
                n.relayer_account
            );
        }
        let client = WyecNear::new(&n.rpc_url, n.domain.clone(), Some(key), n.gas)
            .map_err(|e| anyhow!("near {}: {e}", n.rpc_url))?;
        Ok(Self::new(client))
    }

    /// The underlying client.
    pub fn client(&self) -> &WyecNear {
        &self.client
    }
}

/// [`ForeignChain`] over NEAR as the configured relayer, or (`key_file`) as another account
/// (the CLI's `burn --near-key`).
pub async fn connect_as(
    s: &Settings,
    key_file: Option<&Path>,
) -> anyhow::Result<std::sync::Arc<dyn ForeignChain>> {
    let c = NearChain::connect_with(s, key_file).context("NEAR adapter")?;
    Ok(std::sync::Arc::new(c))
}

impl AttestationScheme for NearScheme {
    fn guardian_of(&self, member: &PubKey33) -> ForeignResult<Guardian> {
        cnear::guardian_key(member)
            .map(Guardian::Secp256k1)
            .map_err(core_err)
    }

    fn mint_digest(&self, lock_id: &Hash32, amount: u64, to: &Account) -> ForeignResult<Hash32> {
        Ok(self.domain.digest(&BridgeMessage::Mint {
            lock_id: *lock_id,
            amount: u128::from(amount),
            receiver_id: near_of(to)?.clone(),
        }))
    }

    fn challenge_digest(&self, lock_id: &Hash32, proposal_id: u128) -> Hash32 {
        self.domain.digest(&BridgeMessage::Challenge {
            lock_id: *lock_id,
            // NEAR proposal ids are u64; a larger id names no proposal
            proposal_id: u64::try_from(proposal_id).unwrap_or(u64::MAX),
        })
    }

    fn sign(&self, key: &SecretKey, digest: &Hash32) -> ForeignResult<[u8; 65]> {
        cnear::sign_digest(key, digest).map_err(core_err)
    }

    fn recover(&self, digest: &Hash32, sig: &[u8]) -> ForeignResult<Guardian> {
        cnear::recover_guardian(digest, sig)
            .map(Guardian::Secp256k1)
            .map_err(core_err)
    }

    fn parse_account(&self, text: &str) -> ForeignResult<Account> {
        AccountId::parse(text).map(Account::Near).map_err(core_err)
    }
}

impl AttestationScheme for NearChain {
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

impl ForeignChain for NearChain {
    fn kind(&self) -> BridgeKind {
        BridgeKind::Near
    }

    fn deployment(&self) -> Deployment {
        self.scheme.domain.deployment()
    }

    fn check_bridge(&self, mainnet: bool) -> BoxFut<'_, BridgeInfo> {
        Box::pin(async move {
            let c = self.client.config().await.map_err(|e| {
                ForeignError::new(format!(
                    "wyec-near config() at {} (is it the wyec-near contract?): {e}",
                    self.scheme.domain.contract_id
                ))
            })?;
            // the digests bind both ids: a mismatch would make every attestation invalid there
            if c.network_id != self.scheme.domain.network_id
                || c.contract_id != self.scheme.domain.contract_id.as_str()
            {
                return Err(ForeignError::new(format!(
                    "the contract's domain is ({}, {}), the config's ({}, {})",
                    c.network_id,
                    c.contract_id,
                    self.scheme.domain.network_id,
                    self.scheme.domain.contract_id
                )));
            }
            if c.threshold == 0 || (mainnet && c.threshold < MAINNET_MIN_THRESHOLD) {
                return Err(ForeignError::new(format!(
                    "the bridge's threshold is {}: mainnet needs at least {MAINNET_MIN_THRESHOLD} \
                     in every mint mode (plan §3.3)",
                    c.threshold
                )));
            }
            Ok(BridgeInfo {
                threshold: c.threshold,
                challenge_window: c.challenge_window_sec,
            })
        })
    }

    fn finalized_height(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { Ok(self.client.final_head().await.map_err(fe)?.0) })
    }

    fn scan(&self, from: u64, to: u64) -> BoxFut<'_, ScanBatch> {
        Box::pin(async move {
            let out = self.client.scan(from, to).await.map_err(fe)?;
            Ok(ScanBatch {
                events: out
                    .events
                    .iter()
                    .map(|e| Scanned {
                        meta: EventMeta {
                            height: e.height,
                            block_hash: e.block_hash,
                            tx: TxId(e.id),
                            index: e.index,
                        },
                        event: event(&e.event),
                    })
                    .collect(),
                to_hash: out.to_hash,
            })
        })
    }

    fn max_scan_blocks(&self) -> u64 {
        NEAR_MAX_SCAN_BLOCKS
    }

    fn now(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { Ok(self.client.final_head().await.map_err(fe)?.1) })
    }

    fn guardians(&self) -> BoxFut<'_, Vec<Guardian>> {
        Box::pin(async move {
            Ok(self
                .client
                .guardians()
                .await
                .map_err(fe)?
                .into_iter()
                .map(Guardian::Secp256k1)
                .collect())
        })
    }

    fn threshold(&self) -> BoxFut<'_, u8> {
        Box::pin(async move { self.client.threshold().await.map_err(fe) })
    }

    fn challenge_window(&self) -> BoxFut<'_, u64> {
        Box::pin(async move { Ok(self.client.config().await.map_err(fe)?.challenge_window_sec) })
    }

    fn consumed(&self, lock_id: Hash32) -> BoxFut<'_, bool> {
        Box::pin(async move { self.client.is_consumed(&lock_id).await.map_err(fe) })
    }

    fn proposal(&self, lock_id: Hash32) -> BoxFut<'_, Option<Proposal>> {
        Box::pin(async move {
            Ok(self
                .client
                .proposal(&lock_id)
                .await
                .map_err(fe)?
                .map(|p| Proposal {
                    id: u128::from(p.id),
                    amount: p.amount,
                    to: Account::Near(p.receiver_id),
                    proposer: Guardian::Secp256k1(p.proposer),
                    eta: p.eta,
                }))
        })
    }

    fn proposal_status(&self, lock_id: Hash32) -> BoxFut<'_, ProposalStatus> {
        Box::pin(async move {
            Ok(
                match self.client.proposal_status(&lock_id).await.map_err(fe)? {
                    wc::ProposalStatus::None => ProposalStatus::None,
                    wc::ProposalStatus::Pending => ProposalStatus::Pending,
                    wc::ProposalStatus::Ready => ProposalStatus::Ready,
                    wc::ProposalStatus::Void => ProposalStatus::Void,
                },
            )
        })
    }

    fn vetoed(&self, lock_id: Hash32, who: Guardian) -> BoxFut<'_, bool> {
        Box::pin(async move {
            let k = *key_of(&who)?;
            self.client.is_vetoed(&lock_id, &k).await.map_err(fe)
        })
    }

    fn mint_available(&self) -> BoxFut<'_, u128> {
        Box::pin(async move { self.client.mint_available().await.map_err(fe) })
    }

    fn total_supply(&self) -> BoxFut<'_, u128> {
        Box::pin(async move { self.client.total_supply().await.map_err(fe) })
    }

    fn paused(&self) -> BoxFut<'_, bool> {
        Box::pin(async move { self.client.is_paused().await.map_err(fe) })
    }

    fn mint_signatures(&self, tx: TxId) -> BoxFut<'_, Vec<Vec<u8>>> {
        Box::pin(async move { self.client.receipt_signatures(&tx.0).await.map_err(fe) })
    }

    fn threshold_mint(
        &self,
        _k: u8,
        lock_id: Hash32,
        amount: u64,
        to: Account,
        sigs: Vec<[u8; 65]>,
    ) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            let receiver = near_of(&to)?.clone();
            let digest = self.scheme.mint_digest(&lock_id, amount, &to)?;
            let sorted = sort_signatures(&digest, &sigs).map_err(fe)?;
            let o = self
                .client
                .mint(&lock_id, u128::from(amount), &receiver, &sorted)
                .await
                .map_err(fe)?;
            Ok(mined(&o))
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
            let receiver = near_of(&to)?.clone();
            let (o, id) = self
                .client
                .propose_mint(&lock_id, u128::from(amount), &receiver, &sig)
                .await
                .map_err(fe)?;
            let eta = match self.client.proposal(&lock_id).await.map_err(fe)? {
                Some(p) if p.id == id => p.eta,
                // challenged already: its eta as the contract computed it
                _ => {
                    let b = self
                        .client
                        .rpc()
                        .block(BlockRef::Height(o.height))
                        .await
                        .map_err(fe)?;
                    let w = self.client.config().await.map_err(fe)?.challenge_window_sec;
                    b.timestamp_ns / 1_000_000_000 + w
                }
            };
            Ok(Proposed {
                mined: mined(&o),
                proposal_id: u128::from(id),
                eta,
            })
        })
    }

    fn challenge_mint(
        &self,
        lock_id: Hash32,
        proposal_id: u128,
        sig: [u8; 65],
    ) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            let id = self::proposal_id(proposal_id)?;
            let o = self
                .client
                .challenge_mint(&lock_id, id, &sig)
                .await
                .map_err(fe)?;
            Ok(mined(&o))
        })
    }

    fn execute_mint(&self, lock_id: Hash32) -> BoxFut<'_, Mined> {
        Box::pin(async move {
            let o = self.client.execute_mint(&lock_id).await.map_err(fe)?;
            Ok(mined(&o))
        })
    }

    fn burn(&self, amount: u64, ycash_recipient: Hash32) -> BoxFut<'_, Burned> {
        Box::pin(async move {
            let (o, nonce) = self
                .client
                .burn(u128::from(amount), &ycash_recipient)
                .await
                .map_err(fe)?;
            Ok(Burned {
                mined: mined(&o),
                nonce,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Domain {
        Domain::new("sandbox", AccountId::parse("wyec.test.near").unwrap()).unwrap()
    }

    /// The scheme through the trait equals hawkeye-core's NEAR digests and signatures, and
    /// recovers to the member key's 64-byte guardian key.
    #[test]
    fn attestation_scheme_is_borsh_sha256() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        let scheme = NearScheme::new(domain());
        let to = AccountId::parse("alice.near").unwrap();
        let lock = [3u8; 32];
        let d = scheme
            .mint_digest(&lock, 5, &Account::Near(to.clone()))
            .unwrap();
        assert_eq!(
            d,
            domain().digest(&BridgeMessage::Mint {
                lock_id: lock,
                amount: 5,
                receiver_id: to.clone()
            })
        );
        assert_eq!(
            scheme.challenge_digest(&lock, 9),
            domain().digest(&BridgeMessage::Challenge {
                lock_id: lock,
                proposal_id: 9
            })
        );
        let sig = scheme.sign(&key, &d).unwrap();
        assert!(sig[64] <= 1);
        let me = scheme.guardian_of(&key.public_key()).unwrap();
        assert_eq!(me, Guardian::Secp256k1(cnear::guardian_key_of(&key)));
        assert_eq!(scheme.recover(&d, &sig).unwrap(), me);
        // an Ethereum account has no NEAR digest; accounts parse as NEAR ids
        assert!(
            scheme
                .mint_digest(
                    &lock,
                    5,
                    &Account::Ethereum(hawkeye_core::EthAddress([1; 20]))
                )
                .is_err()
        );
        assert_eq!(
            scheme.parse_account("alice.near").unwrap(),
            Account::Near(to)
        );
        assert!(scheme.parse_account("Alice").is_err());
        // the memo deployment is the hashed domain
        assert_eq!(
            domain().deployment(),
            Deployment {
                chain_id: cnear::chain_id("sandbox"),
                bridge: hawkeye_core::EthAddress(cnear::bridge_id(&domain().contract_id)),
            }
        );
    }

    /// Contract panics become reverts the engine matches by name; other errors keep their text.
    #[test]
    fn panics_map_to_revert_names() {
        for (msg, name) in [
            ("wyec: lock consumed", "LockConsumed"),
            ("wyec: proposal pending", "ProposalPending"),
            ("wyec: no such proposal", "NoProposal"),
            ("wyec: mint rate limited", "MintRateLimited"),
        ] {
            let e = fe(hawkeye_near::Error::Panic(msg.into()));
            assert!(e.is_revert(name), "{msg}");
            assert_eq!(e.to_string(), format!("panicked: {msg}"));
        }
        let e = fe(hawkeye_near::Error::Panic(
            "wyec: proposer not a guardian".into(),
        ));
        assert!(e.is_revert("ProposerNotGuardian") && !e.is_revert("NotGuardian"));
        let e = fe(hawkeye_near::Error::Panic("something else".into()));
        assert!(!e.is_revert("LockConsumed"));
        let e = fe(hawkeye_near::Error::Http("down".into()));
        assert_eq!(e.to_string(), "http: down");
        assert!(proposal_id(u128::from(u64::MAX) + 1).is_err());
    }

    #[test]
    fn events_map() {
        let alice = AccountId::parse("alice.near").unwrap();
        match event(&NearEvent::Proposed {
            lock_id: [1; 32],
            proposal_id: 4,
            proposer: [2; 64],
            receiver_id: alice.clone(),
            amount: 9,
            eta: 77,
        }) {
            ForeignEvent::MintProposed {
                proposal_id,
                proposer,
                to,
                ..
            } => {
                assert_eq!(proposal_id, 4);
                assert_eq!(proposer, Guardian::Secp256k1([2; 64]));
                assert_eq!(to, Account::Near(alice.clone()));
            }
            e => panic!("{e:?}"),
        }
        match event(&NearEvent::Paused {
            paused: true,
            by: "relayer.near".into(),
        }) {
            ForeignEvent::Paused { by, .. } => assert_eq!(by.to_string(), "relayer.near"),
            e => panic!("{e:?}"),
        }
    }
}
