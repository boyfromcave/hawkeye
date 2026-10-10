//! The peer channel v1 (plan §6 "Peer channel"): plain HTTP between known operators' status APIs.
//! Mint signatures are collected with `GET /locks/<lockId>`, slash votes with `POST /slash/sign`,
//! unlock co-signatures (`unlockThreshold > 1`) with `POST /unlock/sign`.
//! Every answer is verified by the caller (signatures recover to guardians; acts are checked by
//! the node), so the channel needs no authentication of its own in v1.

use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// `GET /locks/<lockId>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockView {
    /// `0x…` lockId.
    pub lock_id: String,
    /// The vault outpoint (`txid:vout`).
    pub outpoint: String,
    /// Lock state.
    pub state: String,
    /// Zatoshi.
    pub amount: u64,
    /// The mint recipient, if the destination decodes.
    pub to: Option<String>,
    /// Ycash block height.
    pub block_height: u32,
    /// Policy rejection reason.
    pub rejection_reason: Option<String>,
    /// This attestor's `Mint` attestation (`0x` + 65 bytes: EIP-712 on Ethereum, Borsh-SHA256
    /// on NEAR), if it signed.
    pub signature: Option<String>,
    /// This attestor's guardian (Ethereum address, or NEAR 64-byte key).
    pub signer: String,
}

/// `GET /burns/<nonce>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BurnView {
    /// Burn nonce.
    pub nonce: u64,
    /// The burn's id: the Ethereum tx hash, or NEAR's `SHA256(borsh(BurnRecord))`.
    pub tx_hash: String,
    /// Amount (base units).
    pub amount: u64,
    /// Raw recipient bytes32.
    pub recipient: String,
    /// Decoded recipient address, if it decodes.
    pub recipient_address: Option<String>,
    /// Burn state.
    pub state: String,
    /// Assigned leader key.
    pub leader: Option<String>,
    /// The intent paying it.
    pub intent: Option<String>,
}

/// `POST /slash/sign` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashSignRequest {
    /// The case's evidence bundle (as the owner stored it).
    pub evidence: serde_json::Value,
    /// The act transaction (hex) with the signatures gathered so far.
    pub act: String,
}

/// `POST /slash/sign` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashSignResponse {
    /// The act with this attestor's signature added.
    pub hex: String,
    /// `slashThreshold` reached.
    pub complete: bool,
    /// Signatures now on the act.
    pub signatures: u32,
    /// Signatures needed.
    pub required: i32,
}

/// `POST /unlock/sign` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockSignRequest {
    /// The unlock transaction (hex) with the set signatures gathered so far.
    pub hex: String,
}

/// `POST /unlock/sign` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockSignResponse {
    /// The unlock with this attestor's node's set signature added.
    pub hex: String,
    /// `unlockThreshold` reached.
    pub complete: bool,
    /// What the verification matched (`burn <nonce>` or `roll`).
    pub matched: String,
}

/// An error answer of the API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    /// Why.
    pub error: String,
}

/// The HTTP client for the other attestors' APIs.
#[derive(Debug, Clone)]
pub struct Peers {
    http: reqwest::Client,
    urls: Vec<String>,
}

impl Peers {
    /// A client for `urls` (5 s timeout per request).
    pub fn new(urls: Vec<String>) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            urls: urls
                .into_iter()
                .map(|u| u.trim_end_matches('/').to_owned())
                .collect(),
        })
    }

    /// The configured peers.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// `GET <peer>/locks/<lockId>`.
    pub async fn lock(&self, peer: &str, lock_id_hex: &str) -> Result<LockView> {
        let r = self
            .http
            .get(format!("{peer}/locks/{lock_id_hex}"))
            .send()
            .await?;
        if !r.status().is_success() {
            return Err(anyhow!("{peer}: HTTP {}", r.status()));
        }
        Ok(r.json().await?)
    }

    /// `POST <peer>/unlock/sign`.
    pub async fn unlock_sign(
        &self,
        peer: &str,
        req: &UnlockSignRequest,
    ) -> Result<UnlockSignResponse> {
        let r = self
            .http
            .post(format!("{peer}/unlock/sign"))
            .json(req)
            .send()
            .await?;
        if !r.status().is_success() {
            let status = r.status();
            let why = r
                .json::<ApiError>()
                .await
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(anyhow!("{peer}: HTTP {status}: {why}"));
        }
        Ok(r.json().await?)
    }

    /// `POST <peer>/slash/sign`.
    pub async fn slash_sign(
        &self,
        peer: &str,
        req: &SlashSignRequest,
    ) -> Result<SlashSignResponse> {
        let r = self
            .http
            .post(format!("{peer}/slash/sign"))
            .json(req)
            .send()
            .await?;
        if !r.status().is_success() {
            let status = r.status();
            let why = r
                .json::<ApiError>()
                .await
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(anyhow!("{peer}: HTTP {status}: {why}"));
        }
        Ok(r.json().await?)
    }
}
