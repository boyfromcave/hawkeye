//! The peer channel (plan §6 "Peer channel", §4.6, HK-13): HTTP(S) between the attestors'
//! APIs. Mint signatures are collected with `GET /locks/<lockId>` (read-only, unsigned: users
//! self-submit from it too), slash votes with `POST /slash/sign`, unlock co-signatures
//! (`unlockThreshold > 1`) with `POST /unlock/sign`, cancel co-signatures
//! (`cancelThreshold > 1`) with `POST /cancel/sign`.
//!
//! The three signing routes are **authenticated by member-key request signatures**
//! ([`crate::peer_auth`], remedial report 05/H-1): every request carries the requester's member
//! key, a timestamp, a nonce and a signature over them, the method, the path, the set, the
//! deployment and the body; the server admits only a current member of the set, and signs its
//! answer, which this client checks. The caller still verifies every answer's content on its own
//! (signatures recover to distinct current members over the transaction it built; acts are
//! checked by the node). TLS is the transport: `https://` peers, required on mainnet for any
//! peer that is not loopback.

use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::peer_auth::PeerSigner;

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
    /// The raw `ycashRecipient` (main plan §4.2: 22 or 35 bytes when well-formed), `0x`-hex of
    /// its actual length.
    pub recipient: String,
    /// The decoded recipient address (`s1…`/`s2…`/`s3…`, or `sq…`/`tq…`/`rq…` for a
    /// `TX_PQPKH` recipient), if it decodes.
    pub recipient_address: Option<String>,
    /// Burn state.
    pub state: String,
    /// Why a `WAITING_CAP` burn waits: `over-cap` (it exceeds the set's full-window cap and
    /// waits for a cap raise, audit 05/M-2) or `epoch` (the next rate-limit epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Assigned leader key.
    pub leader: Option<String>,
    /// The intent paying it.
    pub intent: Option<String>,
}

/// `POST /burns/unlock` request (authenticated, review H-2): the signed unlock a peer holds for a
/// burn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BurnUnlockRequest {
    /// The burn nonce (this deployment).
    pub nonce: u64,
}

/// `POST /burns/unlock` answer (signed by the peer, HK-13).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BurnUnlockResponse {
    /// The burn nonce.
    pub nonce: u64,
    /// The burn's state in the peer's ledger (`unknown` when it has none).
    pub state: String,
    /// The peer's ledger is flagged restored (review N-2): `held` is then `true` whatever it
    /// finds — it cannot know what it signed before the backup.
    #[serde(default)]
    pub restored: bool,
    /// The peer holds a live (non-drill) signed unlock for the burn: it, or a co-signer, signed
    /// one that may still confirm (01/V-2). `false` is the peer's signed statement that it holds
    /// none (review M-1).
    pub held: bool,
    /// That signed unlock (hex), served only while the burn is unpaid in the peer's ledger
    /// (`FINALIZED`, `ASSIGNED`, `WAITING_CAP`): a takeover leader re-sends it (re-funded)
    /// instead of signing another vault for the burn. Never on the public `GET /burns/<nonce>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock: Option<String>,
}

/// `POST /vaults/orphaned` request (authenticated, review H-2): a member that holds a signed
/// unlock of `vault` for burn `nonce` reports that the burn was paid by another vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrphanRequest {
    /// The burn nonce.
    pub nonce: u64,
    /// The orphaned vault (`txid:vout`).
    pub vault: String,
    /// Review N-2: the reporter's ledger was restored and its node wallet signed an unlock of
    /// this vault it has no record of (the burn is unknown): roll it so those bytes die.
    #[serde(default)]
    pub restored: bool,
}

/// `POST /members/gone` request (authenticated): the requester's signed declaration that
/// `member` is permanently gone (the owner's override, 2026-10-13).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoneDeclaration {
    /// The member declared gone (66 hex).
    pub member: String,
    /// The declaring member (66 hex): the requester.
    pub declarer: String,
    /// `sign_compact(declarer, gone_msg(set, member))`, 130 hex.
    pub sig: String,
    /// Why (kept with the record).
    pub reason: String,
}

/// `POST /members/gone` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoneAnswer {
    /// Declarations of the member this ledger now holds, from distinct current members.
    pub declarations: u32,
    /// The quorum (the set's `unlockThreshold`).
    pub quorum: u32,
}

/// `POST /vaults/orphaned` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrphanResponse {
    /// The vault was marked `ROLL_DUE` here now.
    pub marked: bool,
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

/// `POST /cancel/sign` request (`cancelThreshold > 1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelSignRequest {
    /// The cancel transaction (hex) with the set signatures gathered so far.
    pub hex: String,
    /// The intent it cancels (`txid:vout`, display order).
    pub intent: String,
}

/// `POST /cancel/sign` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelSignResponse {
    /// The cancel with this attestor's set signature added.
    pub hex: String,
    /// `cancelThreshold` reached.
    pub complete: bool,
    /// Signatures now on the cancel.
    pub signatures: u32,
    /// Signatures needed.
    pub required: u32,
}

/// An answer of a signing route and who signed it (`None`: an unsigned answer, accepted only
/// with `[peers] require_auth = false`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    /// The answer.
    pub body: T,
    /// The responder's member key, verified over the answer and the request.
    pub responder: Option<hawkeye_core::PubKey33>,
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
    signer: Option<PeerSigner>,
}

impl Peers {
    /// A client for `urls` (5 s timeout per request), with no member key: it can read
    /// (`GET /locks`) but its signing requests carry no authentication (refused by a peer that
    /// requires it). The daemon uses [`Peers::with_signer`].
    pub fn new(urls: Vec<String>) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            urls: urls
                .into_iter()
                .map(|u| u.trim_end_matches('/').to_owned())
                .collect(),
            signer: None,
        })
    }

    /// Sign every request to a signing route with `signer` and check the answers' signatures.
    pub fn with_signer(mut self, signer: PeerSigner) -> Self {
        self.signer = Some(signer);
        self
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

    /// `POST <peer>/members/gone` (authenticated).
    pub async fn declare_gone(
        &self,
        peer: &str,
        req: &GoneDeclaration,
    ) -> Result<Signed<GoneAnswer>> {
        self.post_signed(peer, "/members/gone", req).await
    }

    /// `POST <peer>/vaults/orphaned` (authenticated).
    pub async fn orphaned(
        &self,
        peer: &str,
        req: &OrphanRequest,
    ) -> Result<Signed<OrphanResponse>> {
        self.post_signed(peer, "/vaults/orphaned", req).await
    }

    /// `POST <peer>/burns/unlock` (authenticated; the answer is signed).
    pub async fn burn_unlock(&self, peer: &str, nonce: u64) -> Result<Signed<BurnUnlockResponse>> {
        self.post_signed(peer, "/burns/unlock", &BurnUnlockRequest { nonce })
            .await
    }

    /// `POST <peer><path>` with `req` as JSON, signed when this client has a member key; the
    /// answer's signature is checked.
    async fn post_signed<Q: Serialize, A: for<'de> Deserialize<'de>>(
        &self,
        peer: &str,
        path: &str,
        req: &Q,
    ) -> Result<Signed<A>> {
        let body = serde_json::to_vec(req)?;
        let mut rb = self
            .http
            .post(format!("{peer}{path}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let signed = match &self.signer {
            Some(s) => {
                let sr = s.sign(path, &body)?;
                for (n, v) in &sr.headers {
                    rb = rb.header(*n, v);
                }
                Some(sr.msg)
            }
            None => None,
        };
        let r = rb.body(body).send().await?;
        let status = r.status();
        let headers = r.headers().clone();
        let bytes = r.bytes().await?;
        if !status.is_success() {
            let why = serde_json::from_slice::<ApiError>(&bytes)
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(anyhow!("{peer}: HTTP {status}: {why}"));
        }
        let responder = match (&self.signer, signed) {
            (Some(s), Some(msg)) => s
                .check_response(&msg, &headers, &bytes)
                .map_err(|e| anyhow!("{peer}: {e}"))?,
            _ => None,
        };
        Ok(Signed {
            body: serde_json::from_slice(&bytes)?,
            responder,
        })
    }

    /// `POST <peer>/unlock/sign`.
    pub async fn unlock_sign(
        &self,
        peer: &str,
        req: &UnlockSignRequest,
    ) -> Result<Signed<UnlockSignResponse>> {
        self.post_signed(peer, "/unlock/sign", req).await
    }

    /// `POST <peer>/cancel/sign`.
    pub async fn cancel_sign(
        &self,
        peer: &str,
        req: &CancelSignRequest,
    ) -> Result<Signed<CancelSignResponse>> {
        self.post_signed(peer, "/cancel/sign", req).await
    }

    /// `POST <peer>/slash/sign`.
    pub async fn slash_sign(
        &self,
        peer: &str,
        req: &SlashSignRequest,
    ) -> Result<Signed<SlashSignResponse>> {
        self.post_signed(peer, "/slash/sign", req).await
    }
}
