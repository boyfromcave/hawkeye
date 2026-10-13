// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The peer channel's authentication (plan §6 "Peer channel", §4.6, HK-13; remedial report
//! 05/H-1 §4.1): an axum middleware on the three signing routes (`/unlock/sign`,
//! `/slash/sign`, `/cancel/sign`) that admits a request only when it carries a member-key
//! signature ([`hawkeye_core::peerauth`]) of a **current** member of the set, fresh (±60 s) and
//! not replayed, and signs every answer with this attestor's member key; and the client side
//! ([`PeerSigner`]) the [`Peers`](crate::peers::Peers) client uses.
//!
//! Authorisation follows the Ycash set: a member removed by `SET_REMOVE` (or in its exit delay)
//! is refused at once, with no certificate to revoke. TLS (`https://` peers, or a reverse proxy
//! with client certificates) is the transport, recommended and required for non-loopback peers
//! on mainnet ([`crate::config::check_transport`]); `[peers] allow_from` is a network-level belt
//! (behind a reverse proxy it sees the proxy's address).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hawkeye_core::bytes::Hash32;
use hawkeye_core::peerauth::{
    self, HEADER_MEMBER, HEADER_NONCE, HEADER_SIG, HEADER_TIME, PeerRequest, SKEW_SECS,
};
use hawkeye_core::{Deployment, PubKey33, SecretKey};
use hawkeye_ycash::types::{Member, SetInfo};

use crate::engine::Ctx;
use crate::peers::ApiError;

/// The largest request or response body the peer channel reads (1 MiB: an unlock or act is a
/// few kilobytes, an evidence bundle tens).
pub const MAX_BODY: usize = 1 << 20;

/// The verified requester of a signing route, as a request extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerMember(pub PubKey33);

/// `[peers]` authentication settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAuthConfig {
    /// Refuse unsigned requests and unsigned answers (`[peers] require_auth`, default true;
    /// mainnet refuses false).
    pub require_auth: bool,
    /// When non-empty, the peer's address must be in one of these networks.
    pub allow_from: Vec<Cidr>,
}

impl Default for PeerAuthConfig {
    fn default() -> Self {
        Self {
            require_auth: true,
            allow_from: vec![],
        }
    }
}

/// What the middleware shares with the engine: the set snapshot the engine refreshes every
/// tick (membership, thresholds) and the replay cache.
#[derive(Debug, Default)]
pub struct AuthState {
    /// The settings.
    pub config: PeerAuthConfig,
    /// The set's member list as of the engine's last tick (empty before the first one: then
    /// `set_getinfo` is asked).
    pub members: RwLock<Vec<Member>>,
    /// The set as of the engine's last tick.
    pub set: RwLock<Option<SetInfo>>,
    /// `(member, nonce) → expiry` (unix seconds) of the requests already admitted.
    replay: Mutex<HashMap<(PubKey33, [u8; 16]), u64>>,
    /// Peer API URLs by the member key their signed answers recovered to (learnt, review R-1).
    pub peer_url: Mutex<HashMap<PubKey33, String>>,
    /// `(reporter, restore event) → restored`, as the reporter itself answered once (R-1).
    pub restore_answers: Mutex<HashMap<(PubKey33, String), bool>>,
}

impl AuthState {
    /// A state with `config` and an empty snapshot.
    pub fn new(config: PeerAuthConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Record the engine's view of the set.
    pub fn publish(&self, info: &SetInfo) {
        *self.members.write().unwrap_or_else(|e| e.into_inner()) = info.memberlist.clone();
        *self.set.write().unwrap_or_else(|e| e.into_inner()) = Some(info.clone());
    }

    /// Admit `(member, nonce)` once within its lifetime; false if seen.
    fn admit_once(&self, member: PubKey33, nonce: [u8; 16], now: u64) -> bool {
        let mut m = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, exp| *exp >= now);
        if m.contains_key(&(member, nonce)) {
            return false;
        }
        m.insert((member, nonce), now + 2 * SKEW_SECS);
        true
    }
}

/// An IPv4 or IPv6 network (`10.0.0.0/8`, `::1/128`, or a bare address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d[/n]` or `ipv6[/n]`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .parse()
            .map_err(|_| format!("{s:?} is not an IP network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("{s:?}: prefix length must be 0..={max}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is in the network (an IPv4-mapped IPv6 address counts as IPv4).
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let bits = |a: IpAddr| -> u128 {
            match a {
                IpAddr::V4(v) => u128::from(u32::from(v)) << 96,
                IpAddr::V6(v) => u128::from(v),
            }
        };
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        let n = u32::from(self.prefix);
        if n == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - n);
        bits(ip) & mask == bits(self.addr) & mask
    }
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 16 random bytes for `X-Hawkeye-Nonce` (`/dev/urandom`; no new dependency).
pub fn random_nonce() -> std::io::Result<[u8; 16]> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

fn refuse(code: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    tracing::warn!(event = "peer_auth_refused", status = code.as_u16(), reason = %msg);
    (
        code,
        axum::Json(ApiError {
            error: format!("peer auth: {msg}"),
        }),
    )
        .into_response()
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Whether `key` is a current member of the set: the engine's snapshot, else `set_getinfo`
/// (`hawkeye status`, or before the first tick).
pub async fn is_current_member(ctx: &Ctx, key: &PubKey33) -> bool {
    let snap = ctx
        .auth
        .members
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let members = if snap.is_empty() {
        match ctx.ycash.set_getinfo(&ctx.set_hash(), None).await {
            Ok(i) => i.memberlist,
            Err(_) => return false,
        }
    } else {
        snap
    };
    members.iter().any(|m| m.key.0 == *key && m.current)
}

/// The middleware on the signing routes (see the module documentation): steps 1–6 of the
/// remedial report's §4.1, then the answer is signed.
pub async fn layer(State(ctx): State<Ctx>, req: Request, next: Next) -> Response {
    let cfg = &ctx.auth.config;
    if !cfg.allow_from.is_empty() {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        match ip {
            Some(ip) if cfg.allow_from.iter().any(|c| c.contains(ip)) => {}
            Some(ip) => {
                return refuse(
                    StatusCode::FORBIDDEN,
                    format!("{ip} is not in [peers] allow_from"),
                );
            }
            None => return refuse(StatusCode::FORBIDDEN, "the peer address is unknown"),
        }
    }
    // the route as served (this router nests nothing, so it is the matched route: no query,
    // no host)
    let path = req.uri().path().to_owned();
    let method = req.method().as_str().to_owned();
    let (mut parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return refuse(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
    };
    let h = &parts.headers;
    let present = [HEADER_MEMBER, HEADER_TIME, HEADER_NONCE, HEADER_SIG]
        .iter()
        .filter(|n| h.contains_key(**n))
        .count();
    let mut req_msg: Option<Hash32> = None;
    if present == 0 && !cfg.require_auth {
        // regtest transition only ([peers] require_auth = false): unauthenticated, no requester
        tracing::debug!(event = "peer_unauthenticated", path = %path);
    } else {
        // 1. well-formed headers
        let parse = || -> Result<(PubKey33, u64, [u8; 16], [u8; 65]), String> {
            let get = |n: &str| header(h, n).ok_or_else(|| format!("missing or malformed {n}"));
            let m = peerauth::parse_member(get(HEADER_MEMBER)?)
                .map_err(|_| format!("missing or malformed {HEADER_MEMBER}"))?;
            let t = peerauth::parse_time(get(HEADER_TIME)?)
                .map_err(|_| format!("missing or malformed {HEADER_TIME}"))?;
            let n = peerauth::parse_nonce(get(HEADER_NONCE)?)
                .map_err(|_| format!("missing or malformed {HEADER_NONCE}"))?;
            let s = peerauth::parse_sig(get(HEADER_SIG)?)
                .map_err(|_| format!("missing or malformed {HEADER_SIG}"))?;
            Ok((m, t, n, s))
        };
        let (member, time, nonce, sig) = match parse() {
            Ok(v) => v,
            Err(e) => return refuse(StatusCode::UNAUTHORIZED, e),
        };
        // 2. fresh
        let now = now_secs();
        if now.abs_diff(time) > SKEW_SECS {
            return refuse(
                StatusCode::UNAUTHORIZED,
                format!("stale request (time {time}, now {now}, ±{SKEW_SECS} s)"),
            );
        }
        // 4. the signature recovers to the member
        let msg = match peerauth::request_msg(&PeerRequest {
            set_id: &ctx.params.set_id,
            deployment: &ctx.params.deployment,
            method: &method,
            path: &path,
            timestamp: time,
            nonce: &nonce,
            body: &body,
        }) {
            Ok(m) => m,
            Err(e) => return refuse(StatusCode::UNAUTHORIZED, e.to_string()),
        };
        if peerauth::verify(&member, &msg, &sig).is_err() {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "signature does not recover to the member",
            );
        }
        // 3. not replayed (recorded once the signature verified)
        if !ctx.auth.admit_once(member, nonce, now) {
            return refuse(StatusCode::UNAUTHORIZED, "replayed");
        }
        // 5. a current member (a member in its exit delay is not)
        if !is_current_member(&ctx, &member).await {
            return refuse(
                StatusCode::FORBIDDEN,
                format!("{} is not a current member", hex::encode(member)),
            );
        }
        // 6. the handler sees the requester
        parts.extensions.insert(PeerMember(member));
        req_msg = Some(msg);
    }
    let req = Request::from_parts(parts, Body::from(body));
    let resp = next.run(req).await;
    match req_msg {
        Some(m) => sign_response(&ctx.key, &ctx.me, &m, resp).await,
        None => resp,
    }
}

async fn sign_response(
    key: &SecretKey,
    me: &PubKey33,
    req_msg: &Hash32,
    resp: Response,
) -> Response {
    let (mut parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .unwrap_or_default();
    if let Ok(sig) = peerauth::sign(key, &peerauth::response_msg(req_msg, &bytes)) {
        if let Ok(v) = HeaderValue::from_str(&hex::encode(me)) {
            parts.headers.insert(HEADER_MEMBER, v);
        }
        if let Ok(v) = HeaderValue::from_str(&hex::encode(sig)) {
            parts.headers.insert(HEADER_SIG, v);
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// The client side: signs requests with the member key and checks the signed answers.
#[derive(Clone)]
pub struct PeerSigner {
    /// The member key.
    pub key: SecretKey,
    /// The set.
    pub set_id: Hash32,
    /// The bridge deployment.
    pub deployment: Deployment,
    /// Refuse an answer without a valid responder signature.
    pub require_auth: bool,
}

impl std::fmt::Debug for PeerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSigner")
            .field("member", &hex::encode(self.key.public_key()))
            .field("require_auth", &self.require_auth)
            .finish()
    }
}

/// The headers of a signed request and the message signed.
pub struct SignedRequest {
    /// `(name, value)` pairs.
    pub headers: Vec<(&'static str, String)>,
    /// The request message (the response is bound to it).
    pub msg: Hash32,
}

impl PeerSigner {
    /// Sign `POST <path>` with `body` now.
    pub fn sign(&self, path: &str, body: &[u8]) -> anyhow::Result<SignedRequest> {
        let nonce = random_nonce()?;
        let time = now_secs();
        let msg = peerauth::request_msg(&PeerRequest {
            set_id: &self.set_id,
            deployment: &self.deployment,
            method: "POST",
            path,
            timestamp: time,
            nonce: &nonce,
            body,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let sig = peerauth::sign(&self.key, &msg).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(SignedRequest {
            headers: vec![
                (HEADER_MEMBER, hex::encode(self.key.public_key())),
                (HEADER_TIME, time.to_string()),
                (HEADER_NONCE, hex::encode(nonce)),
                (HEADER_SIG, hex::encode(sig)),
            ],
            msg,
        })
    }

    /// The responder of an answer to a request with message `req_msg`: the key its signature
    /// recovers to. `None` for an unsigned answer when `require_auth` is off.
    pub fn check_response(
        &self,
        req_msg: &Hash32,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> anyhow::Result<Option<PubKey33>> {
        let (m, s) = (header(headers, HEADER_MEMBER), header(headers, HEADER_SIG));
        let (Some(m), Some(s)) = (m, s) else {
            anyhow::ensure!(!self.require_auth, "the answer is not signed by the peer");
            return Ok(None);
        };
        let member = peerauth::parse_member(m).map_err(|e| anyhow::anyhow!("answer: {e}"))?;
        let sig = peerauth::parse_sig(s).map_err(|e| anyhow::anyhow!("answer: {e}"))?;
        peerauth::verify(&member, &peerauth::response_msg(req_msg, body), &sig)
            .map_err(|e| anyhow::anyhow!("answer signature: {e}"))?;
        Ok(Some(member))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.0.0.9".parse().unwrap()));
        let one = Cidr::parse("127.0.0.1").unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        for bad in ["10.0.0.0/33", "host", "10.0.0/8", "::/129"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn replay_cache() {
        let s = AuthState::default();
        let k = [2u8; 33];
        assert!(s.admit_once(k, [1; 16], 100));
        assert!(!s.admit_once(k, [1; 16], 150));
        assert!(s.admit_once(k, [2; 16], 150));
        // expired entries are pruned
        assert!(s.admit_once(k, [1; 16], 100 + 2 * SKEW_SECS + 1));
    }
}
