// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The peer channel's request and response authentication (plan §6 "Peer channel", HK-13;
//! remedial report 05/H-1 §4.1): every `POST` to a signing route (`/unlock/sign`,
//! `/slash/sign`, `/cancel/sign`) is signed by the requester's **member key**, and every answer
//! by the responder's, so authorisation follows the Ycash set (`set_getinfo.memberlist`) rather
//! than a certificate list.
//!
//! ```text
//! request preimage =
//!     "HawkeyePeerReq"                    14 bytes, ASCII, no terminator
//!   ‖ set_id                              32 bytes, internal byte order
//!   ‖ deployment.chain_id                 u64 LE
//!   ‖ deployment.bridge                   20 bytes
//!   ‖ u8(len(method)) ‖ method            "POST" → 04 "POST"
//!   ‖ u16 LE len(path) ‖ path             the route as matched, no query, no host
//!   ‖ timestamp                           u64 LE (the X-Hawkeye-Time value)
//!   ‖ nonce                               16 bytes (the X-Hawkeye-Nonce value)
//!   ‖ sha256(body)                        32 bytes, the exact body bytes as sent
//! request msg  = sha256d(request preimage)
//! response msg = sha256d("HawkeyePeerResp" ‖ request msg ‖ sha256(response body))
//! sig          = sign_compact(member key, msg)   65 bytes, header 31..34, low S
//! ```
//!
//! The body is hashed as raw bytes; nothing is canonicalised. Binding the set and the
//! deployment makes a request for one bridge useless on another; binding the method and path
//! stops a `/slash/sign` body being replayed to `/unlock/sign`. Pure: the server's clock,
//! replay cache and membership check live in the daemon.

use crate::bytes::{Hash32, sha256, sha256d};
use crate::error::{Error, Result};
use crate::keys::{PubKey33, SecretKey};
use crate::memo::Deployment;
use crate::setsig::{recover_compact, sign_compact};

/// The request domain, 14 ASCII bytes.
pub const REQUEST_DOMAIN: &[u8; 14] = b"HawkeyePeerReq";
/// The response domain, 15 ASCII bytes.
pub const RESPONSE_DOMAIN: &[u8; 15] = b"HawkeyePeerResp";

/// The requester's (or responder's) 33-byte compressed member key, 66 lowercase hex chars.
pub const HEADER_MEMBER: &str = "x-hawkeye-member";
/// Unix seconds, decimal ASCII, no leading zeros.
pub const HEADER_TIME: &str = "x-hawkeye-time";
/// 16 random bytes, 32 lowercase hex chars.
pub const HEADER_NONCE: &str = "x-hawkeye-nonce";
/// The 65-byte compact recoverable signature, 130 lowercase hex chars.
pub const HEADER_SIG: &str = "x-hawkeye-sig";

/// The largest accepted difference between the server's clock and `X-Hawkeye-Time`, seconds.
pub const SKEW_SECS: u64 = 60;

/// What a signed request commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRequest<'a> {
    /// The attestor set, internal byte order.
    pub set_id: &'a Hash32,
    /// The bridge deployment.
    pub deployment: &'a Deployment,
    /// The HTTP method (`"POST"`).
    pub method: &'a str,
    /// The route as matched (`"/unlock/sign"`), no query, no host.
    pub path: &'a str,
    /// Unix seconds.
    pub timestamp: u64,
    /// 16 random bytes.
    pub nonce: &'a [u8; 16],
    /// The exact body bytes.
    pub body: &'a [u8],
}

/// The request preimage (see the module documentation).
pub fn request_preimage(r: &PeerRequest<'_>) -> Result<Vec<u8>> {
    let method = r.method.as_bytes();
    let path = r.path.as_bytes();
    let mlen = u8::try_from(method.len()).map_err(|_| Error::Signature("method too long"))?;
    let plen = u16::try_from(path.len()).map_err(|_| Error::Signature("path too long"))?;
    let mut m = Vec::with_capacity(14 + 32 + 8 + 20 + 1 + method.len() + 2 + path.len() + 8 + 48);
    m.extend_from_slice(REQUEST_DOMAIN);
    m.extend_from_slice(r.set_id);
    m.extend_from_slice(&r.deployment.chain_id.to_le_bytes());
    m.extend_from_slice(&r.deployment.bridge.0);
    m.push(mlen);
    m.extend_from_slice(method);
    m.extend_from_slice(&plen.to_le_bytes());
    m.extend_from_slice(path);
    m.extend_from_slice(&r.timestamp.to_le_bytes());
    m.extend_from_slice(r.nonce);
    m.extend_from_slice(&sha256(r.body));
    Ok(m)
}

/// `sha256d(request preimage)`: what the requester signs.
pub fn request_msg(r: &PeerRequest<'_>) -> Result<Hash32> {
    Ok(sha256d(&request_preimage(r)?))
}

/// `sha256d("HawkeyePeerResp" ‖ request_msg ‖ sha256(response body))`: what the responder signs.
pub fn response_msg(request_msg: &Hash32, response_body: &[u8]) -> Hash32 {
    let mut m = Vec::with_capacity(15 + 32 + 32);
    m.extend_from_slice(RESPONSE_DOMAIN);
    m.extend_from_slice(request_msg);
    m.extend_from_slice(&sha256(response_body));
    sha256d(&m)
}

/// The domain of a declaration that a member is permanently gone (the owner's override,
/// 2026-10-13), 17 ASCII bytes.
pub const GONE_DOMAIN: &[u8; 17] = b"HawkeyeMemberGone";

/// `sha256d("HawkeyeMemberGone" ‖ set_id ‖ member ‖ seq (u32 LE) ‖ expiry (u32 LE))`: what an
/// attestor signs to declare `member` permanently gone. `seq` is the member's join height — the
/// membership the declaration is about (a key that leaves and rejoins is a new membership) — and
/// `expiry` the last Ycash height the declaration counts at. A quorum of such declarations
/// releases the holds that member causes while it stays silent.
pub fn gone_msg(set_id: &Hash32, member: &PubKey33, seq: u32, expiry: u32) -> Hash32 {
    let mut m = Vec::with_capacity(17 + 32 + 33 + 8);
    m.extend_from_slice(GONE_DOMAIN);
    m.extend_from_slice(set_id);
    m.extend_from_slice(member);
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&expiry.to_le_bytes());
    sha256d(&m)
}

/// The ledger high-water-mark domain, 16 ASCII bytes (plan §4.7, V-N1).
pub const HWM_DOMAIN: &[u8; 16] = b"HawkeyeLedgerHwm";

/// `sha256d("HawkeyeLedgerHwm" ‖ set_id ‖ ledger_id ‖ count (u64 LE))`: what the member key signs
/// over the ledger's sign-once count. `ledger_id` is the 16 bytes stored in the ledger
/// (`meta.ledger_id`), so a mark from another file does not verify here.
pub fn hwm_msg(set_id: &Hash32, ledger_id: &[u8; 16], count: u64) -> Hash32 {
    let mut m = Vec::with_capacity(16 + 32 + 16 + 8);
    m.extend_from_slice(HWM_DOMAIN);
    m.extend_from_slice(set_id);
    m.extend_from_slice(ledger_id);
    m.extend_from_slice(&count.to_le_bytes());
    sha256d(&m)
}

/// Sign a request message with the member key.
pub fn sign(key: &SecretKey, msg: &Hash32) -> Result<[u8; 65]> {
    sign_compact(key, msg)
}

/// Whether `sig` recovers to `member` over `msg` (header 31..34, low S).
pub fn verify(member: &PubKey33, msg: &Hash32, sig: &[u8]) -> Result<()> {
    let k = recover_compact(sig, msg)?;
    if &k == member {
        Ok(())
    } else {
        Err(Error::Signature("signature does not recover to the member"))
    }
}

/// Parse `X-Hawkeye-Member`: 66 lowercase hex chars, a compressed key.
pub fn parse_member(s: &str) -> Result<PubKey33> {
    parse_lower_hex::<33>(s, "member")
}

/// Parse `X-Hawkeye-Time`: decimal ASCII, no leading zeros (`"0"` alone is allowed).
pub fn parse_time(s: &str) -> Result<u64> {
    let ok = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.len() <= 20;
    if !ok {
        return Err(Error::Signature("time is not canonical decimal"));
    }
    s.parse().map_err(|_| Error::Signature("time out of range"))
}

/// Parse `X-Hawkeye-Nonce`: 32 lowercase hex chars.
pub fn parse_nonce(s: &str) -> Result<[u8; 16]> {
    parse_lower_hex::<16>(s, "nonce")
}

/// Parse `X-Hawkeye-Sig`: 130 lowercase hex chars.
pub fn parse_sig(s: &str) -> Result<[u8; 65]> {
    parse_lower_hex::<65>(s, "signature")
}

fn parse_lower_hex<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Signature(match what {
            "member" => "member is not 66 lowercase hex chars",
            "nonce" => "nonce is not 32 lowercase hex chars",
            _ => "signature is not 130 lowercase hex chars",
        }));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| Error::Signature("not hex"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parsers() {
        assert_eq!(parse_time("1760000000").unwrap(), 1_760_000_000);
        assert_eq!(parse_time("0").unwrap(), 0);
        for bad in ["", "01", "+1", "1 ", "1.0", "99999999999999999999999"] {
            assert!(parse_time(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_nonce(&"0f".repeat(16)).unwrap(), [0x0f; 16]);
        assert!(parse_nonce(&"0F".repeat(16)).is_err());
        assert!(parse_nonce(&"0f".repeat(15)).is_err());
        assert!(parse_member(&"02".repeat(33)).is_ok());
        assert!(parse_sig(&"1f".repeat(64)).is_err());
    }
}
