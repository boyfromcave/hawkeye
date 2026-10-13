// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Where credentials may travel in clear (remedial reports 05/L-2, 05/H-1 §4.1): HTTP Basic
//! credentials (the ycashd RPC password or cookie) and the peer channel go only to a **loopback**
//! host or over **TLS** (`https://`) — the YED attest agent's rule (ycash-dd
//! `doc/yellowback-attestor.md`, "cleartext Basic auth only to loopback, else https://").
//!
//! Loopback is `127.0.0.0/8`, `::1` and the name `localhost`; any other host name is not
//! loopback (it is not resolved: a name can point anywhere).

use std::fmt;
use std::net::IpAddr;

/// Why a URL may not carry credentials in clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Not `scheme://host…`.
    Malformed(String),
    /// Neither `http` nor `https`.
    Scheme(String),
    /// Plain `http://` to a host that is not loopback.
    Cleartext(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(u) => write!(f, "{u:?} is not an http(s) URL"),
            Self::Scheme(s) => write!(f, "scheme {s:?}: only http (loopback) or https"),
            Self::Cleartext(h) => write!(
                f,
                "plain http to {h}, which is not loopback: credentials would cross the network \
                 in clear (use https://, or a loopback address)"
            ),
        }
    }
}

impl std::error::Error for TransportError {}

/// The scheme and host of `url` (lowercased scheme; an IPv6 literal without its brackets).
pub fn scheme_host(url: &str) -> Result<(String, String), TransportError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| TransportError::Malformed(url.to_owned()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // drop any userinfo
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(r) = hostport.strip_prefix('[') {
        r.split_once(']')
            .map(|(h, _)| h)
            .ok_or_else(|| TransportError::Malformed(url.to_owned()))?
    } else {
        hostport.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(TransportError::Malformed(url.to_owned()));
    }
    Ok((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// Whether `host` is loopback: `localhost`, or an IP literal in `127.0.0.0/8` or `::1`.
pub fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip_v4_mapped_loopback(&ip))
}

fn ip_v4_mapped_loopback(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
}

/// `Ok` iff `url` is `https://…`, or `http://` to a loopback host.
pub fn credentials_safe(url: &str) -> Result<(), TransportError> {
    let (scheme, host) = scheme_host(url)?;
    match scheme.as_str() {
        "https" => Ok(()),
        "http" if is_loopback_host(&host) => Ok(()),
        "http" => Err(TransportError::Cleartext(host)),
        other => Err(TransportError::Scheme(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attest agent's cases.
    #[test]
    fn loopback_or_tls() {
        for ok in [
            "http://127.0.0.1:18232",
            "http://127.0.0.1:18232/",
            "http://127.1.2.3:8232",
            "http://[::1]:18232",
            "http://localhost:18232",
            "http://LOCALHOST:18232",
            "https://node.example",
            "https://10.0.0.5:18232/",
            "HTTP://127.0.0.1",
            "http://u:p@127.0.0.1:18232",
        ] {
            assert!(credentials_safe(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://10.0.0.5:18232",
            "http://ycashd.internal",
            "http://localhost.example.com:18232",
            "http://[fd00::1]:18232",
            "http://0.0.0.0:18232",
        ] {
            assert!(
                matches!(credentials_safe(bad), Err(TransportError::Cleartext(_))),
                "{bad}"
            );
        }
        assert!(matches!(
            credentials_safe("ftp://127.0.0.1"),
            Err(TransportError::Scheme(_))
        ));
        assert!(matches!(
            credentials_safe("127.0.0.1:18232"),
            Err(TransportError::Malformed(_))
        ));
        assert!(credentials_safe("http://").is_err());
    }
}
