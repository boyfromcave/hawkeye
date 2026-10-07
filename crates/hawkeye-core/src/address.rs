//! Ycash transparent addresses: base58check with two-byte prefixes (ycash-dd
//! `src/chainparams.cpp:155,157,420,422,628,629`).
//!
//! The leading characters are not what the chainparams comments promise for P2SH: mainnet P2SH
//! (`1c2c`) encodes to `s2…` or `s3…`, testnet/regtest P2SH (`1c2a`) to `s2…` (not `t2…`).
//! Decoding goes by prefix bytes, never by the leading characters.

use crate::bytes::sha256d;
use crate::error::{Error, Result};
use crate::recipient::{RecipientKind, YcashRecipient};

/// A Ycash network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Mainnet: `s1…` (P2PKH), `s2…`/`s3…` (P2SH).
    Mainnet,
    /// Testnet: `sm…` (P2PKH), `s2…` (P2SH).
    Testnet,
    /// Regtest: the testnet prefixes.
    Regtest,
}

impl Network {
    /// The P2PKH prefix.
    pub fn p2pkh_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x1c, 0x28],
            Self::Testnet | Self::Regtest => [0x1c, 0x95],
        }
    }

    /// The P2SH prefix.
    pub fn p2sh_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x1c, 0x2c],
            Self::Testnet | Self::Regtest => [0x1c, 0x2a],
        }
    }

    fn prefix(self, kind: RecipientKind) -> [u8; 2] {
        match kind {
            RecipientKind::P2pkh => self.p2pkh_prefix(),
            RecipientKind::P2sh => self.p2sh_prefix(),
        }
    }
}

/// Base58check of `prefix ‖ payload ‖ SHA256d(prefix ‖ payload)[..4]`.
pub fn base58check_encode(data: &[u8]) -> String {
    let mut v = data.to_vec();
    v.extend_from_slice(&sha256d(data)[..4]);
    bs58::encode(v).into_string()
}

/// Decode base58check, verifying and stripping the checksum.
pub fn base58check_decode(s: &str) -> Result<Vec<u8>> {
    let mut v = bs58::decode(s)
        .into_vec()
        .map_err(|_| Error::Address("not base58"))?;
    if v.len() < 4 {
        return Err(Error::Address("too short"));
    }
    let split = v.len() - 4;
    if sha256d(&v[..split])[..4] != v[split..] {
        return Err(Error::Address("bad checksum"));
    }
    v.truncate(split);
    Ok(v)
}

/// The transparent address of `recipient` on `network`.
pub fn encode_address(recipient: &YcashRecipient, network: Network) -> String {
    let mut data = network.prefix(recipient.kind).to_vec();
    data.extend_from_slice(&recipient.hash);
    base58check_encode(&data)
}

/// Decode a transparent address of `network` (P2PKH or P2SH).
pub fn decode_address(s: &str, network: Network) -> Result<YcashRecipient> {
    let v = base58check_decode(s)?;
    if v.len() != 22 {
        return Err(Error::Address("wrong payload length"));
    }
    let hash: [u8; 20] = v[2..].try_into().expect("20 bytes");
    if v[..2] == network.p2pkh_prefix() {
        Ok(YcashRecipient::p2pkh(hash))
    } else if v[..2] == network.p2sh_prefix() {
        Ok(YcashRecipient::p2sh(hash))
    } else {
        Err(Error::Address("prefix of another network or kind"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected strings computed independently (Python base58check over the same prefixes).
    #[test]
    fn known_encodings() {
        let h = [0x5a; 20];
        for (net, p2pkh, p2sh) in [
            (
                Network::Mainnet,
                "s1VSVGo8TZzsSi5ndRWudtZpy8xmeA3dnno",
                "s36nuDEKcQiiwypLyXCEuq4v7eyoR1P5SEW",
            ),
            (
                Network::Testnet,
                "smMHEbdcrxfNwrKz56FDNkEVijwrTdKCFFv",
                "s2J7hF1j2zMoCLx4oUMaGrpNYPyHXbc3Sab",
            ),
            (
                Network::Regtest,
                "smMHEbdcrxfNwrKz56FDNkEVijwrTdKCFFv",
                "s2J7hF1j2zMoCLx4oUMaGrpNYPyHXbc3Sab",
            ),
        ] {
            assert_eq!(encode_address(&YcashRecipient::p2pkh(h), net), p2pkh);
            assert_eq!(encode_address(&YcashRecipient::p2sh(h), net), p2sh);
            assert_eq!(
                decode_address(p2pkh, net).unwrap(),
                YcashRecipient::p2pkh(h)
            );
            assert_eq!(decode_address(p2sh, net).unwrap(), YcashRecipient::p2sh(h));
        }
        for h in [[0u8; 20], [0xff; 20]] {
            for net in [Network::Mainnet, Network::Testnet] {
                for r in [YcashRecipient::p2pkh(h), YcashRecipient::p2sh(h)] {
                    assert_eq!(decode_address(&encode_address(&r, net), net).unwrap(), r);
                }
            }
        }
    }

    #[test]
    fn rejects() {
        let a = encode_address(&YcashRecipient::p2pkh([7; 20]), Network::Mainnet);
        assert!(decode_address(&a, Network::Testnet).is_err());
        let mut chars: Vec<char> = a.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let bad: String = chars.into_iter().collect();
        assert_eq!(
            decode_address(&bad, Network::Mainnet),
            Err(Error::Address("bad checksum"))
        );
        assert!(decode_address("0OIl", Network::Mainnet).is_err());
        assert!(decode_address("", Network::Mainnet).is_err());
        // a Bitcoin-style one-byte prefix address
        let btc = base58check_encode(&[[0u8].as_slice(), &[7; 20]].concat());
        assert!(decode_address(&btc, Network::Mainnet).is_err());
    }
}
