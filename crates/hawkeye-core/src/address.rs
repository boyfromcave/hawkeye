//! Ycash transparent addresses: base58check with two-byte prefixes (ycash-dd
//! `src/chainparams.cpp:155,157,420,422,628,629`).
//!
//! The leading characters are not what the chainparams comments promise for P2SH: mainnet P2SH
//! (`1c2c`) encodes to `s2…` or `s3…`, testnet/regtest P2SH (`1c2a`) to `s2…` (not `t2…`).
//! Decoding goes by prefix bytes, never by the leading characters.
//!
//! A vault owner is named by a **post-quantum address** (quantum spec §4): base58check of
//! `pqVersion(2) ‖ scheme ‖ keyHash(32)`, 53 characters, `yb…` / `yt…` / `yr…` (versions
//! `0x56AB` / `0x571E` / `0x5710`, ycash-dd `src/yellowback/params.cpp`, `pqAddressVersion`;
//! the mainnet version is quantum plan D-Q-21's, `yb…` like the 35-character YED address).
//!
//! The node also renders a post-quantum key as a **plain-YEC PQ address** (`sq…`/`tq…`/`rq…`,
//! quantum plan D-Q-20, a `TX_PQPKH` output): base58check of `version(2) ‖ scheme ‖ keyHash(32)`,
//! 53 characters, versions `0x4DD9` / `0x4F61` / `0x4C51` (ycash-dd `src/key_io.cpp:23-27` at
//! `d41026209`, `PlainPQAddressVersion`). That form names a kind-2 **burn recipient** (plan
//! §4.2): [`decode_address`] returns it beside P2PKH and P2SH. The owner form never does: owner
//! keys are vault owners, not holder addresses.

use crate::bytes::sha256d;
use crate::error::{Error, Result};
use crate::pq::PqKeyId;
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

    /// The post-quantum (owner) address version: `yb…`, `yt…`, `yr…`.
    pub fn pq_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x56, 0xab],
            Self::Testnet => [0x57, 0x1e],
            Self::Regtest => [0x57, 0x10],
        }
    }

    /// The plain-YEC post-quantum address version (`TX_PQPKH` payees, D-Q-20): `sq…`, `tq…`,
    /// `rq…` (`src/key_io.cpp:23-27`).
    pub fn pq_plain_prefix(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x4d, 0xd9],
            Self::Testnet => [0x4f, 0x61],
            Self::Regtest => [0x4c, 0x51],
        }
    }

    fn prefix(self, kind: RecipientKind) -> [u8; 2] {
        match kind {
            RecipientKind::P2pkh => self.p2pkh_prefix(),
            RecipientKind::P2sh => self.p2sh_prefix(),
            RecipientKind::Pqpkh => self.pq_plain_prefix(),
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

/// The address of `recipient` on `network`: transparent (`s1…`/`s2…`/`s3…`, `sm…`), or the
/// plain-YEC PQ form (`sq…`/`tq…`/`rq…`, 53 characters) of a `TX_PQPKH` recipient.
pub fn encode_address(recipient: &YcashRecipient, network: Network) -> String {
    let mut data = network.prefix(recipient.kind()).to_vec();
    match recipient {
        YcashRecipient::P2pkh(h) | YcashRecipient::P2sh(h) => data.extend_from_slice(h),
        YcashRecipient::Pqpkh(id) => data.extend_from_slice(&id.to_bytes()),
    }
    base58check_encode(&data)
}

/// Decode a recipient address of `network`: P2PKH or P2SH (22-byte payload), or a plain-YEC PQ
/// address (`sq…`/`tq…`/`rq…`, 35-byte payload, a registered scheme). The PQ *owner* address
/// (`yb…`/`yt…`/`yr…`, [`decode_pq_address`]) is refused: it is not a burn recipient.
pub fn decode_address(s: &str, network: Network) -> Result<YcashRecipient> {
    let v = base58check_decode(s)?;
    match v.len() {
        22 => {
            let hash: [u8; 20] = v[2..].try_into().expect("20 bytes");
            if v[..2] == network.p2pkh_prefix() {
                Ok(YcashRecipient::p2pkh(hash))
            } else if v[..2] == network.p2sh_prefix() {
                Ok(YcashRecipient::p2sh(hash))
            } else {
                Err(Error::Address("prefix of another network or kind"))
            }
        }
        35 => {
            if v[..2] == network.pq_prefix() {
                return Err(Error::Address(
                    "a post-quantum owner address is not a recipient",
                ));
            }
            if v[..2] != network.pq_plain_prefix() {
                return Err(Error::Address("prefix of another network or kind"));
            }
            let hash: [u8; 32] = v[3..].try_into().expect("32 bytes");
            YcashRecipient::pqpkh(v[2], hash)
                .map_err(|_| Error::Address("unknown post-quantum scheme"))
        }
        _ => Err(Error::Address("wrong payload length")),
    }
}

/// The post-quantum address of `owner` on `network` (53 characters).
pub fn encode_pq_address(owner: &PqKeyId, network: Network) -> String {
    let mut data = network.pq_prefix().to_vec();
    data.extend_from_slice(&owner.to_bytes());
    base58check_encode(&data)
}

/// Decode a post-quantum address of `network` (the node's `DecodeAddress(…, CPQKeyID&)`:
/// exactly 35 bytes, this network's version, a registered scheme).
pub fn decode_pq_address(s: &str, network: Network) -> Result<PqKeyId> {
    let v = base58check_decode(s)?;
    if v.len() != 35 {
        return Err(Error::Address("wrong payload length"));
    }
    if v[..2] != network.pq_prefix() {
        return Err(Error::Address("prefix of another network or kind"));
    }
    let id: [u8; 33] = v[2..].try_into().expect("33 bytes");
    PqKeyId::from_bytes(&id).map_err(|_| Error::Address("unknown post-quantum scheme"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected strings computed independently (Python base58check over the quantum spec §4
    /// versions, mainnet `0x56AB` per D-Q-21); the scheme-1 hash is the node vector's `pqOwner`.
    #[test]
    fn pq_addresses() {
        let owner =
            PqKeyId::from_hex("01c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258")
                .unwrap();
        let falcon = PqKeyId::new(2, [0xff; 32]).unwrap();
        for (net, a1, a2) in [
            (
                Network::Mainnet,
                "yb5uQ2PDR3EcpZmSHVS4eqT7uLihaqAthhUkNBo5V53tB6DJDyVow",
                "yb5wncBW7FJCXZWJpCr7fAPwy1xkxtWDFS221CAMZhiDeLjBHdsWi",
            ),
            (
                Network::Testnet,
                "yt6aumwesAuyddGxd69TMPTzuxgobqJ5JRHPMY2vNY5Z2UHDaLMVu",
                "yt6dJMjwZNyZLd1q9oZWMiQpydvrytdPr9pezYQCTAjtVio7KiffW",
            ),
            (
                Network::Regtest,
                "yr2U5mgcGim9hz2msM5vrF2g6UbzU9SH896fXhg53fP14XePwX6PL",
                "yr2WUMUtxvpjQymeQ4VyrZyWA9r3rCmbfsdwAi3M8J3LXnAGrkb5E",
            ),
        ] {
            assert_eq!(encode_pq_address(&owner, net), a1);
            assert_eq!(encode_pq_address(&falcon, net), a2);
            assert_eq!(a1.len(), 53);
            assert_eq!(decode_pq_address(a1, net).unwrap(), owner);
            assert_eq!(decode_pq_address(a2, net).unwrap(), falcon);
        }
        let main = encode_pq_address(&owner, Network::Mainnet);
        assert!(decode_pq_address(&main, Network::Testnet).is_err());
        // the former mainnet version 0x56BF (`ye…`) is another network's now
        assert!(
            decode_pq_address(
                "ye3W1TcRQYJwa47heYwxWkw1eKQidXYKExKCyNt1NtcxQiqLtXn6o",
                Network::Mainnet
            )
            .is_err()
        );
        // a transparent address is not an owner address, nor the other way round
        let t = encode_address(&YcashRecipient::p2pkh([7; 20]), Network::Mainnet);
        assert!(decode_pq_address(&t, Network::Mainnet).is_err());
        assert!(decode_address(&main, Network::Mainnet).is_err());
        // scheme 3 under the right version
        let mut d = Network::Mainnet.pq_prefix().to_vec();
        d.push(3);
        d.extend([0; 32]);
        assert_eq!(
            decode_pq_address(&base58check_encode(&d), Network::Mainnet),
            Err(Error::Address("unknown post-quantum scheme"))
        );
    }

    /// The node's own mainnet known answers (ycash-dd `d41026209` `src/test/pq_standard_tests.cpp`,
    /// "D-Q-21 known answers"): `Hash32(0x5a)` under each scheme, and the extreme payloads
    /// (33 × `00`, 33 × `ff`) that pin the `yb` leading characters and the 53-character length.
    #[test]
    fn node_known_answers() {
        let main = Network::Mainnet;
        assert_eq!(
            encode_pq_address(&PqKeyId::new(1, [0x5a; 32]).unwrap(), main),
            "yb5taumpu5RVtFHRjsEgzLi1T33PqEcM3Ac2MipTj3qcLeGaSRJGu"
        );
        assert_eq!(
            encode_pq_address(&PqKeyId::new(2, [0x5a; 32]).unwrap(), main),
            "yb5vXex4M7GvZURFKa9GcLfL3oxWSxG3t3PfRq4cQwqGM2mH4L3Kg"
        );
        for (fill, want) in [
            (
                0x00u8,
                "yb5qxNeom9jvVt6r568NoAXzAhDR7jZ6iof6nsRuW1jFdBFSvPpBv",
            ),
            (
                0xff,
                "ybERawpAfKtqdrcrqeCmgxi5ewecmZyNSy6ivRtFbWD1LTaaj8eCA",
            ),
        ] {
            let mut d = main.pq_prefix().to_vec();
            d.extend([fill; 33]);
            let s = base58check_encode(&d);
            assert_eq!(s, want);
            assert_eq!(s.len(), 53);
            assert!(s.starts_with("yb"));
        }
    }

    /// The plain-YEC PQ address (`sq…`/`tq…`/`rq…`, D-Q-20): expected strings computed
    /// independently (Python base58check over `src/key_io.cpp:23-27`'s versions; the scheme-1
    /// hash is the node vector's `pqOwner`), 53 characters, the node's leading characters
    /// (`src/test/pq_address_tests.cpp` `sq_roundtrip_per_network`), decoded as a kind-2
    /// recipient; the owner form of the same key is refused as a recipient.
    #[test]
    fn plain_pq_addresses() {
        let slh = YcashRecipient::pqpkh(
            1,
            hex::decode("c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let falcon = YcashRecipient::pqpkh(2, [0xff; 32]).unwrap();
        for (net, lead, a1, a2) in [
            (
                Network::Mainnet,
                "sq",
                "sq4dd1yaBk7vNHKXnkLpBETW9Pd4drGdG7xA4i6miNa93JnE4ucTW",
                "sq4g1bmrsxBW5H4QKTksBZQLD4s81ubworVRhiU3o1EUWZJ1erUQK",
            ),
            (
                Network::Testnet,
                "tq",
                "tq3vo9EppNP4GGAiuY3YFJgb4wwpM6JvDw8MA4Aapr9a3gYCxkyak",
                "tq3yBj37WaSdyFubSFTbFddR8dBsj9eEmffco4XruUouWw44waFrF",
            ),
            (
                Network::Regtest,
                "rq",
                "rq5LStiKZ7rnUJULfxe67AERDqJJvcELJJmxyN2xbtzi2w2A7xSr6",
                "rq5NqUWcFKvNBJDDCg497VBFHWYNJfZer3KEcNQEgXf3WBY5W1R6q",
            ),
        ] {
            assert_eq!(encode_address(&slh, net), a1);
            assert_eq!(encode_address(&falcon, net), a2);
            assert_eq!(a1.len(), 53);
            assert!(a1.starts_with(lead) && a2.starts_with(lead), "{net:?}");
            assert_eq!(decode_address(a1, net).unwrap(), slh);
            assert_eq!(decode_address(a2, net).unwrap(), falcon);
            // the same key's owner address (yb…/yt…/yr…) is not a recipient
            let owner = encode_pq_address(slh.pq_key().unwrap(), net);
            assert_eq!(
                decode_address(&owner, net),
                Err(Error::Address(
                    "a post-quantum owner address is not a recipient"
                ))
            );
            // and the sq… form is not an owner address
            assert!(decode_pq_address(a1, net).is_err());
        }
        // the node's D-Q-21 known-answer hash under the plain versions (Python)
        let h5a = YcashRecipient::pqpkh(1, [0x5a; 32]).unwrap();
        assert_eq!(
            encode_address(&h5a, Network::Mainnet),
            "sq4couNBfnJoRxqXF89SWjiPh5wktFi5bb5S4F89xMMsCrqRf2L4z"
        );
        assert_eq!(
            encode_address(
                &YcashRecipient::pqpkh(2, [0x5a; 32]).unwrap(),
                Network::Mainnet
            ),
            "sq4ekeYR7pAE7ByLpq428jfiHrrsVyMnSTs58MNJeFMXDFL63vTbT"
        );
        // another network's form; scheme 3 under the right version; a 34-byte payload
        let main = encode_address(&slh, Network::Mainnet);
        assert!(decode_address(&main, Network::Regtest).is_err());
        assert!(decode_address(&main, Network::Testnet).is_err());
        let mut d = Network::Mainnet.pq_plain_prefix().to_vec();
        d.push(3);
        d.extend([0; 32]);
        assert_eq!(
            decode_address(&base58check_encode(&d), Network::Mainnet),
            Err(Error::Address("unknown post-quantum scheme"))
        );
        let mut d = Network::Mainnet.pq_plain_prefix().to_vec();
        d.push(1);
        d.extend([0; 31]);
        assert_eq!(
            decode_address(&base58check_encode(&d), Network::Mainnet),
            Err(Error::Address("wrong payload length"))
        );
    }

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
