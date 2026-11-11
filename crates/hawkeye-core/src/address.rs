//! Ycash transparent addresses: base58check with two-byte prefixes (ycash-dd
//! `src/chainparams.cpp:155,157,420,422,628,629`).
//!
//! The leading characters are not what the chainparams comments promise for P2SH: mainnet P2SH
//! (`1c2c`) encodes to `s2…` or `s3…`, testnet/regtest P2SH (`1c2a`) to `s2…` (not `t2…`).
//! Decoding goes by prefix bytes, never by the leading characters.
//!
//! Post-quantum addresses (quantum spec §4.1, decision D-9) are base58check of
//! `version(3) ‖ keyHash(32)`, 53 characters, with one 3-byte version per network, form and
//! scheme, so the prefix names the scheme (`f` FN-DSA-512, `s` SLH-DSA-SHA2-128s). The table
//! [`PQ_VERSIONS`] is the only place the versions live; encoding and decoding both read it
//! (the node's `PlainPQAddressVersions` and Yellowback `pqAddressVersions`, ycash-dd/ycash6
//! `up/b2-pq-prefix`). The pre-D-9 form (`version(2) ‖ scheme ‖ keyHash`) is refused.
//!
//! A vault owner is named by the **owner** form, the YED holder form: `ybf…`/`ybs…` mainnet,
//! `ytf…`/`yts…` testnet, `yrf…`/`yrs…` regtest. The node also renders a post-quantum key as a
//! **plain-YEC PQ address** (quantum plan D-Q-20, a `TX_PQPKH` output): `sqf…`/`sqs…`,
//! `tqf…`/`tqs…`, `rqf…`/`rqs…`. That form names a kind-2 **burn recipient** (plan §4.2):
//! [`decode_address`] returns it beside P2PKH and P2SH. The owner form never does: owner keys
//! are vault owners, not holder addresses.

use crate::bytes::sha256d;
use crate::error::{Error, Result};
use crate::pq::PqKeyId;
use crate::recipient::YcashRecipient;

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
}

/// Which post-quantum address form a version names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqForm {
    /// The plain-YEC form (`sq…`/`tq…`/`rq…`): a `TX_PQPKH` payee, a burn recipient.
    Plain,
    /// The owner form, the YED holder form (`yb…`/`yt…`/`yr…`): a vault owner.
    Owner,
}

/// Every post-quantum address version (quantum spec §4.1, D-9): `(version, network, form,
/// scheme)`, scheme 1 SLH-DSA-SHA2-128s, 2 FN-DSA-512. One table for both directions.
pub const PQ_VERSIONS: [([u8; 3], Network, PqForm, u8); 12] = [
    ([0x4d, 0xdd, 0x04], Network::Mainnet, PqForm::Plain, 2), // sqf…
    ([0x4d, 0xde, 0x6a], Network::Mainnet, PqForm::Plain, 1), // sqs…
    ([0x4f, 0x65, 0x19], Network::Testnet, PqForm::Plain, 2), // tqf…
    ([0x4f, 0x66, 0x7f], Network::Testnet, PqForm::Plain, 1), // tqs…
    ([0x4c, 0x54, 0xef], Network::Regtest, PqForm::Plain, 2), // rqf…
    ([0x4c, 0x56, 0x55], Network::Regtest, PqForm::Plain, 1), // rqs…
    ([0x56, 0xae, 0xde], Network::Mainnet, PqForm::Owner, 2), // ybf…
    ([0x56, 0xb0, 0x44], Network::Mainnet, PqForm::Owner, 1), // ybs…
    ([0x57, 0x21, 0xc9], Network::Testnet, PqForm::Owner, 2), // ytf…
    ([0x57, 0x23, 0x30], Network::Testnet, PqForm::Owner, 1), // yts…
    ([0x57, 0x14, 0x44], Network::Regtest, PqForm::Owner, 2), // yrf…
    ([0x57, 0x15, 0xaa], Network::Regtest, PqForm::Owner, 1), // yrs…
];

/// The 3-byte version of a post-quantum address of `network`, `form` and `scheme`; `None` for a
/// scheme outside the registry.
pub fn pq_version(network: Network, form: PqForm, scheme: u8) -> Option<[u8; 3]> {
    PQ_VERSIONS
        .iter()
        .find(|(_, n, f, s)| *n == network && *f == form && *s == scheme)
        .map(|(v, ..)| *v)
}

/// What a 3-byte post-quantum version names: `(network, form, scheme)`; `None` for any other.
pub fn pq_version_info(version: &[u8]) -> Option<(Network, PqForm, u8)> {
    PQ_VERSIONS
        .iter()
        .find(|(v, ..)| v.as_slice() == version)
        .map(|(_, n, f, s)| (*n, *f, *s))
}

fn encode_pq(id: &PqKeyId, network: Network, form: PqForm) -> String {
    let v = pq_version(network, form, id.scheme).expect("a PqKeyId's scheme is registered");
    let mut data = v.to_vec();
    data.extend_from_slice(&id.hash);
    base58check_encode(&data)
}

/// Decode a 35-byte post-quantum payload (`version(3) ‖ keyHash(32)`) of `network` and `form`.
fn decode_pq(v: &[u8], network: Network, form: PqForm) -> Result<PqKeyId> {
    let Some((n, f, scheme)) = pq_version_info(&v[..3]) else {
        return Err(Error::Address("unknown post-quantum address version"));
    };
    if n != network {
        return Err(Error::Address("prefix of another network or kind"));
    }
    if f != form {
        return Err(Error::Address(match form {
            PqForm::Plain => "a post-quantum owner address is not a recipient",
            PqForm::Owner => "prefix of another network or kind",
        }));
    }
    let hash: [u8; 32] = v[3..].try_into().expect("32 bytes");
    PqKeyId::new(scheme, hash).map_err(|_| Error::Address("unknown post-quantum scheme"))
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
/// plain-YEC PQ form (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`, 53 characters) of a
/// `TX_PQPKH` recipient.
pub fn encode_address(recipient: &YcashRecipient, network: Network) -> String {
    let transparent = |prefix: [u8; 2], h: &[u8; 20]| {
        let mut data = prefix.to_vec();
        data.extend_from_slice(h);
        base58check_encode(&data)
    };
    match recipient {
        YcashRecipient::P2pkh(h) => transparent(network.p2pkh_prefix(), h),
        YcashRecipient::P2sh(h) => transparent(network.p2sh_prefix(), h),
        YcashRecipient::Pqpkh(id) => encode_pq(id, network, PqForm::Plain),
    }
}

/// Decode a recipient address of `network`: P2PKH or P2SH (22-byte payload), or a plain-YEC PQ
/// address (35-byte payload under one of this network's plain versions). The PQ *owner* address
/// ([`decode_pq_address`]) is refused: it is not a burn recipient. So is the pre-D-9 form.
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
            let id = decode_pq(&v, network, PqForm::Plain)?;
            YcashRecipient::pqpkh(id.scheme, id.hash)
                .map_err(|_| Error::Address("unknown post-quantum scheme"))
        }
        _ => Err(Error::Address("wrong payload length")),
    }
}

/// The post-quantum owner address of `owner` on `network` (53 characters).
pub fn encode_pq_address(owner: &PqKeyId, network: Network) -> String {
    encode_pq(owner, network, PqForm::Owner)
}

/// Decode a post-quantum owner address of `network` (the node's Yellowback
/// `DecodeAddress(…, CPQKeyID&)`: exactly 35 bytes under one of this network's owner versions).
pub fn decode_pq_address(s: &str, network: Network) -> Result<PqKeyId> {
    let v = base58check_decode(s)?;
    if v.len() != 35 {
        return Err(Error::Address("wrong payload length"));
    }
    decode_pq(&v, network, PqForm::Owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected strings computed independently (Python base58check over the D-9 versions, quantum
    /// spec §4.1); the scheme-1 hash is the node vector's `pqOwner`.
    #[test]
    fn pq_addresses() {
        let owner =
            PqKeyId::from_hex("01c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258")
                .unwrap();
        let falcon = PqKeyId::new(2, [0xff; 32]).unwrap();
        for (net, a1, a2) in [
            (
                Network::Mainnet,
                "ybs3nm1Yz46hpcPU4WYshmE5WUFM77pRoBQgmCQr3b3ZBUw4QkgvM",
                "ybf4L6UbYoEYjJipy2WptNknL8jTQNmwpZTVyZCMBPqeFWHgBEizo",
            ),
            (
                Network::Testnet,
                "yts4Rd3MTYjZ79Can18fzLAYXbuAokwXYPUYLPmhB8C7u78UQC2ub",
                "ytf32DLAaG1yLcQ86pC3YwjvkVUAVJFLitjiUeK3d2zYxjzRmoJrU",
            ),
            (
                Network::Regtest,
                "yrs2kSJbczYdh8QUvJfsD66LrbYGogPeAwHo9hB7mcmWkUhVMYWMy",
                "yrf3HmmeBjgUbpjqppdpPhd3gG2P6wMACKLcN3xcuRZbpW49q9FSv",
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
        assert!(decode_pq_address(&main, Network::Regtest).is_err());
        // the pre-D-9 form (0x56AB ‖ scheme ‖ keyHash) and the retired 0x56BF (`ye…`) are refused
        for old in [
            "yb5uQ2PDR3EcpZmSHVS4eqT7uLihaqAthhUkNBo5V53tB6DJDyVow",
            "ye3W1TcRQYJwa47heYwxWkw1eKQidXYKExKCyNt1NtcxQiqLtXn6o",
        ] {
            assert_eq!(
                decode_pq_address(old, Network::Mainnet),
                Err(Error::Address("unknown post-quantum address version"))
            );
        }
        // a transparent address is not an owner address, nor the other way round
        let t = encode_address(&YcashRecipient::p2pkh([7; 20]), Network::Mainnet);
        assert!(decode_pq_address(&t, Network::Mainnet).is_err());
        assert!(decode_address(&main, Network::Mainnet).is_err());
        // the table: twelve distinct versions, each found again from its parts
        for (v, n, f, sc) in PQ_VERSIONS {
            assert_eq!(pq_version(n, f, sc), Some(v));
            assert_eq!(pq_version_info(&v), Some((n, f, sc)));
        }
        assert_eq!(pq_version(Network::Mainnet, PqForm::Owner, 3), None);
    }

    /// The node's mainnet known answers re-encoded under D-9 (`Hash32(0x5a)` under each scheme,
    /// ycash-dd `src/test/pq_standard_tests.cpp`), and the extreme payloads (`00`×32, `ff`×32
    /// under each mainnet owner version) that pin the `ybf`/`ybs` leading characters and the
    /// 53-character length.
    #[test]
    fn node_known_answers() {
        let main = Network::Mainnet;
        assert_eq!(
            encode_pq_address(&PqKeyId::new(1, [0x5a; 32]).unwrap(), main),
            "ybs2yeQAU6HatHuTWtMW3GUy4Aa3MXFt8eXxkjSEHZqHM2zHYK76X"
        );
        assert_eq!(
            encode_pq_address(&PqKeyId::new(2, [0x5a; 32]).unwrap(), main),
            "ybf359F9nfDGmDdmUPoyqZ2AQvjCtSXnTAq9QC6c2dxgxCKgiEFio"
        );
        for (_, n, f, sc) in PQ_VERSIONS {
            let lead = match (n, f) {
                (Network::Mainnet, PqForm::Plain) => "sq",
                (Network::Testnet, PqForm::Plain) => "tq",
                (Network::Regtest, PqForm::Plain) => "rq",
                (Network::Mainnet, PqForm::Owner) => "yb",
                (Network::Testnet, PqForm::Owner) => "yt",
                (Network::Regtest, PqForm::Owner) => "yr",
            };
            let lead = format!("{lead}{}", if sc == 2 { 'f' } else { 's' });
            for fill in [0x00u8, 0xff] {
                let id = PqKeyId::new(sc, [fill; 32]).unwrap();
                let s = encode_pq(&id, n, f);
                assert_eq!(s.len(), 53, "{s}");
                assert!(s.starts_with(&lead), "{s} does not start {lead}");
            }
        }
    }

    /// The plain-YEC PQ address (`sqf…`/`sqs…` and the test/regtest forms, D-Q-20, D-9):
    /// expected strings computed independently (Python base58check over the D-9 versions; the
    /// scheme-1 hash is the node vector's `pqOwner`), 53 characters, decoded as a kind-2
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
        for (net, a1, a2) in [
            (
                Network::Mainnet,
                "sqs3t3JioyNB4w4jeZuep8UeXwx3ZRcvNsnP9ozEQxLiJSFW53sHq",
                "sqf4RNmmNiW1ydQ6Z5sbzk1MMcS9rgaSQFqCNAmjYm8oNTc5ax2ZX",
            ),
            (
                Network::Testnet,
                "tqs3soGqsGXFAfk9yAeYvBjU3mWCCkK135UzjRBByFnuSxNVMDuJK",
                "tqf4R8jtS1f65N5WsgcW6oGAsRzJW1GX4TXowmxh74azWyj9QK3MK",
            ),
            (
                Network::Regtest,
                "rqs3tHLbkgD6yCPKKyAki5Dq28Ptv6vqig5maCoGretX9v8SB2f5q",
                "rqf4RcoeKRLwstigEV8htgkXqnt1DMtMk48anZamzTgcDwV5p3kn1",
            ),
        ] {
            assert_eq!(encode_address(&slh, net), a1);
            assert_eq!(encode_address(&falcon, net), a2);
            assert_eq!(a1.len(), 53);
            assert_eq!(decode_address(a1, net).unwrap(), slh);
            assert_eq!(decode_address(a2, net).unwrap(), falcon);
            // the same key's owner address is not a recipient
            let owner = encode_pq_address(slh.pq_key().unwrap(), net);
            assert_eq!(
                decode_address(&owner, net),
                Err(Error::Address(
                    "a post-quantum owner address is not a recipient"
                ))
            );
            // and the plain form is not an owner address
            assert!(decode_pq_address(a1, net).is_err());
        }
        // the node's known-answer hash under the plain versions (Python)
        assert_eq!(
            encode_address(
                &YcashRecipient::pqpkh(1, [0x5a; 32]).unwrap(),
                Network::Mainnet
            ),
            "sqs34vhLJ1Z48caj6wiH9djY5eGjoq4NiLuf9M1cew8STzJkZtyAr"
        );
        assert_eq!(
            encode_address(
                &YcashRecipient::pqpkh(2, [0x5a; 32]).unwrap(),
                Network::Mainnet
            ),
            "sqf3ARYKcaUk1YK34TAkwvGjSQRuLkLH2sCqnofzQ1Fr59eA2Past"
        );
        // another network's form; the pre-D-9 form; a 34-byte payload
        let main = encode_address(&slh, Network::Mainnet);
        assert!(decode_address(&main, Network::Regtest).is_err());
        assert!(decode_address(&main, Network::Testnet).is_err());
        assert_eq!(
            decode_address(
                "sq4couNBfnJoRxqXF89SWjiPh5wktFi5bb5S4F89xMMsCrqRf2L4z",
                Network::Mainnet
            ),
            Err(Error::Address("unknown post-quantum address version"))
        );
        let mut d = pq_version(Network::Mainnet, PqForm::Plain, 1)
            .unwrap()
            .to_vec();
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
