// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The node lines' shared post-quantum address vectors (decision D-9; `tests/data/README.md`):
//! every valid vector decodes on its own network and form only, to its scheme and key hash, and
//! encodes back to itself; every invalid vector is refused on every network, in both forms.

use hawkeye_core::PqKeyId;
use hawkeye_core::address::{
    Network, PqForm, decode_address, decode_pq_address, encode_address, encode_pq_address,
    pq_version,
};
use hawkeye_core::bytes::{from_hex_array, sha256};
use hawkeye_core::recipient::YcashRecipient;
use serde_json::Value;

const FILE: &[u8] = include_bytes!("data/pq_address_vectors.json");
const FILE_SHA256: &str = "dbbd1da05d995d659e1e9f8a671197e141c272998722d6cca85cdbdb52b61797";
const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

fn network(name: &str) -> Network {
    match name {
        "main" => Network::Mainnet,
        "test" => Network::Testnet,
        "regtest" => Network::Regtest,
        other => panic!("network {other}"),
    }
}

fn vectors() -> Value {
    assert_eq!(
        hex::encode(sha256(FILE)),
        FILE_SHA256,
        "pq_address_vectors.json drifted from the node lines' file"
    );
    serde_json::from_slice(FILE).expect("parses")
}

#[test]
fn valid_vectors() {
    let v = vectors();
    assert_eq!(v["format"], "ycash-pq-address-vectors-1");
    let valid = v["valid"].as_array().expect("valid");
    assert_eq!(valid.len(), 72);
    for c in valid {
        let addr = c["address"].as_str().unwrap();
        let net = network(c["network"].as_str().unwrap());
        let scheme = c["scheme"].as_u64().unwrap() as u8;
        let hash: [u8; 32] = from_hex_array("keyhash", c["keyhash"].as_str().unwrap()).unwrap();
        let id = PqKeyId::new(scheme, hash).unwrap();
        let form = match c["coin"].as_str().unwrap() {
            "yed" => PqForm::Owner,
            "yec" => PqForm::Plain,
            other => panic!("coin {other}"),
        };
        assert_eq!(
            hex::encode(pq_version(net, form, scheme).unwrap()),
            c["version"].as_str().unwrap(),
            "{addr}"
        );
        match form {
            PqForm::Owner => {
                assert_eq!(decode_pq_address(addr, net).unwrap(), id, "{addr}");
                assert_eq!(encode_pq_address(&id, net), addr);
                assert!(
                    decode_address(addr, net).is_err(),
                    "{addr}: owner as recipient"
                );
            }
            PqForm::Plain => {
                let r = YcashRecipient::pqpkh(scheme, hash).unwrap();
                assert_eq!(decode_address(addr, net).unwrap(), r, "{addr}");
                assert_eq!(encode_address(&r, net), addr);
                assert!(
                    decode_pq_address(addr, net).is_err(),
                    "{addr}: recipient as owner"
                );
            }
        }
        // cross-network: refused everywhere else
        for other in NETWORKS.into_iter().filter(|n| *n != net) {
            assert!(
                decode_pq_address(addr, other).is_err(),
                "{addr} on {other:?}"
            );
            assert!(decode_address(addr, other).is_err(), "{addr} on {other:?}");
        }
    }
}

#[test]
fn invalid_vectors() {
    let v = vectors();
    let invalid = v["invalid"].as_array().expect("invalid");
    assert_eq!(invalid.len(), 60);
    for c in invalid {
        let addr = c["address"].as_str().unwrap();
        for net in NETWORKS {
            assert!(
                decode_pq_address(addr, net).is_err(),
                "{addr} ({}) as an owner on {net:?}",
                c["reason"]
            );
            assert!(
                decode_address(addr, net).is_err(),
                "{addr} ({}) as a recipient on {net:?}",
                c["reason"]
            );
        }
    }
}
