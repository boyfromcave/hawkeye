// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The peer-channel authentication vectors (plan §4.6, remedial report 05/H-1 §4.1): the request
//! preimage and message for fixed inputs, field-by-field sensitivity, the signature round trip
//! and the response message.

use hawkeye_core::bytes::sha256d;
use hawkeye_core::peerauth::{
    PeerRequest, hwm_msg, parse_member, parse_nonce, parse_sig, parse_time, request_msg,
    request_preimage, response_msg, sign, verify,
};
use hawkeye_core::{Deployment, EthAddress, SecretKey};

const SET: [u8; 32] = [0x11; 32];
const NONCE: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const BODY: &[u8] = br#"{"hex":"00"}"#;

/// The committed message of the fixed request.
const MSG: &str = "fd8d6317b8ed13cf458439ac121f07558cef5680ef078940f3ad4a6629747a7c";

fn deployment() -> Deployment {
    Deployment {
        chain_id: 31337,
        bridge: EthAddress::parse("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
    }
}

fn request<'a>(d: &'a Deployment, set: &'a [u8; 32], nonce: &'a [u8; 16]) -> PeerRequest<'a> {
    PeerRequest {
        set_id: set,
        deployment: d,
        method: "POST",
        path: "/unlock/sign",
        timestamp: 1_760_000_000,
        nonce,
        body: BODY,
    }
}

#[test]
fn fixed_vector() {
    let d = deployment();
    let r = request(&d, &SET, &NONCE);
    let pre = request_preimage(&r).unwrap();
    // layout: domain ‖ set ‖ chain LE ‖ bridge ‖ 04 "POST" ‖ 0c00 "/unlock/sign" ‖ time LE ‖
    // nonce ‖ sha256(body)
    let mut want = b"HawkeyePeerReq".to_vec();
    want.extend_from_slice(&SET);
    want.extend_from_slice(&31337u64.to_le_bytes());
    want.extend_from_slice(&d.bridge.0);
    want.push(4);
    want.extend_from_slice(b"POST");
    want.extend_from_slice(&12u16.to_le_bytes());
    want.extend_from_slice(b"/unlock/sign");
    want.extend_from_slice(&1_760_000_000u64.to_le_bytes());
    want.extend_from_slice(&NONCE);
    want.extend_from_slice(&hawkeye_core::bytes::sha256(BODY));
    assert_eq!(pre, want);
    assert_eq!(pre.len(), 14 + 32 + 8 + 20 + 5 + 14 + 8 + 16 + 32);
    let msg = request_msg(&r).unwrap();
    assert_eq!(msg, sha256d(&pre));
    assert_eq!(hex::encode(msg), MSG);
}

#[test]
fn every_field_changes_the_message() {
    let d = deployment();
    let base = request_msg(&request(&d, &SET, &NONCE)).unwrap();
    let other_set = [0x12; 32];
    let other_nonce = [0xff; 16];
    let d2 = Deployment {
        chain_id: 1,
        ..deployment()
    };
    let d3 = Deployment {
        bridge: EthAddress([0x5f; 20]),
        ..deployment()
    };
    let mut variants = vec![
        request(&d, &other_set, &NONCE),
        request(&d2, &SET, &NONCE),
        request(&d3, &SET, &NONCE),
        request(&d, &SET, &other_nonce),
    ];
    let mut v = request(&d, &SET, &NONCE);
    v.method = "GET";
    variants.push(v);
    let mut v = request(&d, &SET, &NONCE);
    v.path = "/slash/sign";
    variants.push(v);
    let mut v = request(&d, &SET, &NONCE);
    v.timestamp += 1;
    variants.push(v);
    let mut v = request(&d, &SET, &NONCE);
    v.body = br#"{"hex":"01"}"#;
    variants.push(v);
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(request_msg(v).unwrap(), base, "variant {i}");
    }
}

#[test]
fn sign_verify_round_trip_and_response() {
    let key = SecretKey::from_bytes(&[7; 32]).unwrap();
    let other = SecretKey::from_bytes(&[8; 32]).unwrap();
    let d = deployment();
    let msg = request_msg(&request(&d, &SET, &NONCE)).unwrap();
    let sig = sign(&key, &msg).unwrap();
    verify(&key.public_key(), &msg, &sig).unwrap();
    assert!(verify(&other.public_key(), &msg, &sig).is_err());
    let mut bad = sig;
    bad[10] ^= 1;
    assert!(verify(&key.public_key(), &msg, &bad).is_err());
    // header encoding round trip
    assert_eq!(parse_sig(&hex::encode(sig)).unwrap(), sig);
    assert_eq!(
        parse_member(&hex::encode(key.public_key())).unwrap(),
        key.public_key()
    );
    assert_eq!(parse_nonce(&hex::encode(NONCE)).unwrap(), NONCE);
    assert_eq!(parse_time("1760000000").unwrap(), 1_760_000_000);
    // the response binds the request and the answer body
    let r1 = response_msg(&msg, b"{\"hex\":\"01\"}");
    assert_ne!(r1, response_msg(&msg, b"{\"hex\":\"02\"}"));
    assert_ne!(r1, response_msg(&[0; 32], b"{\"hex\":\"01\"}"));
    let rs = sign(&other, &r1).unwrap();
    verify(&other.public_key(), &r1, &rs).unwrap();
}

/// Plan §4.7: set `0x11…11`, ledger id `0001…0f`, count 5.
const HWM_MSG: &str = "51409b3495f2d5f7c82d969edca60e081183cf1123f13e1dfd40315d8fd2dc94";

#[test]
fn ledger_hwm_vector() {
    let ledger_id: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let msg = hwm_msg(&SET, &ledger_id, 5);
    let mut pre = b"HawkeyeLedgerHwm".to_vec();
    pre.extend_from_slice(&SET);
    pre.extend_from_slice(&ledger_id);
    pre.extend_from_slice(&5u64.to_le_bytes());
    assert_eq!(pre.len(), 16 + 32 + 16 + 8);
    assert_eq!(msg, sha256d(&pre));
    assert_eq!(hex::encode(msg), HWM_MSG);
    assert_ne!(hwm_msg(&[0x12; 32], &ledger_id, 5), msg);
    assert_ne!(hwm_msg(&SET, &[0xff; 16], 5), msg);
    assert_ne!(hwm_msg(&SET, &ledger_id, 6), msg);
    let key = SecretKey::from_bytes(&[7; 32]).unwrap();
    let sig = sign(&key, &msg).unwrap();
    verify(&key.public_key(), &msg, &sig).unwrap();
    assert!(
        verify(
            &SecretKey::from_bytes(&[8; 32]).unwrap().public_key(),
            &msg,
            &sig
        )
        .is_err()
    );
}
