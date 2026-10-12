//! The member key on every chain (plan §3.5, HK-7): its Ycash form (compressed key, WIF for
//! `importprivkey`), its Ethereum form (guardian address, local signer) and its NEAR guardian
//! form (the 64-byte uncompressed key `wyec-near` recovers, NEAR plan §2.3).

use anyhow::{Result, anyhow};
use hawkeye_core::SecretKey;
use hawkeye_core::address::{Network, base58check_encode};
use hawkeye_eth::PrivateKeySigner;
use serde::Serialize;

/// What `hawkeye keys derive` and `hawkeye enroll` print.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeyInfo {
    /// The 33-byte compressed member key, hex.
    pub memberkey: String,
    /// The Ethereum guardian address (EIP-55).
    pub eth_address: String,
    /// The NEAR guardian key: 64 bytes `x ‖ y` as hex, no prefix (what `wyec-near`'s `new` and
    /// `set_guardians` take).
    pub near_guardian: String,
}

/// The key's two public forms.
pub fn key_info(key: &SecretKey) -> KeyInfo {
    KeyInfo {
        memberkey: hex::encode(key.public_key()),
        eth_address: key.eth_address().to_checksum(),
        near_guardian: hex::encode(hawkeye_core::near::guardian_key_of(key)),
    }
}

/// The compressed-key WIF of `key` for the Ycash `network` (secret-key prefix `0x80` mainnet,
/// `0xEF` testnet/regtest: ycash-dd `src/chainparams.cpp:159,424,630`).
pub fn wif(key: &SecretKey, network: Network) -> String {
    let prefix = match network {
        Network::Mainnet => 0x80,
        Network::Testnet | Network::Regtest => 0xef,
    };
    let mut data = vec![prefix];
    data.extend_from_slice(&key.to_bytes());
    data.push(0x01);
    base58check_encode(&data)
}

/// The member key as an alloy signer (Ethereum gas and submissions).
pub fn eth_signer(key: &SecretKey) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_slice(&key.to_bytes()).map_err(|e| anyhow!("eth signer: {e}"))
}

/// A key from 64 hex digits (optionally `0x`-prefixed).
pub fn parse_secret(hex32: &str) -> Result<SecretKey> {
    SecretKey::from_hex(hex32.trim().trim_start_matches("0x")).map_err(|e| anyhow!("secret: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_and_wif() {
        // secp256k1 generator: secret 1
        let mut s = [0u8; 32];
        s[31] = 1;
        let k = SecretKey::from_bytes(&s).unwrap();
        let i = key_info(&k);
        assert_eq!(
            i.memberkey,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(i.eth_address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        // Bitcoin's well-known compressed WIF of secret 1 (same 0x80 prefix).
        assert_eq!(
            wif(&k, Network::Mainnet),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );
        assert_eq!(
            eth_signer(&k).unwrap().address().to_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        assert!(parse_secret(&format!("0x{}", hex::encode(s))).is_ok());
    }
}
