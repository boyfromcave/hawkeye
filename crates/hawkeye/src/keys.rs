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

/// `/dev/urandom` as the RNG the keystore encryption takes (no new dependency: the traits are
/// `rand_core` 0.6's, re-exported by `k256` through alloy).
struct Urandom(std::fs::File);

impl alloy::signers::k256::elliptic_curve::rand_core::RngCore for Urandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use std::io::Read;
        self.0
            .read_exact(dest)
            .expect("reading /dev/urandom never fails on a working system");
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), alloy::signers::k256::elliptic_curve::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl alloy::signers::k256::elliptic_curve::rand_core::CryptoRng for Urandom {}

/// Write `key` as an Ethereum keystore v3 (scrypt) at `out`, encrypted with `password`; the
/// file is created mode `0600` before anything is written (remedial report 05/L-2) and must
/// not exist.
pub fn encrypt_keystore(key: &SecretKey, out: &std::path::Path, password: &str) -> Result<()> {
    anyhow::ensure!(!password.is_empty(), "an empty keystore password");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(out)
            .map_err(|e| anyhow!("{}: {e} (it must not exist)", out.display()))?;
    }
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let name = out
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{}: not a file name", out.display()))?;
    let mut rng = Urandom(std::fs::File::open("/dev/urandom")?);
    PrivateKeySigner::encrypt_keystore(dir, &mut rng, key.to_bytes(), password, Some(name))
        .map_err(|e| anyhow!("keystore: {e}"))?;
    Ok(())
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

    /// `hawkeye keys encrypt`: a keystore that decrypts to the key, created `0600`, never over
    /// an existing file.
    #[test]
    fn keystore_round_trip_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("member.json");
        let k = SecretKey::from_bytes(&[9; 32]).unwrap();
        encrypt_keystore(&k, &p, "pw").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let back = PrivateKeySigner::decrypt_keystore(&p, "pw").unwrap();
        let bytes: [u8; 32] = back.credential().to_bytes().into();
        assert_eq!(bytes, k.to_bytes());
        assert!(encrypt_keystore(&k, &p, "pw").is_err(), "never overwrites");
    }
}
