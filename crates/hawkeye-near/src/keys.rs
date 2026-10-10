//! The relayer's NEAR key (NEAR plan §0 item 4): an ed25519 access key of the operator's own
//! NEAR account, which pays gas and storage deposits and never attests.
//!
//! The file is the standard NEAR credentials JSON written by `near-cli`, `near-cli-rs` and
//! `near-workspaces`:
//!
//! ```json
//! {"account_id": "hawkeye1.testnet",
//!  "public_key": "ed25519:<base58 of 32 bytes>",
//!  "private_key": "ed25519:<base58 of 64 bytes: seed ‖ public key>"}
//! ```
//!
//! `secret_key` is accepted for `private_key` (near-workspaces' name), and a 32-byte seed for
//! the 64-byte form. The public key, when given, must be the secret's.

use std::path::Path;

use ed25519_dalek::SigningKey;
use hawkeye_core::AccountId;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const PREFIX: &str = "ed25519:";

/// A relayer key: the account and its ed25519 signing key.
#[derive(Clone)]
pub struct KeyFile {
    /// The account the key belongs to.
    pub account_id: AccountId,
    key: SigningKey,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("account_id", &self.account_id)
            .field("public_key", &self.public_key_text())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Serialize)]
struct Json {
    account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, alias = "secret_key", skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

/// Decode `ed25519:<base58>`.
pub fn decode_key_text(s: &str) -> Result<Vec<u8>> {
    let b58 = s
        .strip_prefix(PREFIX)
        .ok_or_else(|| Error::Key(format!("{s:.12}…: not an ed25519: key")))?;
    bs58::decode(b58)
        .into_vec()
        .map_err(|e| Error::Key(format!("base58: {e}")))
}

/// `ed25519:<base58>` of `bytes`.
pub fn key_text(bytes: &[u8]) -> String {
    format!("{PREFIX}{}", bs58::encode(bytes).into_string())
}

impl KeyFile {
    /// A key for `account_id` from a 32-byte ed25519 seed.
    pub fn from_seed(account_id: AccountId, seed: &[u8; 32]) -> Self {
        Self {
            account_id,
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Parse the credentials JSON.
    pub fn from_json(text: &str) -> Result<Self> {
        let j: Json =
            serde_json::from_str(text).map_err(|e| Error::Key(format!("credentials JSON: {e}")))?;
        let account_id = AccountId::parse(&j.account_id)
            .map_err(|e| Error::Key(format!("account_id {:?}: {e}", j.account_id)))?;
        let secret = j
            .private_key
            .ok_or_else(|| Error::Key("no private_key (or secret_key)".into()))?;
        let raw = decode_key_text(&secret)?;
        let seed: [u8; 32] = match raw.len() {
            32 | 64 => raw[..32].try_into().expect("32"),
            n => return Err(Error::Key(format!("private key is {n} bytes, not 64"))),
        };
        let key = SigningKey::from_bytes(&seed);
        if raw.len() == 64 && raw[32..] != key.verifying_key().to_bytes() {
            return Err(Error::Key(
                "private key: its second half is not its public key".into(),
            ));
        }
        if let Some(pk) = j.public_key
            && decode_key_text(&pk)? != key.verifying_key().to_bytes()
        {
            return Err(Error::Key("public_key is not the private key's".into()));
        }
        Ok(Self { account_id, key })
    }

    /// Read the credentials file at `path`.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
        Self::from_json(&text).map_err(|e| Error::Key(format!("{}: {e}", path.display())))
    }

    /// The credentials JSON (`account_id`, `public_key`, `private_key` as 64 bytes).
    pub fn to_json(&self) -> String {
        let mut full = self.key.to_bytes().to_vec();
        full.extend_from_slice(&self.public_key());
        serde_json::to_string(&Json {
            account_id: self.account_id.to_string(),
            public_key: Some(self.public_key_text()),
            private_key: Some(key_text(&full)),
        })
        .expect("JSON")
    }

    /// The ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// `ed25519:<base58>` of the public key (RPC `view_access_key` takes this form).
    pub fn public_key_text(&self) -> String {
        key_text(&self.public_key())
    }

    /// The signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip() {
        let k = KeyFile::from_seed(AccountId::parse("hawkeye1.test.near").unwrap(), &[5; 32]);
        let j = k.to_json();
        let back = KeyFile::from_json(&j).unwrap();
        assert_eq!(back.public_key(), k.public_key());
        assert_eq!(back.account_id, k.account_id);
        // near-workspaces' `secret_key`, and a bare 32-byte seed without a public key
        let alt = format!(
            r#"{{"account_id":"a.near","secret_key":"{}"}}"#,
            key_text(&[5; 32])
        );
        assert_eq!(
            KeyFile::from_json(&alt).unwrap().public_key(),
            k.public_key()
        );
        // a public key that is not the secret's, a bad prefix, a bad account
        let wrong = j.replace(&k.public_key_text(), &key_text(&[1; 32]));
        assert!(KeyFile::from_json(&wrong).is_err());
        assert!(KeyFile::from_json(&j.replace("ed25519:", "secp256k1:")).is_err());
        assert!(KeyFile::from_json(&j.replace("hawkeye1.test.near", "Bad")).is_err());
        assert!(KeyFile::from_json(r#"{"account_id":"a.near"}"#).is_err());
        // the Debug form never prints the secret
        assert!(!format!("{k:?}").contains(&key_text(&[5; 32])));
    }

    /// RFC 8032 test 1: the seed 9d61… has public key d75a….
    #[test]
    fn rfc8032_public_key() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let k = KeyFile::from_seed(AccountId::parse("a.near").unwrap(), &seed);
        assert_eq!(
            hex::encode(k.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }
}
