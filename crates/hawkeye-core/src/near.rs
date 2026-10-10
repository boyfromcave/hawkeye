//! NEAR encodings (NEAR plan `docs/hawkeye-near-plan.md` §2): account ids, the `wyec-near`
//! deployment and its memo fields, the Borsh-serialised attestation messages and their digest,
//! burn records, and secp256k1 signatures in the form `env::ecrecover` takes.
//!
//! ```text
//! digest = SHA256( "HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖ borsh(msg) )
//! sig    = r (32) ‖ s (32) ‖ v (1),  v ∈ {0, 1},  s ≤ n/2
//! guardian id = the 64-byte uncompressed public key x ‖ y (what env::ecrecover returns)
//! ```
//!
//! Borsh is written by hand here (it is five rules: integers little-endian, `bool` one byte,
//! fixed arrays raw, `String` and `Vec` a `u32` LE length then the items, an enum a `u8` variant
//! index then the fields); the tests check every encoding against the `borsh` crate's derive,
//! which is what `near-sdk` uses.

use crate::bytes::{Hash32, sha256};
use crate::error::{Error, Result, array};
use crate::keys::{SecretKey, parse_pubkey, uncompress};
use crate::memo::Deployment;
use crate::setsig::{is_low_s, recover_compact_lenient, sign_rec};

/// The shortest valid account id.
pub const ACCOUNT_ID_MIN_LEN: usize = 2;
/// The longest valid account id.
pub const ACCOUNT_ID_MAX_LEN: usize = 64;
/// The digest's domain prefix (raw bytes, no length).
pub const DIGEST_DOMAIN: &[u8; 14] = b"HawkeyeNear-v1";
/// The prefix of the memo `chainId` preimage: `SHA256("near:" ‖ network_id)`.
pub const CHAIN_ID_PREFIX: &[u8; 5] = b"near:";
/// A guardian id: the uncompressed secp256k1 public key without the `0x04` prefix.
pub type GuardianKey = [u8; 64];

// ---------------------------------------------------------------------------------------------
// Account ids (§2.1)

/// Check `s` against NEAR's account-id rules (`near-account-id`'s `validate`): 2–64 bytes of
/// `a-z 0-9 - _ .`, where `-`, `_` and `.` separate parts and so never lead, trail or touch.
/// Implicit (64 lowercase hex) and EVM-implicit (`0x` + 40 lowercase hex) ids pass these rules
/// as they stand.
pub fn validate_account_id(s: &str) -> Result<()> {
    if s.len() < ACCOUNT_ID_MIN_LEN {
        return Err(Error::Near("account id shorter than 2"));
    }
    if s.len() > ACCOUNT_ID_MAX_LEN {
        return Err(Error::Near("account id longer than 64"));
    }
    // As if a separator came before the first byte: a leading separator is redundant.
    let mut last_was_separator = true;
    for b in s.bytes() {
        let separator = match b {
            b'a'..=b'z' | b'0'..=b'9' => false,
            b'-' | b'_' | b'.' => true,
            _ => {
                return Err(Error::Near(
                    "account id has a character outside a-z 0-9 - _ .",
                ));
            }
        };
        if separator && last_was_separator {
            return Err(Error::Near("account id has a leading or doubled separator"));
        }
        last_was_separator = separator;
    }
    if last_was_separator {
        return Err(Error::Near("account id has a trailing separator"));
    }
    Ok(())
}

/// The kind of a valid account id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// A named account (`alice.near`, `wyec.testnet`, a top-level name).
    Named,
    /// An implicit account: 64 lowercase hex digits (an ed25519 public key).
    NearImplicit,
    /// An EVM-style implicit account: `0x` and 40 lowercase hex digits.
    EthImplicit,
}

fn is_lower_hex(b: &[u8]) -> bool {
    b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// A NEAR account id that satisfies [`validate_account_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(String);

impl AccountId {
    /// Parse and validate.
    pub fn parse(s: &str) -> Result<Self> {
        validate_account_id(s)?;
        Ok(Self(s.to_owned()))
    }

    /// Validate raw bytes (an `OP_RETURN` field): UTF-8 and NEAR's rules.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Self::parse(core::str::from_utf8(b).map_err(|_| Error::Near("account id is not UTF-8"))?)
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id's bytes (ASCII).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Named, implicit or EVM-implicit.
    pub fn kind(&self) -> AccountKind {
        let b = self.as_bytes();
        if b.len() == 64 && is_lower_hex(b) {
            AccountKind::NearImplicit
        } else if b.len() == 42 && b.starts_with(b"0x") && is_lower_hex(&b[2..]) {
            AccountKind::EthImplicit
        } else {
            AccountKind::Named
        }
    }

    /// Borsh: `u32` LE length ‖ bytes (what `near-sdk`'s `AccountId` serialises to).
    pub fn borsh(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.0.len());
        put_str(&mut out, &self.0);
        out
    }
}

impl core::fmt::Display for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for AccountId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<String> for AccountId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        validate_account_id(&s)?;
        Ok(Self(s))
    }
}

impl AsRef<str> for AccountId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------------------------
// Borsh (the subset §2.3 and §2.4 use)

fn put_str(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).expect("a string under 4 GiB");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `borsh(s)` for a `String`: `u32` LE byte length ‖ UTF-8 bytes.
pub fn borsh_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    put_str(&mut out, s);
    out
}

// ---------------------------------------------------------------------------------------------
// The deployment (§2.2, §2.3)

/// `chainId` of the `HKN1` memo: the first 8 bytes of `SHA256("near:" ‖ network_id)` read as
/// a `u64` little-endian.
pub fn chain_id(network_id: &str) -> u64 {
    let mut pre = Vec::with_capacity(CHAIN_ID_PREFIX.len() + network_id.len());
    pre.extend_from_slice(CHAIN_ID_PREFIX);
    pre.extend_from_slice(network_id.as_bytes());
    u64::from_le_bytes(sha256(&pre)[..8].try_into().expect("8 bytes"))
}

/// `bridge` of the `HKN1` memo: the first 20 bytes of `SHA256(contract account id)`.
pub fn bridge_id(contract_id: &AccountId) -> [u8; 20] {
    sha256(contract_id.as_bytes())[..20]
        .try_into()
        .expect("20 bytes")
}

/// One `wyec-near` deployment: the NEAR network and the contract account. It is the digest's
/// domain (the EIP-712 domain's job on Ethereum) and, hashed, the memo's deployment fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain {
    /// The NEAR network id (`mainnet`, `testnet`, `sandbox`, `localnet`, …).
    pub network_id: String,
    /// The `wyec-near` contract's account.
    pub contract_id: AccountId,
}

impl Domain {
    /// A domain; the network id must be non-empty.
    pub fn new(network_id: &str, contract_id: AccountId) -> Result<Self> {
        if network_id.is_empty() {
            return Err(Error::Near("empty network id"));
        }
        Ok(Self {
            network_id: network_id.to_owned(),
            contract_id,
        })
    }

    /// The memo's `(chainId, bridge)` for this deployment. The 20 `bridge` bytes are a hash of
    /// the contract id carried in the memo's address-sized field, not an Ethereum address.
    pub fn deployment(&self) -> Deployment {
        Deployment {
            chain_id: chain_id(&self.network_id),
            bridge: crate::eth::EthAddress(bridge_id(&self.contract_id)),
        }
    }

    /// The bytes hashed for `msg`: `"HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id)
    /// ‖ borsh(msg)`.
    pub fn preimage(&self, msg: &BridgeMessage) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(DIGEST_DOMAIN);
        put_str(&mut out, &self.network_id);
        put_str(&mut out, self.contract_id.as_str());
        out.extend_from_slice(&msg.borsh());
        out
    }

    /// The 32-byte digest guardians sign for `msg` (NEAR plan §2.3, N-6).
    pub fn digest(&self, msg: &BridgeMessage) -> Hash32 {
        sha256(&self.preimage(msg))
    }
}

// ---------------------------------------------------------------------------------------------
// Messages (§2.3)

/// What guardians sign, exactly the contract's Borsh enum (variant index = tag).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BridgeMessage {
    /// Tag 0: mint `amount` zatoshi of wYEC to `receiver_id` for lock `lock_id` (both mint
    /// paths: threshold `mint` and `propose_mint`).
    Mint {
        /// `SHA256(txid ‖ vout)` (N-4).
        lock_id: Hash32,
        /// zatoshi (`decimals = 8`).
        amount: u128,
        /// The receiver (Borsh `String`).
        receiver_id: AccountId,
    },
    /// Tag 1: a guardian's veto of proposal `proposal_id` for `lock_id`.
    Challenge {
        /// The proposal's lock.
        lock_id: Hash32,
        /// The contract's proposal id.
        proposal_id: u64,
    },
    /// Tag 2: replace the guardian set.
    SetGuardians {
        /// The new guardians' 64-byte keys, in the order given to the contract.
        guardians: Vec<GuardianKey>,
        /// The new threshold.
        threshold: u8,
        /// The contract's admin nonce.
        admin_nonce: u64,
    },
    /// Tag 3: pause or unpause.
    SetPaused {
        /// Paused or not.
        paused: bool,
        /// The contract's admin nonce.
        admin_nonce: u64,
    },
    /// Tag 4: the mint rate limit.
    SetMintLimit {
        /// The most zatoshi minted per window.
        mint_cap: u128,
        /// The window in seconds.
        cap_window_sec: u64,
        /// The contract's admin nonce.
        admin_nonce: u64,
    },
}

impl BridgeMessage {
    /// The Borsh variant index.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Mint { .. } => 0,
            Self::Challenge { .. } => 1,
            Self::SetGuardians { .. } => 2,
            Self::SetPaused { .. } => 3,
            Self::SetMintLimit { .. } => 4,
        }
    }

    /// The variant's name (as in the contract and the vector file).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mint { .. } => "Mint",
            Self::Challenge { .. } => "Challenge",
            Self::SetGuardians { .. } => "SetGuardians",
            Self::SetPaused { .. } => "SetPaused",
            Self::SetMintLimit { .. } => "SetMintLimit",
        }
    }

    /// `borsh(self)`.
    pub fn borsh(&self) -> Vec<u8> {
        let mut out = vec![self.tag()];
        match self {
            Self::Mint {
                lock_id,
                amount,
                receiver_id,
            } => {
                out.extend_from_slice(lock_id);
                out.extend_from_slice(&amount.to_le_bytes());
                put_str(&mut out, receiver_id.as_str());
            }
            Self::Challenge {
                lock_id,
                proposal_id,
            } => {
                out.extend_from_slice(lock_id);
                out.extend_from_slice(&proposal_id.to_le_bytes());
            }
            Self::SetGuardians {
                guardians,
                threshold,
                admin_nonce,
            } => {
                let n = u32::try_from(guardians.len()).expect("under 2^32 guardians");
                out.extend_from_slice(&n.to_le_bytes());
                for g in guardians {
                    out.extend_from_slice(g);
                }
                out.push(*threshold);
                out.extend_from_slice(&admin_nonce.to_le_bytes());
            }
            Self::SetPaused {
                paused,
                admin_nonce,
            } => {
                out.push(u8::from(*paused));
                out.extend_from_slice(&admin_nonce.to_le_bytes());
            }
            Self::SetMintLimit {
                mint_cap,
                cap_window_sec,
                admin_nonce,
            } => {
                out.extend_from_slice(&mint_cap.to_le_bytes());
                out.extend_from_slice(&cap_window_sec.to_le_bytes());
                out.extend_from_slice(&admin_nonce.to_le_bytes());
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Burn records (§2.4)

/// One burn as the contract records it (`get_burns`); the `HKN1` burn-release memo's `data` is
/// [`BurnRecord::hash`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BurnRecord {
    /// The burn nonce (the memo's `ref`).
    pub nonce: u64,
    /// The burner's account.
    pub from: AccountId,
    /// zatoshi burned.
    pub amount: u128,
    /// The raw `ycashRecipient` (plan §4.2), kept undecoded: an orphaned burn still hashes.
    pub ycash_recipient: [u8; 32],
    /// The NEAR block height of the burn.
    pub block_height: u64,
    /// The block timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

impl BurnRecord {
    /// `borsh(self)`, fields in declaration order.
    pub fn borsh(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 + self.from.as_str().len() + 16 + 32 + 16);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        put_str(&mut out, self.from.as_str());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.ycash_recipient);
        out.extend_from_slice(&self.block_height.to_le_bytes());
        out.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        out
    }

    /// `SHA256(borsh(self))`: the burn-release memo's `data`.
    pub fn hash(&self) -> Hash32 {
        sha256(&self.borsh())
    }
}

// ---------------------------------------------------------------------------------------------
// Keys and signatures (N-6)

/// The guardian id of a SEC1 public key (33-byte compressed — a Ycash member key — or 65-byte
/// uncompressed): `x ‖ y`.
pub fn guardian_key(pubkey: &[u8]) -> Result<GuardianKey> {
    let full = uncompress(&parse_pubkey(pubkey)?);
    Ok(full[1..].try_into().expect("64 bytes"))
}

/// The guardian id of a secret key's public key.
pub fn guardian_key_of(key: &SecretKey) -> GuardianKey {
    let full = uncompress(key.signing_key().verifying_key());
    full[1..].try_into().expect("64 bytes")
}

/// Sign a 32-byte digest for `env::ecrecover(digest, sig[..64], sig[64], true)`: `r ‖ s ‖ v`,
/// RFC 6979, low S, `v` = the y-parity (0 or 1).
pub fn sign_digest(key: &SecretKey, digest: &Hash32) -> Result<[u8; 65]> {
    let (rs, recid) = sign_rec(key, digest)?;
    if recid.is_x_reduced() {
        // R.x ≥ n: probability ~2^-128; v would be 2 or 3, which the plan does not allow.
        return Err(Error::Signature("x-reduced recovery id"));
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&rs);
    out[64] = u8::from(recid.is_y_odd());
    Ok(out)
}

/// The guardian id a 65-byte `r ‖ s ‖ v` signature over `digest` recovers to, under
/// `env::ecrecover` with `malleability_flag = true` and the plan's `v ∈ {0, 1}`: 0 < r, s < n,
/// s ≤ n/2.
pub fn recover_guardian(digest: &Hash32, sig: &[u8]) -> Result<GuardianKey> {
    let sig: [u8; 65] = array("signature", sig)?;
    let v = sig[64];
    if v > 1 {
        return Err(Error::Near("signature v not 0 or 1"));
    }
    let s: [u8; 32] = sig[32..64].try_into().expect("32");
    if !is_low_s(&s) {
        return Err(Error::Signature("high S"));
    }
    // Header 27 + v: recovery id v, uncompressed result.
    let mut compact = [0u8; 65];
    compact[0] = 27 + v;
    compact[1..].copy_from_slice(&sig[..64]);
    let full = recover_compact_lenient(&compact, digest)?;
    Ok(full[1..].try_into().expect("64 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(s: &str) -> AccountId {
        AccountId::parse(s).unwrap()
    }

    #[test]
    fn account_ids() {
        for ok in [
            "aa",
            "a-a",
            "b-o_w_e-n",
            "illia.cheapaccounts.near",
            "10-4.8-2",
            "near.a",
            &"0".repeat(64),
        ] {
            assert!(validate_account_id(ok).is_ok(), "{ok}");
        }
        let bad = |s: &str| validate_account_id(s).unwrap_err();
        assert_eq!(bad("a"), Error::Near("account id shorter than 2"));
        assert_eq!(bad(""), Error::Near("account id shorter than 2"));
        assert_eq!(
            bad(&"a".repeat(65)),
            Error::Near("account id longer than 64")
        );
        assert!(matches!(bad("nEar"), Error::Near(r) if r.contains("character")));
        assert!(matches!(bad("неар"), Error::Near(r) if r.contains("character")));
        assert!(matches!(bad("-near"), Error::Near(r) if r.contains("leading")));
        assert!(matches!(bad("a..near"), Error::Near(r) if r.contains("doubled")));
        assert!(matches!(bad("near."), Error::Near(r) if r.contains("trailing")));
        assert!(AccountId::from_bytes(&[0xff, 0xfe]).is_err());
        assert!(AccountId::try_from("A".to_string()).is_err());

        let a: AccountId = "alice.near".parse().unwrap();
        assert_eq!(a.to_string(), "alice.near");
        assert_eq!(a.as_ref(), "alice.near");
        assert_eq!(a.kind(), AccountKind::Named);
        assert_eq!(
            AccountId::try_from("bob.near".to_string())
                .unwrap()
                .as_str(),
            "bob.near"
        );
        assert_eq!(acct(&"ab".repeat(32)).kind(), AccountKind::NearImplicit);
        assert_eq!(
            acct(&format!("0x{}", "c".repeat(40))).kind(),
            AccountKind::EthImplicit
        );
        // 64 characters but not hex; 42 characters with 0x but not hex
        assert_eq!(acct(&"g".repeat(64)).kind(), AccountKind::Named);
        assert_eq!(
            acct(&format!("0x{}", "g".repeat(40))).kind(),
            AccountKind::Named
        );
        assert_eq!(acct(&"a".repeat(63)).kind(), AccountKind::Named);
        assert_eq!(a.borsh(), [&[10, 0, 0, 0][..], b"alice.near"].concat());
        assert_eq!(borsh_string(""), vec![0, 0, 0, 0]);
    }

    #[test]
    fn domain_and_deployment() {
        assert!(Domain::new("", acct("wyec.near")).is_err());
        let d = Domain::new("mainnet", acct("wyec.near")).unwrap();
        let dep = d.deployment();
        assert_eq!(dep.chain_id.to_le_bytes(), sha256(b"near:mainnet")[..8]);
        assert_eq!(dep.bridge.0, sha256(b"wyec.near")[..20]);
        assert_ne!(
            Domain::new("testnet", acct("wyec.near"))
                .unwrap()
                .deployment(),
            dep
        );
        let msg = BridgeMessage::SetPaused {
            paused: true,
            admin_nonce: 1,
        };
        let pre = d.preimage(&msg);
        assert_eq!(
            pre,
            [
                &b"HawkeyeNear-v1"[..],
                &[7, 0, 0, 0],
                b"mainnet",
                &[9, 0, 0, 0],
                b"wyec.near",
                &[3, 1],
                &1u64.to_le_bytes(),
            ]
            .concat()
        );
        assert_eq!(d.digest(&msg), sha256(&pre));
    }

    #[test]
    fn message_layouts() {
        let m = BridgeMessage::Mint {
            lock_id: [0x11; 32],
            amount: 250_000_000,
            receiver_id: acct("bob.near"),
        };
        let b = m.borsh();
        assert_eq!(b[0], 0);
        assert_eq!(&b[1..33], &[0x11; 32]);
        assert_eq!(&b[33..49], &250_000_000u128.to_le_bytes());
        assert_eq!(&b[49..53], &[8, 0, 0, 0]);
        assert_eq!(&b[53..], b"bob.near");
        let c = BridgeMessage::Challenge {
            lock_id: [0x22; 32],
            proposal_id: 0x0102,
        };
        assert_eq!(c.borsh().len(), 1 + 32 + 8);
        let g = BridgeMessage::SetGuardians {
            guardians: vec![[1; 64], [2; 64]],
            threshold: 2,
            admin_nonce: 3,
        };
        let gb = g.borsh();
        assert_eq!(&gb[..5], &[2, 2, 0, 0, 0]);
        assert_eq!(gb.len(), 1 + 4 + 128 + 1 + 8);
        let p = BridgeMessage::SetPaused {
            paused: false,
            admin_nonce: 0,
        };
        assert_eq!(p.borsh(), vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let l = BridgeMessage::SetMintLimit {
            mint_cap: u128::MAX,
            cap_window_sec: 86_400,
            admin_nonce: 9,
        };
        assert_eq!(l.borsh().len(), 1 + 16 + 8 + 8);
        let names: Vec<(u8, &str)> = [m, c, g, p, l]
            .iter()
            .map(|m| (m.tag(), m.name()))
            .collect();
        assert_eq!(
            names,
            vec![
                (0, "Mint"),
                (1, "Challenge"),
                (2, "SetGuardians"),
                (3, "SetPaused"),
                (4, "SetMintLimit")
            ]
        );
    }

    #[test]
    fn burn_record() {
        let r = BurnRecord {
            nonce: 7,
            from: acct("alice.near"),
            amount: 1,
            ycash_recipient: [0xab; 32],
            block_height: 100,
            timestamp_ns: 5,
        };
        let b = r.borsh();
        assert_eq!(b.len(), 8 + 4 + 10 + 16 + 32 + 8 + 8);
        assert_eq!(&b[..8], &7u64.to_le_bytes());
        assert_eq!(r.hash(), sha256(&b));
    }

    #[test]
    fn sign_and_recover() {
        let digest = sha256(b"near digest");
        for i in 1u8..=8 {
            let k = SecretKey::from_bytes(&[i; 32]).unwrap();
            let g = guardian_key_of(&k);
            assert_eq!(guardian_key(&k.public_key()).unwrap(), g);
            let mut full = vec![4u8];
            full.extend_from_slice(&g);
            assert_eq!(guardian_key(&full).unwrap(), g);
            let sig = sign_digest(&k, &digest).unwrap();
            assert!(sig[64] <= 1);
            assert_eq!(recover_guardian(&digest, &sig).unwrap(), g);
            assert_ne!(recover_guardian(&sha256(b"other"), &sig).ok(), Some(g));
        }
        let k = SecretKey::from_bytes(&[1; 32]).unwrap();
        let sig = sign_digest(&k, &digest).unwrap();
        let mut v27 = sig;
        v27[64] += 27;
        assert_eq!(
            recover_guardian(&digest, &v27),
            Err(Error::Near("signature v not 0 or 1"))
        );
        let mut high = sig;
        high[32] = 0xff;
        assert_eq!(
            recover_guardian(&digest, &high),
            Err(Error::Signature("high S"))
        );
        let mut zero_r = sig;
        zero_r[..32].copy_from_slice(&[0; 32]);
        assert!(recover_guardian(&digest, &zero_r).is_err());
        assert!(recover_guardian(&digest, &sig[..64]).is_err());
        assert!(guardian_key(&[2; 32]).is_err());
    }
}
