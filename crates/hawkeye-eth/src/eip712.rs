//! The bridge's EIP-712 encoding (plan §4.4) and the attestor's Ethereum signature.
//!
//! Domain `{name: "WyecBridge", version: "1", chainId, verifyingContract: bridge}`; the six types
//! exactly as `WyecBridge.sol` declares them (`Mint`, `Challenge`, and the four admin acts). Signatures are 65-byte `r ‖ s ‖ v`, `v ∈ {27, 28}`,
//! low-S (OpenZeppelin's `ECDSA.recover` rejects anything else), and a `sigs[]` array is ordered by
//! strictly ascending recovered address (the contract's distinctness rule).
//!
//! **Sign once (AGENTS.md rule 7).** [`sign_digest`] is a pure function. The engine must record the
//! bytes it signed for a `lockId` (one `(amount, to)` ever), and for a `(lockId, proposalId)`
//! challenge, in the sign-once store *before* releasing them, and a retry must reuse the recorded
//! bytes, never call this again.

use alloy::primitives::{Address, B256, Bytes, Signature, U256};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct};

use crate::{Error, Result};

sol! {
    /// `Mint(bytes32 lockId,uint256 amount,address to)`
    #[derive(Debug, PartialEq, Eq)]
    struct Mint {
        bytes32 lockId;
        uint256 amount;
        address to;
    }

    /// `Challenge(bytes32 lockId,uint256 proposalId)`: a guardian's veto of one optimistic
    /// proposal (the id binds it, so a challenge never deletes a later re-proposal).
    #[derive(Debug, PartialEq, Eq)]
    struct Challenge {
        bytes32 lockId;
        uint256 proposalId;
    }

    /// `SetMintLimit(uint256 mintCap,uint256 capWindow,uint256 adminNonce)`
    #[derive(Debug, PartialEq, Eq)]
    struct SetMintLimit {
        uint256 mintCap;
        uint256 capWindow;
        uint256 adminNonce;
    }

    /// `SetGuardians(address[] guardians,uint8 threshold,uint256 adminNonce)`
    #[derive(Debug, PartialEq, Eq)]
    struct SetGuardians {
        address[] guardians;
        uint8 threshold;
        uint256 adminNonce;
    }

    /// `SetPaused(bool paused,uint256 adminNonce)`
    #[derive(Debug, PartialEq, Eq)]
    struct SetPaused {
        bool paused;
        uint256 adminNonce;
    }

    /// `SetBridge(address newBridge,uint256 adminNonce)`
    #[derive(Debug, PartialEq, Eq)]
    struct SetBridge {
        address newBridge;
        uint256 adminNonce;
    }
}

/// The EIP-712 domain of the bridge at `bridge` on `chain_id`.
pub fn domain(chain_id: u64, bridge: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some("WyecBridge".into()),
        Some("1".into()),
        Some(U256::from(chain_id)),
        Some(bridge),
        None,
    )
}

/// The domain separator (`hashStruct(EIP712Domain)`).
pub fn domain_separator(chain_id: u64, bridge: Address) -> B256 {
    domain(chain_id, bridge).separator()
}

/// The digest a guardian signs for `Mint(lockId, amount, to)`.
pub fn mint_digest(
    chain_id: u64,
    bridge: Address,
    lock_id: B256,
    amount: U256,
    to: Address,
) -> B256 {
    Mint {
        lockId: lock_id,
        amount,
        to,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// The digest a guardian signs to challenge optimistic proposal `proposal_id` of `lock_id`.
pub fn challenge_digest(chain_id: u64, bridge: Address, lock_id: B256, proposal_id: U256) -> B256 {
    Challenge {
        lockId: lock_id,
        proposalId: proposal_id,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// The digest for `setMintLimit(mintCap, capWindow, ...)` at `admin_nonce`.
pub fn set_mint_limit_digest(
    chain_id: u64,
    bridge: Address,
    mint_cap: U256,
    cap_window: U256,
    admin_nonce: U256,
) -> B256 {
    SetMintLimit {
        mintCap: mint_cap,
        capWindow: cap_window,
        adminNonce: admin_nonce,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// The digest for `setGuardians(guardians, threshold, ...)` at `admin_nonce` (order of
/// `guardians` matters: it is hashed as given).
pub fn set_guardians_digest(
    chain_id: u64,
    bridge: Address,
    guardians: &[Address],
    threshold: u8,
    admin_nonce: U256,
) -> B256 {
    SetGuardians {
        guardians: guardians.to_vec(),
        threshold,
        adminNonce: admin_nonce,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// The digest for `setPaused(paused, ...)` at `admin_nonce`.
pub fn set_paused_digest(chain_id: u64, bridge: Address, paused: bool, admin_nonce: U256) -> B256 {
    SetPaused {
        paused,
        adminNonce: admin_nonce,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// The digest for `setBridge(newBridge, ...)` at `admin_nonce`.
pub fn set_bridge_digest(
    chain_id: u64,
    bridge: Address,
    new_bridge: Address,
    admin_nonce: U256,
) -> B256 {
    SetBridge {
        newBridge: new_bridge,
        adminNonce: admin_nonce,
    }
    .eip712_signing_hash(&domain(chain_id, bridge))
}

/// Signs a 32-byte digest: 65 bytes `r ‖ s ‖ v`, `v ∈ {27, 28}`, low-S, deterministic (RFC 6979).
/// See the module note on sign-once.
pub fn sign_digest(signer: &PrivateKeySigner, digest: B256) -> Result<Bytes> {
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|e| Error::BadSignature {
            index: 0,
            reason: e.to_string(),
        })?;
    // k256 always produces low-S; normalise anyway so the contract can never see high-S from us.
    Ok(Bytes::from(sig.normalized_s().as_bytes().to_vec()))
}

/// Recovers the signer of a 65-byte signature exactly as the contract would accept it: length 65,
/// `v ∈ {27, 28}`, `s ≤ n/2`.
pub fn recover(digest: B256, sig: &[u8]) -> Result<Address> {
    recover_at(0, digest, sig)
}

fn recover_at(index: usize, digest: B256, sig: &[u8]) -> Result<Address> {
    let bad = |reason: &str| Error::BadSignature {
        index,
        reason: reason.to_string(),
    };
    if sig.len() != 65 {
        return Err(bad("not 65 bytes"));
    }
    if sig[64] != 27 && sig[64] != 28 {
        return Err(bad("v is not 27 or 28"));
    }
    let parsed = Signature::from_raw(sig).map_err(|e| bad(&e.to_string()))?;
    if parsed.normalize_s().is_some() {
        return Err(bad("high-S"));
    }
    parsed
        .recover_address_from_prehash(&digest)
        .map_err(|e| bad(&e.to_string()))
}

/// A signature with the address it recovers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBy {
    pub signer: Address,
    pub signature: Bytes,
}

/// Recovers every signature over `digest` and returns them ordered by strictly ascending signer,
/// the order `sigs[]` must have. Fails on a malformed or high-S signature or a repeated signer.
/// Whether each signer is a current guardian is the contract's check (and the caller's).
pub fn sort_signatures<S: AsRef<[u8]>>(digest: B256, sigs: &[S]) -> Result<Vec<SignedBy>> {
    let mut out = sigs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Ok(SignedBy {
                signer: recover_at(i, digest, s.as_ref())?,
                signature: Bytes::copy_from_slice(s.as_ref()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|s| s.signer);
    if let Some(w) = out.windows(2).find(|w| w[0].signer == w[1].signer) {
        return Err(Error::DuplicateSigner(w[0].signer));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};

    #[test]
    fn typehashes_match_the_contract_strings() {
        use alloy::primitives::keccak256;
        assert_eq!(
            Mint::eip712_type_hash(&Mint {
                lockId: B256::ZERO,
                amount: U256::ZERO,
                to: Address::ZERO
            }),
            keccak256("Mint(bytes32 lockId,uint256 amount,address to)")
        );
        assert_eq!(
            Challenge::eip712_encode_type(),
            "Challenge(bytes32 lockId,uint256 proposalId)"
        );
        assert_eq!(
            SetMintLimit::eip712_encode_type(),
            "SetMintLimit(uint256 mintCap,uint256 capWindow,uint256 adminNonce)"
        );
        assert_eq!(
            SetGuardians::eip712_encode_type(),
            "SetGuardians(address[] guardians,uint8 threshold,uint256 adminNonce)"
        );
        assert_eq!(
            SetPaused::eip712_encode_type(),
            "SetPaused(bool paused,uint256 adminNonce)"
        );
        assert_eq!(
            SetBridge::eip712_encode_type(),
            "SetBridge(address newBridge,uint256 adminNonce)"
        );
    }

    #[test]
    fn sign_recover_sort() {
        let keys: Vec<PrivateKeySigner> = (1u8..=3)
            .map(|i| PrivateKeySigner::from_bytes(&B256::with_last_byte(i)).unwrap())
            .collect();
        let d = mint_digest(
            31337,
            address!("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
            b256!("0x0101010101010101010101010101010101010101010101010101010101010101"),
            U256::from(1),
            Address::with_last_byte(9),
        );
        let mut sigs: Vec<Bytes> = keys.iter().map(|k| sign_digest(k, d).unwrap()).collect();
        sigs.reverse();
        let sorted = sort_signatures(d, &sigs).unwrap();
        let mut want: Vec<Address> = keys.iter().map(|k| k.address()).collect();
        want.sort();
        assert_eq!(sorted.iter().map(|s| s.signer).collect::<Vec<_>>(), want);

        // duplicate
        let dup = vec![sigs[0].clone(), sigs[0].clone()];
        assert!(matches!(
            sort_signatures(d, &dup),
            Err(Error::DuplicateSigner(_))
        ));

        // high-S: s -> n - s, parity flipped, recovers the same key in ecrecover but is rejected
        let sig = Signature::from_raw(&sigs[0]).unwrap();
        let n = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        let high = Signature::new(sig.r(), n - sig.s(), !sig.v());
        assert!(matches!(
            recover(d, &high.as_bytes()),
            Err(Error::BadSignature { .. })
        ));

        // v = 0/1 is rejected (the contract only accepts 27/28)
        let mut v01 = sigs[0].to_vec();
        v01[64] -= 27;
        assert!(matches!(recover(d, &v01), Err(Error::BadSignature { .. })));
        assert!(matches!(
            recover(d, &[0u8; 64]),
            Err(Error::BadSignature { .. })
        ));
    }
}
