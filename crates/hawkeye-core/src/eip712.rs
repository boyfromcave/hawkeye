//! EIP-712 digests exactly as `WyecBridge.sol` (wyec @ `d2e382b`) builds them (plan §4.4):
//! domain `{name: "WyecBridge", version: "1", chainId, verifyingContract}` and the four typed
//! messages `Mint`, `SetGuardians`, `SetPaused`, `SetBridge`.

use crate::bytes::{Hash32, keccak256};
use crate::eth::EthAddress;

/// The contract's EIP-712 name.
pub const DOMAIN_NAME: &str = "WyecBridge";
/// The contract's EIP-712 version.
pub const DOMAIN_VERSION: &str = "1";

/// The EIP-712 domain type string (OpenZeppelin `EIP712`).
pub const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// `Mint`'s type string.
pub const MINT_TYPE: &str = "Mint(bytes32 lockId,uint256 amount,address to)";
/// `SetGuardians`' type string.
pub const SET_GUARDIANS_TYPE: &str =
    "SetGuardians(address[] guardians,uint8 threshold,uint256 adminNonce)";
/// `SetPaused`' type string.
pub const SET_PAUSED_TYPE: &str = "SetPaused(bool paused,uint256 adminNonce)";
/// `SetBridge`' type string.
pub const SET_BRIDGE_TYPE: &str = "SetBridge(address newBridge,uint256 adminNonce)";

/// A uint as its 32-byte ABI word.
pub fn uint_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn encode(words: &[[u8; 32]]) -> Hash32 {
    let mut buf = Vec::with_capacity(32 * words.len());
    for w in words {
        buf.extend_from_slice(w);
    }
    keccak256(&buf)
}

/// One bridge deployment's EIP-712 domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Domain {
    /// The Ethereum chain id.
    pub chain_id: u64,
    /// The `WyecBridge` address.
    pub verifying_contract: EthAddress,
}

impl Domain {
    /// A domain for `bridge` on `chain_id`.
    pub fn new(chain_id: u64, verifying_contract: EthAddress) -> Self {
        Self {
            chain_id,
            verifying_contract,
        }
    }

    /// `_domainSeparatorV4()`.
    pub fn separator(&self) -> Hash32 {
        encode(&[
            keccak256(DOMAIN_TYPE.as_bytes()),
            keccak256(DOMAIN_NAME.as_bytes()),
            keccak256(DOMAIN_VERSION.as_bytes()),
            uint_word(u128::from(self.chain_id)),
            self.verifying_contract.to_word(),
        ])
    }

    /// `_hashTypedDataV4(structHash)`: `keccak256(0x1901 ‖ separator ‖ structHash)`.
    pub fn digest(&self, struct_hash: &Hash32) -> Hash32 {
        let mut buf = Vec::with_capacity(66);
        buf.extend_from_slice(&[0x19, 0x01]);
        buf.extend_from_slice(&self.separator());
        buf.extend_from_slice(struct_hash);
        keccak256(&buf)
    }

    /// The digest guardians sign for `mint(lockId, amount, to, sigs)`.
    pub fn mint_digest(&self, lock_id: &Hash32, amount: u64, to: &EthAddress) -> Hash32 {
        self.digest(&mint_struct_hash(lock_id, amount, to))
    }

    /// The digest for `setGuardians(guardians, threshold, sigs)` at `admin_nonce`.
    pub fn set_guardians_digest(
        &self,
        guardians: &[EthAddress],
        threshold: u8,
        admin_nonce: u64,
    ) -> Hash32 {
        self.digest(&set_guardians_struct_hash(
            guardians,
            threshold,
            admin_nonce,
        ))
    }

    /// The digest for `setPaused(paused, sigs)` at `admin_nonce`.
    pub fn set_paused_digest(&self, paused: bool, admin_nonce: u64) -> Hash32 {
        self.digest(&set_paused_struct_hash(paused, admin_nonce))
    }

    /// The digest for `setBridge(newBridge, sigs)` at `admin_nonce`.
    pub fn set_bridge_digest(&self, new_bridge: &EthAddress, admin_nonce: u64) -> Hash32 {
        self.digest(&set_bridge_struct_hash(new_bridge, admin_nonce))
    }
}

/// `keccak256(abi.encode(MINT_TYPEHASH, lockId, amount, to))`.
pub fn mint_struct_hash(lock_id: &Hash32, amount: u64, to: &EthAddress) -> Hash32 {
    encode(&[
        keccak256(MINT_TYPE.as_bytes()),
        *lock_id,
        uint_word(u128::from(amount)),
        to.to_word(),
    ])
}

/// `keccak256(abi.encode(SET_GUARDIANS_TYPEHASH, keccak256(abi.encodePacked(guardians)),
/// threshold, adminNonce))`. `abi.encodePacked` pads each array element to 32 bytes.
pub fn set_guardians_struct_hash(
    guardians: &[EthAddress],
    threshold: u8,
    admin_nonce: u64,
) -> Hash32 {
    let words: Vec<[u8; 32]> = guardians.iter().map(EthAddress::to_word).collect();
    encode(&[
        keccak256(SET_GUARDIANS_TYPE.as_bytes()),
        encode(&words),
        uint_word(u128::from(threshold)),
        uint_word(u128::from(admin_nonce)),
    ])
}

/// `keccak256(abi.encode(SET_PAUSED_TYPEHASH, paused, adminNonce))`.
pub fn set_paused_struct_hash(paused: bool, admin_nonce: u64) -> Hash32 {
    encode(&[
        keccak256(SET_PAUSED_TYPE.as_bytes()),
        uint_word(u128::from(paused)),
        uint_word(u128::from(admin_nonce)),
    ])
}

/// `keccak256(abi.encode(SET_BRIDGE_TYPEHASH, newBridge, adminNonce))`.
pub fn set_bridge_struct_hash(new_bridge: &EthAddress, admin_nonce: u64) -> Hash32 {
    encode(&[
        keccak256(SET_BRIDGE_TYPE.as_bytes()),
        new_bridge.to_word(),
        uint_word(u128::from(admin_nonce)),
    ])
}
