// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Hawkeye's own statement of the wYEC EIP-712 encoding (plan §4.4), written independently of
/// WyecBridge.sol so the tests prove the contract agrees with it rather than with itself.
library WyecEip712 {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant MINT_TYPEHASH = keccak256("Mint(bytes32 lockId,uint256 amount,address to)");
    bytes32 internal constant SET_GUARDIANS_TYPEHASH =
        keccak256("SetGuardians(address[] guardians,uint8 threshold,uint256 adminNonce)");
    bytes32 internal constant SET_PAUSED_TYPEHASH = keccak256("SetPaused(bool paused,uint256 adminNonce)");
    bytes32 internal constant SET_BRIDGE_TYPEHASH =
        keccak256("SetBridge(address newBridge,uint256 adminNonce)");

    function domainSeparator(uint256 chainId, address bridge) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("WyecBridge"), keccak256("1"), chainId, bridge));
    }

    function digest(bytes32 domain, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function mintStruct(bytes32 lockId, uint256 amount, address to) internal pure returns (bytes32) {
        return keccak256(abi.encode(MINT_TYPEHASH, lockId, amount, to));
    }

    function setGuardiansStruct(address[] memory guardians, uint8 threshold, uint256 adminNonce)
        internal
        pure
        returns (bytes32)
    {
        // address[] is encoded as keccak256 of the concatenated 32-byte-padded elements.
        return keccak256(
            abi.encode(SET_GUARDIANS_TYPEHASH, keccak256(abi.encodePacked(guardians)), threshold, adminNonce)
        );
    }

    function setPausedStruct(bool paused, uint256 adminNonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(SET_PAUSED_TYPEHASH, paused, adminNonce));
    }

    function setBridgeStruct(address newBridge, uint256 adminNonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(SET_BRIDGE_TYPEHASH, newBridge, adminNonce));
    }
}
