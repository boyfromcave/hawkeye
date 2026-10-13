// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Ycash developers
pragma solidity ^0.8.24;

import {WyecBridge} from "wyec/WyecBridge.sol";
import {BridgeTestBase} from "wyec-test/utils/BridgeTestBase.sol";

/// Hawkeye's assumptions about `burn`'s recipient check that wyec's own suites (run at the pin
/// through test/Upstream.t.sol) do not state in Hawkeye's terms: the exact recipients
/// `hawkeye-core`'s `recipient_vectors.json` builds are accepted, and every malformed shape reverts
/// `InvalidRecipient()` without a nonce or a balance change.
contract HawkeyeBurnRecipientTest is BridgeTestBase {
    bytes32 constant LOCK = keccak256("lock-1");
    uint256 constant AMOUNT = 5e8;

    // ------------------------------------------------------------------ burn: recipient (§4.2 rev. 2)
    // What Hawkeye relies on: every well-formed recipient `hawkeye-core` builds (22 bytes `02 00|01
    // <hash160>`, 35 bytes `02 02 01|02 <keyHash>`) is accepted whatever its hash, and anything else
    // reverts `InvalidRecipient()` without a nonce or a balance change, so an undecodable recipient
    // never reaches the ledger from this contract (only a zero amount orphans a burn).

    function burnAccepted(bytes memory r) internal {
        uint256 nonce = bridge.burnNonce();
        uint256 bal = token.balanceOf(alice);
        vm.expectEmit(true, true, false, true, address(bridge));
        emit BurnToYcash(nonce, alice, 1, r);
        vm.prank(alice);
        bridge.burn(1, r);
        assertEq(bridge.burnNonce(), nonce + 1);
        assertEq(token.balanceOf(alice), bal - 1);
    }

    function burnRejected(bytes memory r) internal {
        uint256 nonce = bridge.burnNonce();
        uint256 bal = token.balanceOf(alice);
        vm.expectRevert(WyecBridge.InvalidRecipient.selector);
        vm.prank(alice);
        bridge.burn(1, r);
        assertEq(bridge.burnNonce(), nonce);
        assertEq(token.balanceOf(alice), bal);
    }

    /// The `recipient_vectors.json` valid cases (hawkeye-core): P2PKH, P2SH, PQPKH 1 and 2.
    function test_Burn_Recipient_VectorsAccepted() public {
        mintTo(alice, AMOUNT, LOCK);
        bytes20 h5a = hex"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
        burnAccepted(p2pkh(h5a));
        burnAccepted(p2sh(h5a));
        burnAccepted(pqpkh(1, hex"c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258"));
        burnAccepted(pqpkh(2, bytes32(type(uint256).max)));
        burnAccepted(p2pkh(bytes20(0)));
        burnAccepted(pqpkh(1, bytes32(0)));
    }

    /// Revision 1's 32 bytes, every other length, a wrong version, kind or scheme: refused, so
    /// Hawkeye's `ForeignError::is_revert("InvalidRecipient")` names it.
    function test_Burn_Recipient_MalformedRejected() public {
        mintTo(alice, AMOUNT, LOCK);
        bytes20 h = bytes20(keccak256("h"));
        bytes32 k = keccak256("k");
        burnRejected(abi.encodePacked(bytes1(0x01), bytes1(0x00), new bytes(10), h)); // revision 1
        burnRejected(abi.encodePacked(bytes1(0x01), bytes1(0x00), h)); // version 1 at 22
        burnRejected(abi.encodePacked(bytes1(0x03), bytes1(0x00), h));
        burnRejected(abi.encodePacked(bytes1(0x02), bytes1(0x03), h)); // kind 3
        burnRejected(abi.encodePacked(bytes1(0x02), bytes1(0x02), h)); // PQ kind at 22
        burnRejected(abi.encodePacked(bytes1(0x02), bytes1(0x00), bytes1(0x01), k)); // P2PKH at 35
        burnRejected(pqpkh(0, k));
        burnRejected(pqpkh(3, k));
        burnRejected("");
        burnRejected(hex"0200");
        burnRejected(abi.encodePacked(p2pkh(h), bytes1(0))); // 23
        burnRejected(abi.encodePacked(pqpkh(1, k), bytes1(0))); // 36
        burnRejected(abi.encodePacked(new bytes(12), h)); // a left-padded Ethereum address
    }

    // ------------------------------------------------------------------ pause
}
