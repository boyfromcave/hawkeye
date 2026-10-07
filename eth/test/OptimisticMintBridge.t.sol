// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {IWrappedYcash, WyecBridge} from "wyec/WyecBridge.sol";
import {OptimisticMintBridge} from "./mocks/OptimisticMintBridge.sol";
import {BridgeTestBase} from "./utils/BridgeTestBase.sol";

/// The CR-W1 test double's behaviour, as Hawkeye's optimistic mint mode relies on it.
contract OptimisticMintBridgeTest is BridgeTestBase {
    uint64 constant WINDOW = 3600;
    bytes32 constant LOCK = keccak256("opt-lock");
    uint256 constant AMOUNT = 7e8;

    OptimisticMintBridge internal opt;
    WrappedYcash internal optToken;

    event MintProposed(
        bytes32 indexed lockId,
        address indexed to,
        uint256 amount,
        address indexed proposer,
        uint64 executableAt
    );
    event MintChallenged(bytes32 indexed lockId, address indexed challenger, address indexed proposer);
    event Minted(bytes32 indexed lockId, address indexed to, uint256 amount);

    function setUp() public override {
        super.setUp();
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        opt = new OptimisticMintBridge(IWrappedYcash(predicted), guardianAddrs, 2, WINDOW);
        optToken = new WrappedYcash(address(opt));
        assertEq(address(optToken), predicted);
    }

    function propose(uint256 pk) internal {
        opt.proposeMint(LOCK, AMOUNT, alice, sign(pk, mintDigest(address(opt), LOCK, AMOUNT, alice)));
    }

    function test_MintDigest_MatchesHawkeyeEncoding() public view {
        assertEq(opt.mintDigest(LOCK, AMOUNT, alice), mintDigest(address(opt), LOCK, AMOUNT, alice));
    }

    function test_Propose_Window_Execute() public {
        uint64 at = uint64(block.timestamp) + WINDOW;
        vm.expectEmit(true, true, true, true, address(opt));
        emit MintProposed(LOCK, alice, AMOUNT, guardianAddrs[0], at);
        vm.prank(bob); // anyone may carry the one guardian signature
        propose(guardianKeys[0]);

        (uint256 amount, address to, address proposer, uint64 executableAt) = opt.proposals(LOCK);
        assertEq(amount, AMOUNT);
        assertEq(to, alice);
        assertEq(proposer, guardianAddrs[0]);
        assertEq(executableAt, at);

        vm.expectRevert(abi.encodeWithSelector(OptimisticMintBridge.ChallengeWindowOpen.selector, at));
        opt.executeMint(LOCK);

        vm.warp(at);
        vm.expectEmit(true, true, false, true, address(opt));
        emit Minted(LOCK, alice, AMOUNT);
        vm.prank(bob);
        opt.executeMint(LOCK);
        assertEq(optToken.balanceOf(alice), AMOUNT);
        assertTrue(opt.consumed(LOCK));
        (,, proposer,) = opt.proposals(LOCK);
        assertEq(proposer, address(0));

        vm.expectRevert(abi.encodeWithSelector(WyecBridge.LockConsumed.selector, LOCK));
        propose(guardianKeys[1]);
    }

    function test_Challenge_DeletesAndIsReproposable() public {
        propose(guardianKeys[0]);
        vm.expectEmit(true, true, true, false, address(opt));
        emit MintChallenged(LOCK, guardianAddrs[1], guardianAddrs[0]);
        vm.prank(guardianAddrs[1]);
        opt.challengeMint(LOCK);

        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(OptimisticMintBridge.NoProposal.selector, LOCK));
        opt.executeMint(LOCK);
        assertFalse(opt.consumed(LOCK));

        propose(guardianKeys[2]);
        vm.warp(block.timestamp + WINDOW);
        opt.executeMint(LOCK);
        assertEq(optToken.balanceOf(alice), AMOUNT);
    }

    function test_Challenge_OnlyGuardian() public {
        propose(guardianKeys[0]);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NotGuardian.selector, bob));
        vm.prank(bob);
        opt.challengeMint(LOCK);
        vm.prank(guardianAddrs[2]);
        vm.expectRevert(abi.encodeWithSelector(OptimisticMintBridge.NoProposal.selector, keccak256("none")));
        opt.challengeMint(keccak256("none"));
    }

    function test_Propose_NonGuardianSignatureRejected() public {
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NotGuardian.selector, vm.addr(outsiderKey)));
        propose(outsiderKey);
    }

    function test_Propose_OnePendingPerLock() public {
        propose(guardianKeys[0]);
        vm.expectRevert(abi.encodeWithSelector(OptimisticMintBridge.ProposalPending.selector, LOCK));
        propose(guardianKeys[1]);
    }

    /// The k-of-n path stays; a threshold mint of a pending lockId makes the proposal unexecutable.
    function test_ThresholdMint_PreemptsProposal() public {
        propose(guardianKeys[0]);
        opt.mint(
            LOCK, AMOUNT, alice, signSorted(guardianPair(), mintDigest(address(opt), LOCK, AMOUNT, alice))
        );
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.LockConsumed.selector, LOCK));
        opt.executeMint(LOCK);
        assertEq(optToken.balanceOf(alice), AMOUNT);
    }

    function test_Pause_StopsProposeAndExecuteNotChallenge() public {
        propose(guardianKeys[0]);
        bytes32 d = keccak256(
            abi.encodePacked(
                hex"1901",
                domainOf(address(opt)),
                keccak256(
                    abi.encode(keccak256("SetPaused(bool paused,uint256 adminNonce)"), true, uint256(0))
                )
            )
        );
        opt.setPaused(true, signSorted(guardianPair(), d));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        opt.executeMint(LOCK);
        vm.prank(guardianAddrs[1]);
        opt.challengeMint(LOCK);
        bytes32 lock2 = keccak256("opt-lock-2");
        bytes memory sig = sign(guardianKeys[0], mintDigest(address(opt), lock2, 1, alice));
        vm.expectRevert(Pausable.EnforcedPause.selector);
        opt.proposeMint(lock2, 1, alice, sig);
    }
}
