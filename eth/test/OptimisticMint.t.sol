// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {WyecBridge} from "wyec/WyecBridge.sol";
import {BridgeTestBase} from "./utils/BridgeTestBase.sol";
import {WyecEip712} from "./utils/WyecEip712.sol";

/// Hawkeye's assumptions about wyec's optimistic mint (wyec-contract-design.md §4.5; plan §3.3,
/// §5.3), the path its `mint_mode = optimistic` drives: the leader proposes with its own Mint
/// signature, watchers challenge with a Challenge signature, anyone executes after the window. Each
/// test names one assumption the engine (crates/hawkeye/src/engine/mint.rs) or the adapter
/// (crates/hawkeye-eth) relies on.
contract OptimisticMintTest is BridgeTestBase {
    bytes32 constant LOCK = keccak256("opt-lock");
    uint256 constant AMOUNT = 7e8;

    event MintProposed(
        bytes32 indexed lockId,
        uint256 indexed proposalId,
        address indexed proposer,
        address to,
        uint256 amount,
        uint64 eta
    );
    event MintChallenged(bytes32 indexed lockId, uint256 indexed proposalId, address indexed challenger);
    event Minted(bytes32 indexed lockId, address indexed to, uint256 amount);

    function g(uint256 i) internal view returns (uint256) {
        return guardianKeys[i];
    }

    function status(bytes32 lockId) internal view returns (WyecBridge.ProposalStatus) {
        return bridge.proposalStatus(lockId);
    }

    // ------------------------------------------------------------------ encoding

    /// The adapter computes both digests itself (hawkeye-core eip712, hawkeye-eth eip712): they
    /// must be the contract's.
    function test_Digests_MatchHawkeyeEncoding() public view {
        assertEq(bridge.mintDigest(LOCK, AMOUNT, alice), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        assertEq(bridge.challengeDigest(LOCK, 9), challengeDigest(address(bridge), LOCK, 9));
        assertTrue(bridge.challengeDigest(LOCK, 9) != bridge.challengeDigest(LOCK, 10));
    }

    // ------------------------------------------------------------------ propose

    /// One guardian's signature over the threshold path's Mint digest opens a proposal; anyone
    /// submits it (the proposer is the signer, not msg.sender); ids start at 1 and increase.
    function test_Propose_OneSignatureAnySubmitter() public {
        uint64 eta = uint64(block.timestamp) + WINDOW;
        vm.expectEmit(true, true, true, true, address(bridge));
        emit MintProposed(LOCK, 1, guardianAddrs[0], alice, AMOUNT, eta);
        vm.prank(bob);
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        assertEq(id, 1);
        assertEq(bridge.proposalCount(), 1);

        WyecBridge.Proposal memory p = bridge.getProposal(LOCK);
        assertEq(p.to, alice);
        assertEq(p.eta, eta);
        assertEq(p.proposer, guardianAddrs[0]);
        assertEq(p.id, 1);
        assertEq(p.amount, AMOUNT);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Pending));
        assertEq(uint8(status(keccak256("none"))), uint8(WyecBridge.ProposalStatus.None));
        assertEq(propose(g(1), keccak256("lock-b"), 1, bob), 2);
    }

    /// MintProposed topics: [sig, lockId, proposalId, proposer]; data: abi.encode(to, amount, eta).
    /// MintChallenged topics: [sig, lockId, proposalId, challenger]; no data. The scanner decodes
    /// exactly this layout.
    function test_Events_LogLayout() public {
        vm.recordLogs();
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        challenge(g(1), LOCK, id);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        Vm.Log memory l = logs[0];
        assertEq(l.topics.length, 4);
        assertEq(l.topics[0], keccak256("MintProposed(bytes32,uint256,address,address,uint256,uint64)"));
        assertEq(l.topics[1], LOCK);
        assertEq(l.topics[2], bytes32(id));
        assertEq(l.topics[3], bytes32(uint256(uint160(guardianAddrs[0]))));
        assertEq(l.data, abi.encode(alice, AMOUNT, uint64(block.timestamp) + WINDOW));
        l = logs[1];
        assertEq(l.topics.length, 4);
        assertEq(l.topics[0], keccak256("MintChallenged(bytes32,uint256,address)"));
        assertEq(l.topics[1], LOCK);
        assertEq(l.topics[2], bytes32(id));
        assertEq(l.topics[3], bytes32(uint256(uint160(guardianAddrs[1]))));
        assertEq(l.data.length, 0);
    }

    function test_Propose_RefusesBadInput() public {
        bytes memory sig = sign(outsiderKey, mintDigest(address(bridge), LOCK, AMOUNT, alice));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NotGuardian.selector, vm.addr(outsiderKey)));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig);
        // a zero recipient or amount is refused before the signature is looked at
        vm.expectRevert(WyecBridge.ZeroRecipient.selector);
        bridge.proposeMint(LOCK, AMOUNT, address(0), sig);
        vm.expectRevert(WyecBridge.ZeroAmount.selector);
        bridge.proposeMint(LOCK, 0, alice, sig);
        // a signature over other fields recovers to someone else
        sig = sign(g(0), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        vm.expectRevert();
        bridge.proposeMint(LOCK, AMOUNT + 1, alice, sig);
        mintTo(alice, AMOUNT, LOCK);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.LockConsumed.selector, LOCK));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig);
    }

    /// At most one live proposal per lockId, even a matching one by another guardian: the engine
    /// treats `ProposalPending` over a matching proposal as done, never as a failure to retry.
    function test_Propose_OneLiveProposalPerLock() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        bytes memory sig = sign(g(1), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.ProposalPending.selector, LOCK, id));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig);
        // also once the window has passed (Ready): only execute, challenge or threshold clear it
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.ProposalPending.selector, LOCK, id));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig);
    }

    // ------------------------------------------------------------------ challenge

    /// Any one guardian's Challenge(lockId, proposalId) signature deletes the proposal; anyone
    /// submits it (guardians need no ETH); the lockId is not consumed.
    function test_Challenge_AnyGuardianSignatureAnySubmitter() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        vm.expectEmit(true, true, true, true, address(bridge));
        emit MintChallenged(LOCK, id, guardianAddrs[2]);
        vm.prank(bob);
        challenge(g(2), LOCK, id);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.None));
        assertEq(bridge.getProposal(LOCK).id, 0);
        assertFalse(bridge.consumed(LOCK));
        assertTrue(bridge.vetoed(LOCK, guardianAddrs[0]));
        assertFalse(bridge.vetoed(LOCK, guardianAddrs[2]));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, LOCK, 0));
        bridge.executeMint(LOCK);
    }

    function test_Challenge_RefusesBadInput() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        // a non-guardian's signature
        bytes memory sig = sign(outsiderKey, challengeDigest(address(bridge), LOCK, id));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NotGuardian.selector, vm.addr(outsiderKey)));
        bridge.challengeMint(LOCK, id, sig);
        // the wrong id, or no proposal
        sig = sign(g(1), challengeDigest(address(bridge), LOCK, id + 1));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, LOCK, id + 1));
        bridge.challengeMint(LOCK, id + 1, sig);
        bytes32 none = keccak256("none");
        sig = sign(g(1), challengeDigest(address(bridge), none, 1));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, none, 1));
        bridge.challengeMint(none, 1, sig);
        // a signature for another proposal id recovers to someone else
        sig = sign(g(1), challengeDigest(address(bridge), LOCK, id + 1));
        vm.expectRevert();
        bridge.challengeMint(LOCK, id, sig);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Pending));
    }

    /// The challenged proposer is barred from that lockId, so its (now public) Mint signature
    /// cannot be replayed after every challenge; another guardian re-proposes with a fresh id, and
    /// the old challenge cannot delete the re-proposal. A watcher challenges a fraud once.
    function test_Challenge_VetoesProposer_OtherGuardianReproposes() public {
        bytes memory sig0 = sign(g(0), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        uint256 id1 = bridge.proposeMint(LOCK, AMOUNT, alice, sig0);
        bytes memory veto = sign(g(1), challengeDigest(address(bridge), LOCK, id1));
        bridge.challengeMint(LOCK, id1, veto);

        vm.prank(bob); // anyone replaying the public signature
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.ProposerVetoed.selector, LOCK, guardianAddrs[0]));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig0);

        uint256 id2 = propose(g(2), LOCK, AMOUNT, alice);
        assertGt(id2, id1);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, LOCK, id1));
        bridge.challengeMint(LOCK, id1, veto);

        vm.warp(block.timestamp + WINDOW);
        bridge.executeMint(LOCK);
        assertEq(token.balanceOf(alice), AMOUNT);
        // the veto is per lockId: the vetoed guardian still proposes other locks
        propose(g(0), keccak256("other"), 1, alice);
    }

    /// A guardian may challenge its own proposal (withdraw a mistake) and is then barred too.
    function test_Challenge_Own() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        challenge(g(0), LOCK, id);
        assertTrue(bridge.vetoed(LOCK, guardianAddrs[0]));
    }

    // ------------------------------------------------------------------ execute

    /// Anyone executes once block.timestamp >= eta; the event is the threshold path's Minted, so
    /// the scanner needs nothing new to observe a completed optimistic mint.
    function test_Execute_AfterWindow_Anyone() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        uint64 eta = bridge.getProposal(LOCK).eta;
        vm.warp(eta - 1);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.ChallengeWindowOpen.selector, eta));
        bridge.executeMint(LOCK);
        // the window is still open for a challenge one second before eta ...
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Pending));
        vm.warp(eta);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Ready));
        // ... and at eta, too: challenge and execute race from eta on (the engine challenges
        // before eta, plan §5.3)
        uint256 snap = vm.snapshotState();
        challenge(g(1), LOCK, id);
        vm.revertToState(snap);

        vm.expectEmit(true, true, false, true, address(bridge));
        emit Minted(LOCK, alice, AMOUNT);
        vm.prank(bob);
        bridge.executeMint(LOCK);
        assertEq(token.balanceOf(alice), AMOUNT);
        assertTrue(bridge.consumed(LOCK));
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.None));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, LOCK, 0));
        bridge.executeMint(LOCK);
    }

    /// A proposer rotated out of the guardian set (e.g. after a slash on Ycash) leaves a Void
    /// proposal: not executable, replaced by any current guardian's proposal.
    function test_Execute_VoidAfterRotation_Reproposable() public {
        propose(g(0), LOCK, AMOUNT, alice);
        address[] memory gs = new address[](2);
        gs[0] = guardianAddrs[1];
        gs[1] = guardianAddrs[2];
        bytes32 d = WyecEip712.digest(
            domainOf(address(bridge)), WyecEip712.setGuardiansStruct(gs, 2, bridge.adminNonce())
        );
        bridge.setGuardians(gs, 2, signSorted(keys(g(1), g(2)), d));
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Void));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.ProposerNotGuardian.selector, guardianAddrs[0]));
        bridge.executeMint(LOCK);
        uint256 id = propose(g(1), LOCK, AMOUNT, alice);
        assertEq(bridge.getProposal(LOCK).id, id);
        vm.warp(block.timestamp + WINDOW);
        bridge.executeMint(LOCK);
        assertEq(token.balanceOf(alice), AMOUNT);
    }

    /// A quorum overrides: the threshold mint clears a pending proposal at once.
    function test_ThresholdMint_ClearsProposal() public {
        propose(g(0), LOCK, 1, bob); // a wrong proposal squatting the lock
        mintTo(alice, AMOUNT, LOCK);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.None));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.NoProposal.selector, LOCK, 0));
        bridge.executeMint(LOCK);
        assertEq(token.balanceOf(alice), AMOUNT);
        assertEq(token.balanceOf(bob), 0);
    }

    /// A proposer's Mint signature also counts towards a threshold mint of the same lock (one
    /// message per lock in either mode: the sign-once record serves both).
    function test_ProposerSignature_CountsForThreshold() public {
        bytes memory sig0 = sign(g(0), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        bridge.proposeMint(LOCK, AMOUNT, alice, sig0);
        bytes memory sig1 = sign(g(1), mintDigest(address(bridge), LOCK, AMOUNT, alice));
        bytes[] memory sigs = new bytes[](2);
        (sigs[0], sigs[1]) = guardianAddrs[0] < guardianAddrs[1] ? (sig0, sig1) : (sig1, sig0);
        bridge.mint(LOCK, AMOUNT, alice, sigs);
        assertEq(token.balanceOf(alice), AMOUNT);
    }

    /// Pause stops propose and execute, never challenge; windows keep running while paused.
    function test_Pause_StopsProposeAndExecuteNotChallenge() public {
        uint256 id = propose(g(0), LOCK, AMOUNT, alice);
        bridge.setPaused(true, signedSetPaused(true));
        vm.warp(block.timestamp + WINDOW);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.executeMint(LOCK);
        bytes32 lock2 = keccak256("opt-lock-2");
        bytes memory sig = sign(g(0), mintDigest(address(bridge), lock2, 1, alice));
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.proposeMint(lock2, 1, alice, sig);
        challenge(g(1), LOCK, id);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.None));
    }

    // ------------------------------------------------------------------ rate limit

    /// The rate limit applies at execute, not at propose: a proposal over the remaining budget
    /// stays Ready (MintRateLimited) and executes in a later window. Hawkeye retries the execute.
    function test_RateLimit_AtExecute_ProposalWaits() public {
        uint256 day = 86400;
        bytes32 d = WyecEip712.digest(
            domainOf(address(bridge)), WyecEip712.setMintLimitStruct(10e8, day, bridge.adminNonce())
        );
        bridge.setMintLimit(10e8, day, signSorted(guardianPair(), d));
        assertEq(bridge.mintAvailable(), 10e8);
        mintTo(alice, 6e8, keccak256("first"));
        assertEq(bridge.mintAvailable(), 4e8);

        propose(g(0), LOCK, AMOUNT, alice);
        vm.warp(block.timestamp + WINDOW);
        uint256 avail = bridge.mintAvailable();
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.MintRateLimited.selector, AMOUNT, avail));
        bridge.executeMint(LOCK);
        assertEq(uint8(status(LOCK)), uint8(WyecBridge.ProposalStatus.Ready));

        vm.warp((block.timestamp / day + 1) * day);
        bridge.executeMint(LOCK);
        assertEq(token.balanceOf(alice), 6e8 + AMOUNT);
        assertEq(bridge.mintAvailable(), 10e8 - AMOUNT);
    }

    // ------------------------------------------------------------------ the mainnet rule

    /// Why the mainnet rule is `threshold >= 2` in every mode (plan §3.3): at threshold 1 a single
    /// key skips the window through `mint`, so the optimistic path protects nothing.
    function test_ThresholdOne_BypassesWindow() public {
        address[] memory one = new address[](3);
        one[0] = guardianAddrs[0];
        one[1] = guardianAddrs[1];
        one[2] = guardianAddrs[2];
        (WrappedYcash t, WyecBridge b) = deployPair(one, 1);
        b.mint(LOCK, AMOUNT, bob, signSorted(keys(g(0)), mintDigest(address(b), LOCK, AMOUNT, bob)));
        assertEq(t.balanceOf(bob), AMOUNT, "one key, no window");
        // at threshold 2 (the fixture) one key can only propose
        bytes[] memory one0 = signSorted(keys(g(0)), mintDigest(address(bridge), LOCK, AMOUNT, bob));
        vm.expectRevert(abi.encodeWithSelector(WyecBridge.Threshold.selector, 1, 2));
        bridge.mint(LOCK, AMOUNT, bob, one0);
    }
}
