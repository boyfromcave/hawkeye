// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// =================================================================================================
//  TEST DOUBLE - NOT THE CONTRACT OF RECORD.
//
//  This is Hawkeye's stand-in for change request CR-W1 (hawkeye-bridge-plan.md §10, §3.3): the
//  optimistic mint the wYEC contracts do not have yet. It exists only so Hawkeye's optimistic mint
//  mode can be developed and tested on anvil before wyec ships the real thing. It has not been
//  designed with the wyec maintainers, reviewed or audited, and must never be deployed to a public
//  network as a bridge. When wyec ships CR-W1, Hawkeye binds that contract and this file goes.
// =================================================================================================

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IWrappedYcash, WyecBridge} from "wyec/WyecBridge.sol";

/// WyecBridge (pinned wyec, unchanged: k-of-n `mint`, `burn`, admin) plus CR-W1's optimistic path:
///   proposeMint(lockId, amount, to, sig)  one guardian's EIP-712 Mint signature opens a proposal
///   challengeMint(lockId)                 any guardian (msg.sender) deletes it; re-proposable
///   executeMint(lockId)                   anyone, once `challengeWindow` seconds have passed
/// The proposal's signature is the same `Mint(bytes32 lockId,uint256 amount,address to)` digest the
/// k-of-n path verifies, so one attestor signature serves both modes and is slashing evidence.
contract OptimisticMintBridge is WyecBridge {
    bytes32 private constant MINT_TYPEHASH_ = keccak256("Mint(bytes32 lockId,uint256 amount,address to)");

    struct Proposal {
        uint256 amount;
        address to;
        address proposer;
        uint64 executableAt;
    }

    /// Seconds between a proposal and the earliest execute (CR-W1's MINT_CHALLENGE_WINDOW).
    uint64 public immutable challengeWindow;

    mapping(bytes32 lockId => Proposal) public proposals;

    event MintProposed(
        bytes32 indexed lockId,
        address indexed to,
        uint256 amount,
        address indexed proposer,
        uint64 executableAt
    );
    event MintChallenged(bytes32 indexed lockId, address indexed challenger, address indexed proposer);

    error ProposalPending(bytes32 lockId);
    error NoProposal(bytes32 lockId);
    error ChallengeWindowOpen(uint64 executableAt);

    constructor(IWrappedYcash token_, address[] memory guardians_, uint8 threshold_, uint64 challengeWindow_)
        WyecBridge(token_, guardians_, threshold_)
    {
        challengeWindow = challengeWindow_;
    }

    function proposeMint(bytes32 lockId, uint256 amount, address to, bytes calldata sig)
        external
        whenNotPaused
    {
        if (consumed[lockId]) revert LockConsumed(lockId);
        if (proposals[lockId].proposer != address(0)) revert ProposalPending(lockId);
        address signer = ECDSA.recover(mintDigest(lockId, amount, to), sig);
        if (!isGuardian[signer]) revert NotGuardian(signer);
        uint64 executableAt = uint64(block.timestamp) + challengeWindow;
        proposals[lockId] = Proposal(amount, to, signer, executableAt);
        emit MintProposed(lockId, to, amount, signer, executableAt);
    }

    /// Any current guardian deletes a pending proposal. Allowed while paused.
    function challengeMint(bytes32 lockId) external {
        if (!isGuardian[msg.sender]) revert NotGuardian(msg.sender);
        address proposer = proposals[lockId].proposer;
        if (proposer == address(0)) revert NoProposal(lockId);
        delete proposals[lockId];
        emit MintChallenged(lockId, msg.sender, proposer);
    }

    function executeMint(bytes32 lockId) external whenNotPaused {
        Proposal memory p = proposals[lockId];
        if (p.proposer == address(0)) revert NoProposal(lockId);
        // A challenge window of minutes to hours; validator timestamp drift is seconds.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < p.executableAt) revert ChallengeWindowOpen(p.executableAt);
        if (consumed[lockId]) revert LockConsumed(lockId);
        delete proposals[lockId];
        consumed[lockId] = true;
        token.crosschainMint(p.to, p.amount);
        emit Minted(lockId, p.to, p.amount);
    }

    /// The EIP-712 Mint digest (the same one WyecBridge.mint verifies). Test-double convenience.
    function mintDigest(bytes32 lockId, uint256 amount, address to) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH_, lockId, amount, to)));
    }
}
