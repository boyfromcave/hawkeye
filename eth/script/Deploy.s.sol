// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {IWrappedYcash, WyecBridge} from "wyec/WyecBridge.sol";
import {OptimisticMintBridge} from "../test/mocks/OptimisticMintBridge.sol";

/// Deploys wYEC in the order of wyec-contract-design.md §8: the bridge first, constructed with the
/// token address predicted from the deployer's next nonce, then the token in the very next
/// transaction from the same deployer. The prediction is asserted before and after.
///
/// Environment:
///   GUARDIANS          comma-separated guardian addresses (required)
///   THRESHOLD          k of the k-of-n mint and admin threshold (required)
///   MINT_MODE          "threshold" (default: wyec's WyecBridge) or "optimistic" (the CR-W1 TEST
///                      DOUBLE test/mocks/OptimisticMintBridge.sol; refused unless chain id 31337)
///   CHALLENGE_WINDOW   seconds, optimistic mode only (default 60)
///   DEPLOYMENT_FILE    output path (default deployments/<chainid>.json)
///
/// Output: {chainId, bridge, token, deployBlock, guardians, threshold, mintMode, challengeWindow}.
/// deployBlock is the first block the deployment can be in (head + 1 at script time): exact on an
/// automining anvil, a safe lower bound for a log scanner elsewhere.
contract Deploy is Script {
    struct Result {
        address bridge;
        address token;
        uint256 deployBlock;
    }

    struct Config {
        address[] guardians;
        uint256 threshold;
        bool optimistic;
        uint64 challengeWindow;
        string file;
    }

    function run() external returns (Result memory) {
        Config memory c;
        c.guardians = vm.envAddress("GUARDIANS", ",");
        c.threshold = vm.envUint("THRESHOLD");
        string memory mode = vm.envOr("MINT_MODE", string("threshold"));
        c.optimistic = keccak256(bytes(mode)) == keccak256("optimistic");
        require(
            c.optimistic || keccak256(bytes(mode)) == keccak256("threshold"),
            "MINT_MODE: threshold|optimistic"
        );
        c.challengeWindow = uint64(vm.envOr("CHALLENGE_WINDOW", uint256(60)));
        c.file = vm.envOr(
            "DEPLOYMENT_FILE",
            string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json")
        );
        return deploy(c);
    }

    function deploy(Config memory c) public returns (Result memory r) {
        address[] memory guardians = c.guardians;
        uint256 threshold = c.threshold;
        require(
            threshold > 0 && threshold <= guardians.length && threshold <= type(uint8).max, "bad THRESHOLD"
        );
        bool optimistic = c.optimistic;
        require(!optimistic || block.chainid == 31337, "the optimistic bridge is a test double: anvil only");
        uint64 window = c.challengeWindow;
        string memory mode = optimistic ? "optimistic" : "threshold";

        r.deployBlock = block.number + 1;
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        uint64 nonce = vm.getNonce(deployer);
        address predicted = vm.computeCreateAddress(deployer, nonce + 1);

        // casting to uint8 is safe: threshold <= type(uint8).max is required above.
        // forge-lint: disable-next-item(unsafe-typecast)
        WyecBridge bridge = optimistic
            ? new OptimisticMintBridge(IWrappedYcash(predicted), guardians, uint8(threshold), window)
            : new WyecBridge(IWrappedYcash(predicted), guardians, uint8(threshold));
        WrappedYcash token = new WrappedYcash(address(bridge));
        vm.stopBroadcast();

        require(address(token) == predicted, "token address prediction failed");
        require(
            address(bridge.token()) == address(token) && token.bridge() == address(bridge), "pair mismatch"
        );
        r.bridge = address(bridge);
        r.token = address(token);

        string memory o = "deployment";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "bridge", r.bridge);
        vm.serializeAddress(o, "token", r.token);
        vm.serializeUint(o, "deployBlock", r.deployBlock);
        vm.serializeAddress(o, "guardians", guardians);
        vm.serializeUint(o, "threshold", threshold);
        vm.serializeUint(o, "challengeWindow", optimistic ? uint256(window) : 0);
        string memory json = vm.serializeString(o, "mintMode", mode);

        string memory path = c.file;
        vm.writeJson(json, path);
        console.log("deployer   ", deployer);
        console.log("bridge     ", r.bridge);
        console.log("token      ", r.token);
        console.log("deployBlock", r.deployBlock);
        console.log("written    ", path);
    }
}
