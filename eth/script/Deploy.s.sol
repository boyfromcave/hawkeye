// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {IWrappedYcash, WyecBridge} from "wyec/WyecBridge.sol";

/// Deploys wYEC in the order of wyec-contract-design.md §8: the bridge first, constructed with the
/// token address predicted from the deployer's next nonce, then the token in the very next
/// transaction from the same deployer. The prediction is asserted before and after.
///
/// The same checks as wyec's own script/Deploy.s.sol (at the pinned commit), plus the mint mode
/// the attestors are configured for, recorded in the deployment file for their configs. One
/// WyecBridge serves both modes: the mode is how Hawkeye mints (plan §3.3), not a contract variant.
///
/// Environment:
///   GUARDIANS          comma-separated guardian addresses (required)
///   THRESHOLD          k of the threshold mint and every admin act (required; >= 2 on mainnet in
///                      every mode: at k = 1 one key mints through `mint` and skips the window)
///   CHALLENGE_WINDOW   optimistic-mint challenge window in seconds (required, > 0; immutable)
///   MINT_CAP           mint rate limit in wYEC base units per CAP_WINDOW (default 0 = no limit)
///   CAP_WINDOW         rate-limit window in seconds (default 0; > 0 when MINT_CAP > 0)
///   MINT_MODE          "optimistic" (default: proposeMint + window, the Foundation's model) or
///                      "threshold" (k-of-n mint), recorded as mintMode
///   DEPLOYMENT_FILE    output path (default deployments/<chainid>.json)
///
/// Output: {chainId, bridge, token, deployBlock, guardians, threshold, mintMode, challengeWindow,
/// mintCap, capWindow}. deployBlock is the first block the deployment can be in (head + 1 at
/// script time): exact on an automining anvil, a safe lower bound for a log scanner elsewhere.
contract Deploy is Script {
    struct Result {
        address bridge;
        address token;
        uint256 deployBlock;
    }

    struct Config {
        address[] guardians;
        uint256 threshold;
        uint256 challengeWindow;
        uint256 mintCap;
        uint256 capWindow;
        string mintMode;
        string file;
    }

    function run() external returns (Result memory) {
        Config memory c;
        c.guardians = vm.envAddress("GUARDIANS", ",");
        c.threshold = vm.envUint("THRESHOLD");
        c.challengeWindow = vm.envUint("CHALLENGE_WINDOW");
        c.mintCap = vm.envOr("MINT_CAP", uint256(0));
        c.capWindow = vm.envOr("CAP_WINDOW", uint256(0));
        c.mintMode = vm.envOr("MINT_MODE", string("optimistic"));
        c.file = vm.envOr(
            "DEPLOYMENT_FILE",
            string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json")
        );
        return deploy(c);
    }

    function deploy(Config memory c) public returns (Result memory r) {
        require(
            c.threshold > 0 && c.threshold <= c.guardians.length && c.threshold <= type(uint8).max,
            "bad THRESHOLD"
        );
        // With k = 1 one key mints immediately through `mint`, bypassing the optimistic window
        // (wyec-contract-design.md §4.5.2, plan §3.3): never on mainnet, whatever the mode.
        require(block.chainid != 1 || c.threshold >= 2, "THRESHOLD must be >= 2 on mainnet");
        require(c.challengeWindow > 0 && c.challengeWindow <= type(uint64).max, "bad CHALLENGE_WINDOW");
        require(c.mintCap == 0 || c.capWindow > 0, "CAP_WINDOW must be > 0 when MINT_CAP > 0");
        bytes32 mode = keccak256(bytes(c.mintMode));
        require(
            mode == keccak256("optimistic") || mode == keccak256("threshold"),
            "MINT_MODE: optimistic|threshold"
        );

        r.deployBlock = block.number + 1;
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        address predicted = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);

        // casting is safe: both bounds are required above.
        // forge-lint: disable-next-item(unsafe-typecast)
        WyecBridge bridge = new WyecBridge(
            IWrappedYcash(predicted),
            c.guardians,
            uint8(c.threshold),
            uint64(c.challengeWindow),
            c.mintCap,
            c.capWindow
        );
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
        vm.serializeAddress(o, "guardians", c.guardians);
        vm.serializeUint(o, "threshold", c.threshold);
        vm.serializeString(o, "mintMode", c.mintMode);
        vm.serializeUint(o, "challengeWindow", c.challengeWindow);
        vm.serializeUint(o, "mintCap", c.mintCap);
        string memory json = vm.serializeUint(o, "capWindow", c.capWindow);
        vm.writeJson(json, c.file);

        console.log("deployer   ", deployer);
        console.log("bridge     ", r.bridge);
        console.log("token      ", r.token);
        console.log("deployBlock", r.deployBlock);
        console.log("mintMode   ", c.mintMode);
        console.log("written    ", c.file);
    }
}
