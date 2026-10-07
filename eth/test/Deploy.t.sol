// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {WyecBridge} from "wyec/WyecBridge.sol";
import {OptimisticMintBridge} from "./mocks/OptimisticMintBridge.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// script/Deploy.s.sol in-process: predicted-address deployment and the deployment file.
contract DeployScriptTest is Test {
    using stdJson for string;

    // Configs are passed in, not through the environment: forge runs tests in parallel and
    // environment variables are process-wide.
    function config(bool optimistic, string memory name) internal view returns (Deploy.Config memory c) {
        c.guardians = new address[](2);
        c.guardians[0] = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        c.guardians[1] = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
        c.threshold = 2;
        c.optimistic = optimistic;
        c.challengeWindow = 120;
        c.file = string.concat(vm.projectRoot(), "/deployments/.test-", name, ".json");
    }

    function test_Deploy_Threshold() public {
        Deploy.Config memory c = config(false, "threshold");
        string memory file = c.file;
        Deploy.Result memory r = new Deploy().deploy(c);
        WyecBridge b = WyecBridge(r.bridge);
        assertEq(address(b.token()), r.token);
        assertEq(WrappedYcash(r.token).bridge(), r.bridge);
        assertEq(b.threshold(), 2);

        string memory j = vm.readFile(file);
        vm.removeFile(file);
        assertEq(j.readUint(".chainId"), block.chainid);
        assertEq(j.readAddress(".bridge"), r.bridge);
        assertEq(j.readAddress(".token"), r.token);
        assertEq(j.readUint(".deployBlock"), block.number + 1);
        assertEq(j.readUint(".threshold"), 2);
        address[] memory g = j.readAddressArray(".guardians");
        assertEq(g.length, 2);
        assertEq(g[1], 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC);
        assertEq(j.readString(".mintMode"), "threshold");
    }

    function test_Deploy_OptimisticOnAnvilOnly() public {
        Deploy.Config memory c = config(true, "optimistic");
        string memory file = c.file;
        vm.chainId(31337);
        Deploy.Result memory r = new Deploy().deploy(c);
        assertEq(OptimisticMintBridge(r.bridge).challengeWindow(), 120);
        assertEq(vm.readFile(file).readUint(".challengeWindow"), 120);
        vm.removeFile(file);

        vm.chainId(11155111);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("the optimistic bridge is a test double: anvil only"));
        d.deploy(c);
    }
}
