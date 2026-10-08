// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {WrappedYcash} from "wyec/WrappedYcash.sol";
import {WyecBridge} from "wyec/WyecBridge.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// script/Deploy.s.sol in-process: predicted-address deployment and the deployment file.
contract DeployScriptTest is Test {
    using stdJson for string;

    // Configs are passed in, not through the environment: forge runs tests in parallel and
    // environment variables are process-wide.
    function config(string memory name) internal view returns (Deploy.Config memory c) {
        c.guardians = new address[](3);
        c.guardians[0] = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        c.guardians[1] = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
        c.guardians[2] = 0x90F79bf6EB2c4f870365E785982E1f101E93b906;
        c.threshold = 2;
        c.challengeWindow = 120;
        c.mintCap = 1000e8;
        c.capWindow = 1 days;
        c.mintMode = "optimistic";
        c.file = string.concat(vm.projectRoot(), "/deployments/.test-", name, ".json");
    }

    function test_Deploy_PairAndFile() public {
        Deploy.Config memory c = config("pair");
        string memory file = c.file;
        Deploy.Result memory r = new Deploy().deploy(c);
        WyecBridge b = WyecBridge(r.bridge);
        assertEq(address(b.token()), r.token);
        assertEq(WrappedYcash(r.token).bridge(), r.bridge);
        assertEq(b.threshold(), 2);
        assertEq(b.guardianCount(), 3);
        assertEq(b.challengeWindow(), 120);
        assertEq(b.mintCap(), 1000e8);
        assertEq(b.capWindow(), 1 days);

        string memory j = vm.readFile(file);
        vm.removeFile(file);
        assertEq(j.readUint(".chainId"), block.chainid);
        assertEq(j.readAddress(".bridge"), r.bridge);
        assertEq(j.readAddress(".token"), r.token);
        assertEq(j.readUint(".deployBlock"), block.number + 1);
        assertEq(j.readUint(".threshold"), 2);
        assertEq(j.readString(".mintMode"), "optimistic");
        assertEq(j.readUint(".challengeWindow"), 120);
        assertEq(j.readUint(".mintCap"), 1000e8);
        assertEq(j.readUint(".capWindow"), 1 days);
        address[] memory g = j.readAddressArray(".guardians");
        assertEq(g.length, 3);
        assertEq(g[2], 0x90F79bf6EB2c4f870365E785982E1f101E93b906);
    }

    /// The mode is recorded, not a contract variant: a threshold-mode deployment is the same bridge.
    function test_Deploy_ThresholdModeRecorded() public {
        Deploy.Config memory c = config("threshold");
        c.mintMode = "threshold";
        c.mintCap = 0;
        c.capWindow = 0;
        string memory file = c.file;
        Deploy.Result memory r = new Deploy().deploy(c);
        assertEq(WyecBridge(r.bridge).challengeWindow(), 120);
        string memory j = vm.readFile(file);
        vm.removeFile(file);
        assertEq(j.readString(".mintMode"), "threshold");
        assertEq(j.readUint(".mintCap"), 0);
    }

    /// threshold = 1 lets one key bypass the optimistic window: refused on mainnet in every mode.
    function test_Deploy_MainnetNeedsThresholdTwo() public {
        Deploy.Config memory c = config("mainnet");
        c.threshold = 1;
        vm.chainId(1);
        Deploy d = new Deploy();
        vm.expectRevert(bytes("THRESHOLD must be >= 2 on mainnet"));
        d.deploy(c);
        c.mintMode = "threshold";
        vm.expectRevert(bytes("THRESHOLD must be >= 2 on mainnet"));
        d.deploy(c);

        vm.chainId(11155111);
        string memory file = c.file;
        Deploy.Result memory r = new Deploy().deploy(c);
        assertEq(WyecBridge(r.bridge).threshold(), 1);
        vm.removeFile(file);
    }

    function test_Deploy_BadConfigRejected() public {
        Deploy d = new Deploy();
        Deploy.Config memory c = config("bad");
        c.challengeWindow = 0;
        vm.expectRevert(bytes("bad CHALLENGE_WINDOW"));
        d.deploy(c);

        c = config("bad");
        c.capWindow = 0;
        vm.expectRevert(bytes("CAP_WINDOW must be > 0 when MINT_CAP > 0"));
        d.deploy(c);

        c = config("bad");
        c.threshold = 4;
        vm.expectRevert(bytes("bad THRESHOLD"));
        d.deploy(c);

        c = config("bad");
        c.mintMode = "fast";
        vm.expectRevert(bytes("MINT_MODE: optimistic|threshold"));
        d.deploy(c);
    }
}
