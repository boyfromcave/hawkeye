// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Ycash developers
pragma solidity ^0.8.24;

// wyec's own Foundry suites at the commit pinned in tools/fetch-wyec.sh, fetched into
// vendor/wyec/test and run here under Hawkeye's toolchain (audit 05/T-4): one copy of the
// contract tests, never a diverging local one. Importing a suite compiles it into this project,
// and forge runs every test contract it compiles; nothing else is needed. CI asserts the number
// of upstream tests forge lists (eth/README.md, "What the tests pin down").
import {WyecBridgeTest} from "wyec-test/WyecBridge.t.sol";
import {OptimisticMintTest} from "wyec-test/OptimisticMint.t.sol";
import {RateLimitTest} from "wyec-test/RateLimit.t.sol";
import {DeployScriptTest} from "wyec-test/Deploy.t.sol";
