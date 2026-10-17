#!/bin/sh
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying file LICENSE or
# https://www.opensource.org/licenses/mit-license.php.
#
# One copy of the contract tests (audit 05/T-4): wyec's own Foundry suites run from
# vendor/wyec/test at the pin (imported by test/Upstream.t.sol), Hawkeye's own from test/. Every
# test function declared in either place must be one `forge test --list` actually lists, so an
# upstream suite that silently stops compiling in, or a Hawkeye test forge does not pick up, fails.
#
#   ./tools/fetch-wyec.sh && ./tools/check-test-counts.sh
set -eu
cd "$(dirname "$0")/.."

# forge test --list counts `test*` and `invariant*`. `afterInvariant` is a hook, not a test.
declared() { cat "$@" | grep -cE '^[[:space:]]*function (test|invariant)[A-Za-z0-9_]*\(' || true; }
listed=$(forge test --list --json)
count() {
    echo "$listed" | jq --arg p "$1" '[to_entries[] | select(.key | startswith($p)) | .value[] | length] | add // 0'
}

up_listed=$(count vendor/wyec/test/)
own_listed=$(count test/)
up_declared=$(declared vendor/wyec/test/*.t.sol)
own_declared=$(declared test/*.t.sol)
echo "upstream (vendor/wyec/test): $up_listed listed / $up_declared declared"
echo "Hawkeye (test):              $own_listed listed / $own_declared declared"
test "$up_declared" -gt 0 || { echo "no upstream tests: run tools/fetch-wyec.sh" >&2; exit 1; }
test "$up_listed" = "$up_declared" || { echo "upstream tests not all run" >&2; exit 1; }
test "$own_listed" = "$own_declared" || { echo "Hawkeye tests not all run" >&2; exit 1; }
