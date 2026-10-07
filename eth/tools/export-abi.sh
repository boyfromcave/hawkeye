#!/bin/sh
# Export the forge-built artifacts the Rust adapter binds (crates/hawkeye-eth/abi/*.json):
# ABI, creation bytecode and runtime bytecode of wYEC @ the pinned commit and of the CR-W1 test
# double. Run after any re-pin or compiler change, then commit the result; `--check` fails if the
# committed files differ from a fresh build (what CI runs).
#
#   ./tools/export-abi.sh            # rebuild and rewrite
#   ./tools/export-abi.sh --check    # rebuild and compare
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dest="$here/../crates/hawkeye-eth/abi"
cd "$here"

forge build --quiet

check=0
[ "${1:-}" = "--check" ] && check=1
status=0
for spec in WyecBridge.sol:WyecBridge WrappedYcash.sol:WrappedYcash OptimisticMintBridge.sol:OptimisticMintBridge; do
    file=${spec%%:*}
    name=${spec##*:}
    out=$(jq --sort-keys '{abi: .abi, bytecode: {object: .bytecode.object}, deployedBytecode: {object: .deployedBytecode.object}}' \
        "out/$file/$name.json")
    if [ $check -eq 1 ]; then
        if ! printf '%s\n' "$out" | cmp -s - "$dest/$name.json"; then
            echo "stale: crates/hawkeye-eth/abi/$name.json" >&2
            status=1
        fi
    else
        mkdir -p "$dest"
        printf '%s\n' "$out" >"$dest/$name.json"
        echo "wrote crates/hawkeye-eth/abi/$name.json"
    fi
done
exit $status
