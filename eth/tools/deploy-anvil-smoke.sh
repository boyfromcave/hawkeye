#!/usr/bin/env bash
# Smoke test of script/Deploy.s.sol against a throwaway anvil (CI: contracts job).
#
# Starts anvil on a free port, deploys with anvil's default account 0, three guardians (anvil
# accounts 1-3) and threshold 2, then checks the deployment file and reads the contracts back
# with `cast call`: guardianCount = 3, threshold = 2, token decimals = 8, bridge.token() = token,
# token.bridge() = bridge. Exits non-zero on any failure; anvil is always killed.
#
# The deployment file goes to a temporary directory under deployments/ (Foundry's fs_permissions
# allow only that path; `deployments/.smoke.*` is gitignored and removed on exit), so nothing
# lands in the tree. Works with the solc-js shim too:
#   FOUNDRY_SOLC=./tools/solc FOUNDRY_OFFLINE=true ./tools/deploy-anvil-smoke.sh
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

# anvil's well-known dev key for account 0 and addresses of accounts 1-3 (public test values).
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
G1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
G2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
G3=0x90F79bf6EB2c4f870365E785982E1f101E93b906

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()' 2>/dev/null ||
    node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')
rpc="http://127.0.0.1:$port"
tmp=$(mktemp -d "$here/deployments/.smoke.XXXXXX")
anvil_pid=

cleanup() {
    if [ -n "$anvil_pid" ]; then
        kill "$anvil_pid" 2>/dev/null || true
        wait "$anvil_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    echo "smoke: FAIL: $*" >&2
    exit 1
}

anvil --port "$port" --slots-in-an-epoch 1 >"$tmp/anvil.log" 2>&1 &
anvil_pid=$!
for _ in $(seq 1 100); do
    cast chain-id --rpc-url "$rpc" >/dev/null 2>&1 && break
    kill -0 "$anvil_pid" 2>/dev/null || { cat "$tmp/anvil.log" >&2; fail "anvil exited"; }
    sleep 0.1
done
[ "$(cast chain-id --rpc-url "$rpc")" = 31337 ] || fail "anvil not answering on $rpc"

file="$tmp/31337.json"
GUARDIANS="$G1,$G2,$G3" THRESHOLD=2 DEPLOYMENT_FILE="$file" \
    forge script script/Deploy.s.sol --rpc-url "$rpc" --private-key "$DEPLOYER_KEY" --broadcast \
    >"$tmp/forge.log" 2>&1 || { cat "$tmp/forge.log" >&2; fail "forge script"; }

[ -s "$file" ] || fail "deployment file not written"
field() { node -e 'const d=require(process.argv[1]); console.log(d[process.argv[2]])' "$file" "$1"; }
bridge=$(field bridge)
token=$(field token)
[ "$(field chainId)" = 31337 ] || fail "chainId in deployment file"
[ "$(field threshold)" = 2 ] || fail "threshold in deployment file"
[ "$(node -e 'console.log(require(process.argv[1]).guardians.length)' "$file")" = 3 ] || fail "guardians in deployment file"

eq_addr() { [ "$(echo "$1" | tr 'A-F' 'a-f')" = "$(echo "$2" | tr 'A-F' 'a-f')" ]; }
call() { cast call --rpc-url "$rpc" "$@"; }

got=$(call "$bridge" 'guardianCount()(uint256)')
[ "$got" = 3 ] || fail "guardianCount = $got"
got=$(call "$bridge" 'threshold()(uint8)')
[ "$got" = 2 ] || fail "threshold = $got"
got=$(call "$token" 'decimals()(uint8)')
[ "$got" = 8 ] || fail "decimals = $got"
got=$(call "$bridge" 'token()(address)')
eq_addr "$got" "$token" || fail "bridge.token() = $got, want $token"
got=$(call "$token" 'bridge()(address)')
eq_addr "$got" "$bridge" || fail "token.bridge() = $got, want $bridge"
for i in 0 1 2; do
    got=$(call "$bridge" 'guardians(uint256)(address)' "$i")
    want=$(node -e 'console.log(require(process.argv[1]).guardians[process.argv[2]])' "$file" "$i")
    eq_addr "$got" "$want" || fail "guardians($i) = $got, want $want"
done

echo "smoke: OK bridge $bridge token $token (3 guardians, threshold 2, decimals 8)"
