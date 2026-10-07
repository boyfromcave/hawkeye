# `eth/`: Hawkeye's Foundry project

What Hawkeye needs on the Ethereum side (plan §6, §7, phase H3), built against the wYEC contracts
at a **pinned commit**, which are fetched and never copied in (AGENTS.md rule 2):

| Path | What |
|---|---|
| `tools/fetch-wyec.sh` | fetches `boyfromcave/wyec` @ `d2e382beeea11c9f9b43675ae49d6d52334c46d6` into `vendor/wyec` (gitignored); `WYEC_SRC=<clone>` to export from a local clone instead |
| `package.json` | pinned dependencies: `@openzeppelin/contracts` 5.6.1 (wyec's compile check), `forge-std` v1.17.0 (git commit `f3dae6e`), `solc` 0.8.37 (solc-js, only for the shim) |
| `foundry.toml` | `src` = `vendor/wyec/contracts`, solc 0.8.37, optimizer 200 runs (as wyec's `compile.js`), remappings `@openzeppelin/contracts/`, `forge-std/`, `wyec/` |
| `tools/solc`, `tools/solc-shim.js` | a native-`solc` stand-in over solc-js, for machines where Foundry cannot download the compiler |
| `test/WyecBridge.t.sol` | Hawkeye's assumptions about the contract (below) |
| `test/OptimisticMintBridge.t.sol`, `test/mocks/OptimisticMintBridge.sol` | the CR-W1 **test double** and its tests |
| `test/Vectors.t.sol` → `vectors/eip712.json` | EIP-712 golden vectors; format in `vectors/README.md` |
| `test/Deploy.t.sol`, `script/Deploy.s.sol` | the predicted-address deployment and its output file |
| `tools/deploy-anvil-smoke.sh` | CI smoke test: anvil on a free port, `Deploy.s.sol --broadcast` (3 guardians, threshold 2), checks the file and `cast call`s guardianCount / threshold / decimals / token↔bridge; output in a removed temp dir |
| `tools/export-abi.sh` | writes `../crates/hawkeye-eth/abi/*.json` (ABI + bytecode) from the build; `--check` in CI |
| `deployments/<chainid>.json` | written by `Deploy.s.sol`; anvil's (31337) is gitignored, public networks' are committed |

## Build and test

What CI's `contracts` job runs (native forge v1.7.1, which downloads native solc 0.8.37 as
`foundry.toml` asks):

```sh
cd eth
npm ci --ignore-scripts        # OpenZeppelin 5.6.1, forge-std v1.17.0, solc-js 0.8.37 (package-lock.json)
./tools/fetch-wyec.sh          # wyec @ pin -> vendor/wyec; idempotent, verifies the commit and checksums
forge fmt --check              # Hawkeye's own script/ and test/ only ([fmt] ignore: vendor, node_modules)
forge build --sizes
forge test -vvv                # also fails if vectors/eip712.json is stale
./tools/export-abi.sh --check  # crates/hawkeye-eth/abi/ matches this build
./tools/deploy-anvil-smoke.sh  # Deploy.s.sol on a throwaway anvil, read back with cast
```

**Restricted environments (opt-in).** Where the native solc download is blocked (this is how
the H3 work was done), point Foundry at the solc-js shim from `package.json`. It is the same
compiler version, so the bytecode is identical (the wYEC sizes match wyec-contract-design.md §8:
5,361 bytes bridge, 4,683 bytes token). Every command above works with it:

```sh
export FOUNDRY_SOLC=./tools/solc FOUNDRY_OFFLINE=true
```

Foundry itself can come from npm too (`@foundry-rs/forge`, `@foundry-rs/anvil`,
`@foundry-rs/cast`, 1.7.1) when its installer is blocked.

After a re-pin or a compiler change: `WRITE_VECTORS=true forge test --mc Eip712VectorsTest` and
`./tools/export-abi.sh`, then commit `vectors/eip712.json` and `crates/hawkeye-eth/abi/`. CI runs
`forge test` (which fails on stale vectors) and `./tools/export-abi.sh --check`.

## What the tests pin down

`test/WyecBridge.t.sol` (one test per assumption Hawkeye's engine makes):

- deployment order: bridge first with the predicted token address; the EIP-712 domain is
  `WyecBridge` / `1` / chain id / bridge;
- mint: 1-of-1, 2-of-3, 3-of-3; anyone may submit; `lockId` replay rejected even with other fields;
  signers strictly ascending (a swapped pair and a duplicated signature both fail
  `SignersNotAscending`); a non-guardian fails `NotGuardian(signer)`; below threshold fails
  `Threshold(got, need)`; tampering with amount, recipient or `lockId` fails; another deployment's
  signature fails; **high-S fails** (`ECDSAInvalidSignatureS`); minting to `address(0)` reverts and
  leaves the `lockId` unconsumed; the 21M cap;
- burn: `BurnToYcash(nonce, from, amount, ycashRecipient)` fields and topic layout, nonce
  increments, no allowance needed, over-balance reverts without spending a nonce, **a zero-amount
  burn succeeds and spends a nonce**;
- pause: stops `mint` and `burn`, not transfers; a no-op `setPaused` reverts without spending
  `adminNonce`; replayed admin signatures fail;
- rotation: `setGuardians` changes set and threshold, bumps the shared `adminNonce`, works while
  paused; a removed guardian's signature stops counting; **mint signatures carry no nonce** and
  survive a rotation as long as their signers remain guardians;
- `setBridge`: the old bridge can no longer mint or burn; balances are untouched; zero rejected;
- the token: `decimals() = 8`, `CAP = 21,000,000 × 10^8`, only the bridge mints and burns.

## Anvil runbook

```sh
export FOUNDRY_SOLC=./tools/solc FOUNDRY_OFFLINE=true  # only where solc cannot be downloaded
anvil --slots-in-an-epoch 1 &                          # finalized = latest - 2 (default: latest - 64)
GUARDIANS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC \
THRESHOLD=1 forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil account 0
cat deployments/31337.json
kill %1
```

On a fresh anvil this gives bridge `0x5FbDB2315678afecb367f032d93F642f64180aa3` (block 1) and
token `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` (block 2), and writes:

```json
{
  "bridge": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "chainId": 31337,
  "challengeWindow": 0,
  "deployBlock": 1,
  "guardians": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"],
  "mintMode": "threshold",
  "threshold": 1,
  "token": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
}
```

`deployBlock` is head + 1 at script time: exact on an automining anvil, a safe lower bound for the
scanner anywhere else. `MINT_MODE=optimistic CHALLENGE_WINDOW=<seconds>` deploys the CR-W1 test
double instead; the script refuses it on any chain id but 31337. `DEPLOYMENT_FILE=<path>` overrides
the output path (inside `deployments/`, Foundry's `fs_permissions`).

anvil 1.7.1's block tags: `safe = latest − slots_in_an_epoch`, `finalized = latest −
2 × slots_in_an_epoch` (default 32). The `hawkeye-eth` integration tests start their own anvil with
`--slots-in-an-epoch 1` and deploy from `crates/hawkeye-eth/abi/` without Foundry.

## Sepolia runbook (H7; Sepolia is not reachable from the H3 build container, so not yet run)

Prerequisites: a funded deployer key; the guardian addresses, derived from the Ycash set members'
compressed keys (`keccak256(uncompressed pubkey)[12:]`; `hawkeye keys eth-address --set <setid>`
once the CLI exists, H5); `THRESHOLD = 1` for the Sepolia devnet (plan §0 item 4, §2).

```sh
cd eth && ./tools/fetch-wyec.sh && npm ci
export SEPOLIA_RPC_URL=... DEPLOYER_KEY=... ETHERSCAN_API_KEY=...
# dry run first: simulates against Sepolia state, predicts both addresses, sends nothing
GUARDIANS=0x..,0x..,0x.. THRESHOLD=1 forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY
# then broadcast and verify
GUARDIANS=0x..,0x..,0x.. THRESHOLD=1 forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --verify \
    --etherscan-api-key $ETHERSCAN_API_KEY
cat deployments/11155111.json      # {chainId, bridge, token, deployBlock, guardians, threshold, ...}
```

- The deployer must send nothing else between the two transactions (the token's address is
  predicted from the deployer's nonce; a fresh deployer key is the simple way). The script asserts
  the prediction; if it fails mid-broadcast, the bridge is unusable: redeploy both with a fresh key.
- Check before announcing: `cast call <bridge> "token()(address)"`, `cast call <token>
  "bridge()(address)"`, `cast call <bridge> "threshold()(uint8)"`, `guardians(uint256)` for each
  index, and that both contracts are verified on Etherscan.
- Commit `deployments/11155111.json` and `broadcast/Deploy.s.sol/11155111/run-latest.json`, then
  point `config/sepolia.toml` at them (bridge, token, deploy block as the scanner start) and run
  `hawkeye --config config/sepolia.toml status`.
- Never deploy the optimistic double to Sepolia; it is not the contract of record. A CR-W1 Sepolia
  deployment waits for wyec to ship the real optimistic mint.
