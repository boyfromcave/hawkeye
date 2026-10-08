# `eth/`: Hawkeye's Foundry project

What Hawkeye needs on the Ethereum side (plan §6, §7, phase H3), built against the wYEC contracts
at a **pinned commit**, which are fetched and never copied in (AGENTS.md rule 2):

| Path | What |
|---|---|
| `tools/fetch-wyec.sh` | fetches `boyfromcave/wyec` @ `cad126a415bdb5e0ae9cf7d05f6bd1b512267efb` (main, the merge of PR #1: CR-W1 optimistic mint and rate limit, CR-W2, CR-W3) into `vendor/wyec` (gitignored), verifies the commit and records file checksums; `WYEC_SRC=<clone>` to export from a local clone instead |
| `package.json` | pinned dependencies: `@openzeppelin/contracts` 5.6.1 (wyec's compile check), `forge-std` v1.17.0 (git commit `f3dae6e`), `solc` 0.8.37 (solc-js, only for the shim) |
| `foundry.toml` | `src` = `vendor/wyec/contracts`, solc 0.8.37, optimizer 200 runs (as wyec's `compile.js`), remappings `@openzeppelin/contracts/`, `forge-std/`, `wyec/` |
| `tools/solc`, `tools/solc-shim.js` | a native-`solc` stand-in over solc-js, for machines where Foundry cannot download the compiler |
| `test/WyecBridge.t.sol` | Hawkeye's assumptions about the contract: deployment, threshold mint, burn, pause, rotation, hand-off (below) |
| `test/OptimisticMint.t.sol` | Hawkeye's assumptions about the optimistic mint it drives (below) |
| `test/Vectors.t.sol` → `vectors/eip712.json` | EIP-712 golden vectors; format in `vectors/README.md` |
| `test/Deploy.t.sol`, `script/Deploy.s.sol` | the predicted-address deployment and its output file |
| `tools/deploy-anvil-smoke.sh` | CI smoke test: anvil on a free port, `Deploy.s.sol --broadcast` (3 guardians, threshold 2, 12 s window, 1000 wYEC/day cap), checks the file and `cast call`s guardianCount / threshold / challengeWindow / mintCap / capWindow / decimals / token↔bridge; output in a removed temp dir |
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
compiler version, so the bytecode is identical (the wYEC sizes match wyec-contract-design.md §4.5.5:
9,446 bytes bridge, 4,683 bytes token). Every command above works with it:

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
- the token: `decimals() = 8`, `CAP = 21,000,000 × 10^8`, only the bridge mints and burns;
- the constructor: a zero challenge window and a cap without a window are refused; `setMintLimit`
  shares the `adminNonce`.

`test/OptimisticMint.t.sol` (the optimistic path, wyec-contract-design.md §4.5, as the engine drives
it):

- both digests (`Mint`, `Challenge(bytes32 lockId,uint256 proposalId)`) are Hawkeye's encoding;
- `proposeMint`: one guardian's signature over the threshold path's `Mint` digest, **any submitter**
  (the proposer is the signer); ids start at 1 and increase; `MintProposed` / `MintChallenged`
  topic and data layout; non-guardian, zero recipient, zero amount, tampered fields and a consumed
  lock are refused; **one live proposal per lock, even a matching one** (`ProposalPending`, also
  once Ready);
- `challengeMint`: any guardian's `Challenge` signature, any submitter (guardians need no ETH); the
  lock is not consumed; wrong id, no proposal and a non-guardian are refused; **the challenged
  proposer is `vetoed` for that lock** (its public signature cannot be replayed), another guardian
  re-proposes with a fresh id that the old challenge cannot touch; a guardian may challenge its own;
- `executeMint`: anyone, at `eta`; `Minted` is the threshold path's event; challenge and execute
  race from `eta` on; a proposer rotated out leaves a `Void` proposal that any guardian replaces;
- a threshold `mint` clears a pending proposal; a proposer's signature also counts towards a
  threshold mint; pause stops propose and execute, never challenge;
- the rate limit applies at execute: over the budget the proposal stays `Ready` and executes in a
  later window;
- **why the mainnet rule is threshold ≥ 2 in every mode**: at threshold 1 one key mints through
  `mint` at once.

## Anvil runbook

```sh
export FOUNDRY_SOLC=./tools/solc FOUNDRY_OFFLINE=true  # only where solc cannot be downloaded
anvil --slots-in-an-epoch 1 &                          # finalized = latest - 2 (default: latest - 64)
GUARDIANS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC \
THRESHOLD=2 CHALLENGE_WINDOW=60 forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
    --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil account 0
cat deployments/31337.json
kill %1
```

On a fresh anvil this gives bridge `0x5FbDB2315678afecb367f032d93F642f64180aa3` (block 1) and
token `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` (block 2), and writes:

```json
{
  "bridge": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "capWindow": 0,
  "chainId": 31337,
  "challengeWindow": 60,
  "deployBlock": 1,
  "guardians": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"],
  "mintCap": 0,
  "mintMode": "optimistic",
  "threshold": 2,
  "token": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
}
```

`deployBlock` is head + 1 at script time: exact on an automining anvil, a safe lower bound for the
scanner anywhere else. Environment: `GUARDIANS`, `THRESHOLD` (≥ 2 on mainnet, refused otherwise:
plan §3.3), `CHALLENGE_WINDOW` (required, seconds, immutable), `MINT_CAP` / `CAP_WINDOW` (the
rate limit, default none), `MINT_MODE` (`optimistic`, the default, or `threshold`: only recorded as
`mintMode` for the attestors' configs — one `WyecBridge` serves both). The checks are wyec's own
`script/Deploy.s.sol`'s at the pin; Hawkeye keeps its own script for `mintMode` and the in-process
`Config` its tests and the devnet use. `DEPLOYMENT_FILE=<path>` overrides the output path (inside
`deployments/`, Foundry's `fs_permissions`).

anvil 1.7.1's block tags: `safe = latest − slots_in_an_epoch`, `finalized = latest −
2 × slots_in_an_epoch` (default 32). The `hawkeye-eth` integration tests start their own anvil with
`--slots-in-an-epoch 1` and deploy from `crates/hawkeye-eth/abi/` without Foundry.

## Sepolia runbook (H7; Sepolia is not reachable from the H3 build container, so not yet run)

Prerequisites: a funded deployer key; the guardian addresses, derived from the Ycash set members'
compressed keys (`keccak256(uncompressed pubkey)[12:]`; `hawkeye keys eth-address --set <setid>`
once the CLI exists, H5); `THRESHOLD = 2` and the optimistic mode (plan §3.3: the mainnet rule,
rehearsed on Sepolia), a `CHALLENGE_WINDOW` longer than Sepolia's finality plus detection (e.g.
1800 s; wyec-contract-design.md §4.5.3).

```sh
cd eth && ./tools/fetch-wyec.sh && npm ci
export SEPOLIA_RPC_URL=... DEPLOYER_KEY=... ETHERSCAN_API_KEY=...
# dry run first: simulates against Sepolia state, predicts both addresses, sends nothing
GUARDIANS=0x..,0x..,0x.. THRESHOLD=2 CHALLENGE_WINDOW=1800 forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY
# then broadcast and verify
GUARDIANS=0x..,0x..,0x.. THRESHOLD=2 CHALLENGE_WINDOW=1800 forge script script/Deploy.s.sol \
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
- The bridge is the contract of record (wyec @ the pin, with the optimistic mint since `cad126a`);
  there is no separate optimistic variant to deploy.
