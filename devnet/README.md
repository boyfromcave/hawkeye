# `devnet/`: Hawkeye beside real `ycashd` (plan phase H6)

`hawkeye-devnet` starts a self-contained bridge devnet on one machine and proves the owner's
success criterion (plan §9): **Hawkeye runs as a sidecar next to a real `ycashd`.**

```
node0  ycashd (regtest)  user: miner, depositor (lock), wYEC holder (burn)      node0.toml
node1  ycashd ◀── hawkeye (attestor1.toml, api 127.0.0.1:7801) ──┐
node2  ycashd ◀── hawkeye (attestor2.toml, api 127.0.0.1:7802) ──┼──▶ anvil (31337): WyecBridge + WrappedYcash
node3  ycashd ◀── hawkeye (attestor3.toml, api 127.0.0.1:7803) ──┘     guardians = the members' Ethereum addresses
```

The bridge is wyec at the pin in `eth/tools/fetch-wyec.sh` (`cad126a`), deployed with **threshold
2** and a **12 s challenge window**, and the attestors run **`mint_mode = "optimistic"`**, the
Foundation's model (plan §3.3): the mint leader proposes with its own `Mint` signature
(`proposeMint`), every other attestor checks the proposal against its own ledger and challenges one
it cannot match (`challengeMint`, an EIP-712 `Challenge` signature), and after the window the leader
(or anyone) executes it. `--mint-mode threshold` runs the k-of-n mint instead (k = 2, signatures
gathered from the peers' APIs); `--challenge-window N` changes the window. Both are `up` / `scenario`
options.

Each Hawkeye talks only to its own node's RPC and to anvil (AGENTS.md rule 1). The nodes are
regtest `ycashd` built from `ycash-dd` `upgrade/vault`, the vault upgrade activated with
`-nuparams=6d5b7a31:<h>`. The commands mirror `bridge-sim`'s (ycash-dd
`contrib/yellowback/devnet/bridge-sim`), whose set-up logic this follows: set creation, closed-set
joins co-signed by the admit key, several funding coins per wallet, the lock transaction.

The script is Python 3 standard library only. It also needs Foundry (`anvil`, `forge`, `cast`) on
`PATH`.

## Prerequisites

### 1. `ycashd` from `ycash-dd` `upgrade/vault` (built outside this repository)

Hawkeye never patches the node. Build it the way CI does
(`ycash-dd/.github/workflows/yellowback-tests.yml`, job `build`):

```sh
git clone https://github.com/boyfromcave/ycash-dd -b upgrade/vault ycash-build && cd ycash-build
BUILD_STAGE=depends ./zcutil/build.sh -j3          # depends (about 25 min)
host=$(./depends/config.guess)
./autogen.sh
CONFIG_SITE="$PWD/depends/$host/share/config.site" ./configure
make -C src -j3 ycashd ycash-cli                    # about 25 min
export YCASHD=$PWD/src/ycashd YCASH_CLI=$PWD/src/ycash-cli
```

`configure` needs `hexdump` (`apt-get install bsdextrautils` on minimal images).

**Behind a restrictive egress proxy** (this is how the H6 container was built), some depends
hosts are refused: `boostorg.jfrog.io`, `download.libsodium.org`, `deb.debian.org`,
`download.z.cash` (the depends fallback and the params host), and GitHub `/archive/` codeload
tarballs. Pre-seed `depends/sources/` with substitutes under the expected file names, and write a
matching `depends/sources/download-stamps/.stamp_fetched-<pkg>-<file>.hash` (`sha256sum` output)
for each one, or `check-sources` deletes them:

| package | substitute | hash |
|---|---|---|
| boost, native_b2 | `downloads.sourceforge.net/project/boost/boost/1.83.0/boost_1_83_0.tar.bz2` | matches |
| libsodium | `github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz` | matches |
| libevent, utfcpp, googletest | `git clone` the tag, then `git archive --prefix=<dir>/ <tag> \| gzip -n -9` | differs: edit `sha256_hash` in `depends/packages/<pkg>.mk` |
| native_libtinfo5 | `archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/libtinfo5_6.2-0ubuntu2.1_amd64.deb` | differs: edit the `.mk` |

The four `.mk` hash edits are the only change. The result reports itself as `-dirty`, and no
`src/` file is touched.

### 2. zk parameters in `~/.zcash-params`

`ycashd` aborts at start-up without `sapling-spend.params`, `sapling-output.params` and
`sprout-groth16.params`. Use `zcutil/fetch-params.sh`. If `download.z.cash` is blocked, these
sources are sha256-identical to the hashes in `fetch-params.sh`:

- `sapling-spend.params`: the concatenation of `src/sapling-spend-{1..5}.params` from the
  crates.io crates `wagyu-zcash-parameters-{1..5}` v0.2.0
- `sapling-output.params`: `src/sapling-output-1.params` from `wagyu-zcash-parameters-6` v0.2.0
- `sprout-groth16.params`: `github.com/PirateNetwork/zcash_params/releases/download/release_bd4e9a3/sprout-groth16.params`

### 3. The contracts and Foundry

```sh
cd eth && ./tools/fetch-wyec.sh && npm ci --ignore-scripts && cd ..
```

`up` deploys with `forge script script/Deploy.s.sol`. If `FOUNDRY_SOLC` is unset and
`eth/tools/solc` exists, the devnet points forge at the solc-js shim
(`FOUNDRY_SOLC=./tools/solc FOUNDRY_OFFLINE=true`, eth/README.md). It is the same compiler
version and gives the same bytecode. To use native solc instead, set `DEVNET_NATIVE_SOLC=1`.

### 4. The daemon

```sh
cargo build --locked -p hawkeye          # target/debug/hawkeye; or HAWKEYE=/path/to/hawkeye
```

## Commands

```sh
export YCASHD=... YCASH_CLI=...          # the node binaries; default: ycashd / ycash-cli on PATH
# DEVNET_NODE_LINE=ycash-dd|ycash6       # optional: the node line; default: read from `ycashd -version`
devnet/hawkeye-devnet up [--attestors 3] [--dir devnet/run] [--activation 110] [--interval 2] \
                         [--mint-mode optimistic|threshold] [--challenge-window 12]
devnet/hawkeye-devnet status [--json]
devnet/hawkeye-devnet lock 10 [--dest 0x<holder>] [--owner-age N]  # node0 → WYEC vault + dest OP_RETURN
devnet/hawkeye-devnet burn 4 [--recipient <node0 t-addr>]
devnet/hawkeye-devnet rogue 1 [--attestor 1]            # drill D-2: an unlock with no burn
devnet/hawkeye-devnet rogue-mint 5 [--attestor 1] [--to 0x..]   # drill D-5: a proposal with no lock
devnet/hawkeye-devnet silence 2 | unsilence 2           # stop / restart attestor2's hawkeye
devnet/hawkeye-devnet mine 5 | pause | resume           # blocks now; the background miner
devnet/hawkeye-devnet heartbeat                         # SET_HEARTBEAT from every attestor node (by hand)
devnet/hawkeye-devnet cli 2 set_getinfo <setid>         # ycash-cli against node2
devnet/hawkeye-devnet logs [-n 50] [-f]
devnet/hawkeye-devnet down                              # stop everything, keep the directory
devnet/hawkeye-devnet up                                # on a stopped devnet: resume it
devnet/hawkeye-devnet clean                             # remove the stopped run directory
devnet/hawkeye-devnet scenario demo [--fresh] [--keep]  # the end-to-end proof, below
devnet/hawkeye-devnet scenario roll [--fresh] [--keep]  # drill D-13: a vault rolled before ownerHeight (HK-6)
devnet/hawkeye-devnet scenario dormancy|takeover|double|restart|reorg|rogue-mint [--fresh]
                                                        # drills D-11, D-7, D-3, D-16, D-9/D-10, D-5
```

`--dir` (or `$HAWKEYE_DEVNET_DIR`) works before or after the command. `devnet/run` is gitignored.

### Both node lines

The same script drives `ycash-dd` (v4.5.0) and `ycash6` (6.2x) `upgrade/vault` nodes. It reads the
line from `ycashd -version` (major version 6 or above is `ycash6`), or from `DEVNET_NODE_LINE`,
records it in `devnet.json`, and passes that line's extra start-up arguments the way its qa harness
does: none on `ycash-dd`, and `-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025` on
`ycash6`. `ycash6` needs no zk parameters. On `ycash6`, `set_heartbeat` is refused with -4 ("this
wallet holds no current member key of the set") while the member's `SET_JOIN` is still in the mempool,
so `heartbeat` first waits for every join to confirm, on both lines. Hawkeye itself heartbeats only
as a current member, so it is not affected.

### What `up` does

1. Starts N+1 regtest nodes on `127.0.0.1`. Node *i* uses p2p port `base+2i` and RPC port
   `base+2i+1` (`--base-port`, default 18400), with `rpcuser=u rpcpassword=p`, `txindex=1`, and
   the six upgrade `-nuparams` at 1 plus `-nuparams=6d5b7a31:<activation>`. Without the four
   Ycash upgrades, plain regtest's `getblocktemplate` aborts at height 150 or above. The nodes are
   peered with each other.
2. node0 mines to `activation + 101`, which is past activation and coinbase maturity, and checks
   `vault_getinfo.active`.
3. Generates one random secret per attestor. It derives the member key (compressed secp256k1)
   and the Ethereum address (`keccak256(pubkey)[12:]`). It uses `hawkeye keys derive --secret`
   when the binary has it and cross-checks that output against its own derivation. It also
   generates a holder secret: node0's Ethereum persona.
4. Funds each attestor wallet with 8 coins of 2.5 YEC. Every act and unlock spends a whole
   confirmed coin (finding (76)).
5. `set_create` on node0 with the plan §2 regtest row: seats N, unlock 1, cancel 1, slash
   max(1, N−1), rate 5000 bps / 20, liveness 60, maturity 2, bondmin 1, bondlockmin 50.
   `SET_REMOVE` needs `slashThreshold` current members *other than the target*, so with 3
   attestors the slash threshold is 2. node0 holds the admit key.
6. Starts anvil (`--slots-in-an-epoch 1`, so finalized = latest − 2; `--block-time 1`; state
   kept in `anvil-state.json` across `down`/`up`). Deploys wYEC with `GUARDIANS` set to the
   attestors' addresses, `THRESHOLD=2`, `CHALLENGE_WINDOW=12` and `MINT_MODE` (recorded as
   `mintMode`), and reads `challengeWindow()` and `threshold()` back. The output file goes to
   `<run>/deployments/31337.json`. Funds the attestors and the holder with 1000 ETH each
   (`anvil_setBalance`).
7. Writes `<run>/attestor<i>.toml` (the contract below) and `<run>/node0.toml`, then enrols each
   member key in its attestor's own node wallet: `hawkeye --config attestor<i>.toml enroll`, or
   `importprivkey <WIF> "hawkeye-member" false` as the fallback (regtest WIF prefix 0xEF). Checks that the
   wallet holds the key.
8. Joins: `set_join <setid> 1 <tip+5001> <memberkey>` on each attestor node. Because the set is
   closed, each join is co-signed with the admit key (`set_signact` on node0) and then sent with
   `set_sendact` on the attestor node. All joins land before any of them matures, so the admit key
   covers all of them. Mines `1 + maturity` blocks and checks that every member is current.
9. Starts `hawkeye --config <run>/attestor<i>.toml run` beside each attestor node, each in its
   own process group, with its log in `<run>/attestor<i>/hawkeye.log`. Then starts the
   background miner: node0 mines 1 block every `--interval` seconds; `pause` / `resume`.

`up` refuses if anything of that devnet is still running. Every process gets its own session,
and its pid is recorded in `<run>/devnet.json`. `down` stops the nodes with RPC `stop`, then
SIGTERM and SIGKILL on each process group, and fails if anything is left. If `up` fails, it runs
`down` itself.

### The config contract (`attestor<i>.toml`)

```toml
[network]  name = "regtest"
[ycash]    rpc_url = "http://127.0.0.1:<node i rpc>"  rpc_user = "u"  rpc_password = "p"
[eth]      rpc_url = "http://127.0.0.1:18545"  deployment = "<run>/deployments/31337.json"  finality = "finalized"
[bridge]   set_id = "<display hex>"  delay = 6  confirmations = 2  min_owner_age = 400  roll_margin = 50
           takeover_blocks = 4  heartbeat_blocks = 10  min_lock = "0.1"  max_lock = "1000"
           mint_mode = "optimistic"  mint_threshold = 2      # --mint-mode threshold: k = 2
[keys]     secret_hex = "<hex32>"
[store]    path = "<run>/attestor<i>/hawkeye.db"
[api]      listen = "127.0.0.1:<7800+i>"
[policy]   auto_slash = true
[peers]    urls = [the other attestors' http://api URLs]
[devnet]   drills = true
[log]      level = "info"  format = "text"
```

`node0.toml` has the same shape but points at node0, with `api` 127.0.0.1:7800. Its
`[keys] secret_hex` is the **holder's** Ethereum key. The depositor and the holder are one person
on two chains, so `hawkeye --config node0.toml lock` and `... burn` both use it. That key is never
imported into node0's wallet: the lock's owner key is a fresh node0 wallet key.

### lock / burn / rogue: the binary first, fallbacks until it has them

| Command | With the binary | Fallback (used while the subcommand is missing, or with `HAWKEYE_DEVNET_FALLBACK=1`) |
|---|---|---|
| `lock A [--dest]` | `hawkeye --config node0.toml lock A --dest <addr>` | Builds the WYEC V in Python (the §15.3 template, `ownerHeight = tip+1+min_owner_age+20`) plus the `OP_RETURN` with the ABI `bytes32` destination. Serialises a v4 transaction, then calls `signrawtransaction` and `sendrawtransaction` on node0, and checks the V with `vault_decodescript`. This is bridge-sim's `lock`. |
| `burn A [--recipient]` | `hawkeye --config node0.toml burn A --recipient <t-addr>` | `cast send <bridge> "burn(uint256,bytes32)"` with the holder key and the §4.2 `ycashRecipient` (`01 00 0…0 hash160`). |
| `rogue A` | `hawkeye --config attestor1.toml rogue-unlock A` (drill D-3: `rogue-unlock --replay-burn <nonce>`, below) | On node1: `vault_buildunlock` to a fresh node1 address, then `set_signunlock` (attestor1's member key alone meets `unlockthreshold 1`), then `vault_send`. No memo. |
| `rogue-mint A` | `hawkeye --config attestor1.toml rogue-mint A [--to] [--lock-id]`: signs `Mint(lockId, A, to)` for an invented lockId (sign-once drill record), `proposeMint` from its own account | none (needs the binary) |
| enrolment | `hawkeye --config … enroll` | `importprivkey` of the WIF. |
| key derivation | `hawkeye keys derive --secret <hex>` (cross-checked) | Python secp256k1, plus `cast wallet address`. |

The script detects a subcommand by checking whether `hawkeye [<parent>] --help` lists it.

## `scenario demo`: the end-to-end proof (plan §8 D-1 + D-2)

```sh
devnet/hawkeye-devnet scenario demo [--fresh] [--keep] [--timeout 180]
```

Each step is asserted, with a timeout:

1. `up` with 3 attestors.
2. `lock 10` from node0 to the holder, and wait for 1 confirmation.
3. **Mint:** wait until `cast call token balanceOf(holder)` equals `10e8` (optimistic: one
   proposal, no challenge, executed after the 12 s window; the transcript lists `proposalCount`
   and the attestors' `mint_proposed` / `mint_executed` lines).
4. `burn 4` to a fresh node0 t-address *R*.
5. **Intent:** wait for a `vault_list {"kind":"intent"}` row of 4 YEC with
   `recipienthash = SHA256(spk(R))`. Its transaction must carry an `HKB1` kind-1 memo (75-byte
   `6a49…` `OP_RETURN`, plan §4.3) naming chain 31337 and this bridge.
6. **Release:** wait until `getreceivedbyaddress(R, 1)` equals 4.
7. `rogue 1` by attestor1.
8. **Cancel:** wait until a transaction spends the rogue intent and pays back into a V. Its fee
   inputs must belong to an attestor other than attestor1, which the script checks with
   `validateaddress … ismine` on each attestor node.
9. **Slash:** wait until `set_getinfo` `memberlist` shows attestor1 with `status "removed"` and
   `bondfrozen true` (`SET_REMOVE burn=1`, co-signed by the 2 other attestors).
10. **Invariant:** `wYEC.totalSupply()` equals 6 YEC and is at most the WYEC value under the set.
11. `down`, unless `--keep`.

A passing run writes its transcript to `devnet/transcripts/demo-<date>-<line>-<version>.txt` (for
example `demo-2026-10-07-ycash6-v6.22.0-rc1.txt`), which is committed as evidence, one per node
line. A failing run writes `<run>/transcripts/demo-<date>-<line>-<version>-FAILED.txt`. The demo needs a
fresh directory: with `--fresh`, it cleans a *stopped* devnet first, and it never touches a
running one.

The node side of steps 7–9 has been checked by hand on this devnet, with the RPC calls Hawkeye's
engine makes (plan §5.3):

- On node2: `vault_buildcancel` → `set_signcancel` → `vault_send`, against a mempool-only rogue
  intent.
- `set_buildact remove {"burn": true}` on node2 → `set_signact` on node2 and node3 (2 of 2
  required) → `set_sendact`. Result: attestor1 `removed`, `bondfrozen: true`.

## `scenario roll`: drill D-13 (plan §3.1 HK-6)

```sh
devnet/hawkeye-devnet scenario roll [--fresh] [--keep] [--timeout 180]
```

`up` records `[bridge]` overrides in `devnet.json` and writes them into every `attestor<i>.toml`:
the drill uses `min_owner_age = 20` and `roll_margin = 40` (the other values as above).

1. `up` with those overrides.
2. `lock 10 --owner-age 400` (far from due); wait for its mint.
3. `lock 2 --owner-age 30`: policy-OK (30 ≥ 20) and already within `ROLL_MARGIN` (30 ≤ 40); wait
   for its mint (12 wYEC). Two vaults, so the roll fits the 5000 bps rate limit.
4. **Roll:** wait until the 2 YEC vault is spent by an unlock carrying an `HKB1` kind-2 memo whose
   `ref` (the new `ownerHeight`) is above the old one and whose `data` equals the intent's
   `recipientHash`.
5. **Release:** wait until the roll intent is spent into a V with `ownerHeight = ref` (a cancel would
   pay back into the old `ownerHeight`, and fails the drill), and the new vault is in `vault_list`.
6. No member lost its seat; `wYEC.totalSupply()` (12) ≤ the WYEC value under the set.

A passing run writes `devnet/transcripts/roll-<date>-<line>-<version>.txt`.

## The adversarial drills (plan §8)

```sh
devnet/hawkeye-devnet scenario <dormancy|takeover|double|restart|reorg|rogue-mint> [--fresh] [--keep] [--timeout 180]
```

Each drill is self-contained like the demo: `up` with 3 attestors, act, assert every step with a
timeout, `down`. A pass writes `devnet/transcripts/<drill>-<date>-<line>-<version>.txt`; a failure
writes `<run>/transcripts/<drill>-…-FAILED.txt`. Leaders are computed with the daemon's own rule
(plan §5.2: live members sorted by key; burn `n` → `live[n mod |live|]`, a mint → `lockId mod |live|`).

| Drill | Plan | What it does | Pass condition |
|---|---|---|---|
| `dormancy` | D-11, R1 | lock 10, mint; burn 4 and, the moment its intent appears, pause the miner and stop all three Hawkeyes; mine past `livenessWindow` (60) | `set_getinfo` `dormant` and `released`; `hawkeye --config node0.toml recover` spends the remaining vault **and the in-flight intent** with selector 3, node0's wallet gets 10 YEC back less fees; no WYEC output is left under the set. The 6 wYEC still outstanding are **unbacked by design** (the R1 trade-off, stated in the transcript) and every attestor's `hawkeye status` carries the `supply` alarm |
| `takeover` | D-7 | lock 10, mint; stop the leader of the next burn nonce *before* burning; burn 4 | another attestor logs `burn_takeover` and posts the intent; exactly one intent for the burn; released. The leader is restarted after the release: it catches up, adopts the release (`GET /burns/<n>` `RELEASED` with that intent, `release_adopted`) and logs no `unlock_signed` / `unlock_sent` for the nonce through three takeover rounds; nobody slashed |
| `double` | D-3 | lock 30, mint; burn 4 and wait for its release; then attestor1 runs `hawkeye rogue-unlock --replay-burn <nonce>`: a second unlock for the released burn, paying its recipient its amount, with the burn's own valid `HKB1` memo, more than `takeover_blocks` after the first | another attestor cancels it in its window; the watchers classify it `unmatched:consumed-burn` (never `benign-race`) and open a slash case; attestor1 `removed`, `bondfrozen`; the recipient was paid once. (30 YEC are locked so the 4 YEC replay fits the 5000 bps rate limit and only the watchers stop it.) |
| `restart` | D-16 | (A) pause the miner, lock 20, restart the mint leader with crash point `mint_signed` armed; (B) restart the next burn's leader with `unlock_signed` armed, burn 4; (C) burn 3 and `kill -9` its leader the moment it logs `unlock_signed` | (A) the leader aborts after recording its EIP-712 signature and before submitting; after the restart nothing is re-signed, minted once. (B) it aborts after recording the set signature, before broadcasting: no intent anywhere; restarted, it resends the stored bytes (`unlock_resend`), signs nothing again, one intent, released. (C) one intent, released, one `unlock_signed`. No `set-sign-once` refusal, no equivocation, no exposure; every ledger shows locks `MINTED` 1, burns and intents `RELEASED` 2, no slash case, no alarm |
| `rogue-mint` | D-5 | lock 10 and wait for its mint (one unchallenged proposal); then attestor1 runs `hawkeye rogue-mint 5`: one `Mint` signature over an invented lockId with no lock behind it, `proposeMint` from its own account (12 s window). Attestor1's own Hawkeye leaves its deliberate proposal to the others (`own_fraudulent_proposal`) | another attestor's `MintChallenged(lockId, proposalId)` lands before `eta` (read from anvil's logs: challenger, block time); after `eta` the proposal is gone (`proposalStatus` None, `consumed` false, `executeMint` reverts `NoProposal`), `vetoed[lockId][attestor1]` is set, no wYEC was minted (supply 10, the rogue recipient holds 0); the others open `FRAUDULENT_MINT` cases and attestor1 is `removed`, `bondfrozen`; the supply invariant holds |
| `reorg` | D-9, D-10 | anvil with `--slots-in-an-epoch 8` (finalized = latest − 16). (a) Pause the miner; lock 10 (the fallback builder, `nLockTime` = tip, sequence `0xfffffffe`), mine it at 1 confirmation (`C_Y` = 2); `invalidateblock` its *parent* on all nodes, so the lock is not final on the shorter chain and no mempool takes it back; mine a competing chain. Then re-broadcast the same lock. (b) Burn 4, then `anvil_reorg` it out before it is finalized; burn 4 again | (a) every Hawkeye logs `ycash_reorg … locks_deleted=1` and `GET /locks/<id>` is 404; no mint signature, no mint; after re-confirmation exactly one mint (`totalSupply` 10, every ledger `MINTED`). (b) the burn has no receipt, `burnNonce` is back; once finality passes the reorged blocks no ledger holds the nonce and no intent names it; the new burn reuses the nonce, its intent names the *new* tx hash, released once |

`[devnet] drills = true` (refused on mainnet) gates the drill-only daemon features: the
`rogue-unlock` command (with `--replay-burn <nonce>` for D-3), the `rogue-mint` command (D-5) and the
crash points armed by
`HAWKEYE_DRILL_CRASH_AT=unlock_signed|mint_signed` (the process aborts right after that signature is
recorded in the ledger, as a `kill -9` would; the devnet arms it by restarting that Hawkeye with the
variable set).

## Troubleshooting

- **`ycashd node<i> exited during start-up`**: read `<run>/ycash<i>/stdout.log`. Usually the zk
  parameters are missing (see Prerequisites §2). Loading them takes up to a minute per node on a
  busy machine; `up` waits up to 300 s.
- **`ports in use`**: another devnet, or something else, holds the ports. Pass `--base-port`,
  `--anvil-port`, or another `--dir`. The Hawkeye API ports 7801… are fixed by the contract.
- **`forge script failed`**: read `<run>/forge-deploy.log`. Without network access, use the shim
  (the default here) and make sure `eth/node_modules` and `eth/vendor/wyec` exist.
- **The set goes DORMANT**: `livenesswindow` is 60 blocks, about 2 minutes at the default
  `--interval 2`. Members stay live only through Hawkeye's heartbeats (`heartbeat_blocks` 10).
  Without running sidecars, `pause` the miner or send `heartbeat` by hand. That is drill D-11's
  pre-condition, not a bug.
- **A stopped devnet**: `up` resumes it: the nodes from their datadirs, anvil from
  `anvil-state.json`, the Hawkeyes from their SQLite stores. `clean` starts over.
- **Logs**: `hawkeye-devnet logs -f` tails the node `debug.log`s, anvil, forge, the miner and
  every `hawkeye.log`.
- **`corrupted size vs. prev_size` in `<run>/ycash0/stdout.log`** (ycash-dd v4.5.0): a glibc heap
  abort of node0 while `up` mines its 211 blocks, seen once in about 25 devnet runs of the H6 drill round; the
  node, not Hawkeye. `up` fails and goes down; run the scenario again.
- **Orphans**: `down` fails loudly if a recorded pid survives. `pgrep -af 'ycashd|anvil|hawkeye'`
  should print nothing afterwards.
