# Hawkeye

**The attestor sidecar for the Ycash bridges: the wYEC bridge to Ethereum and the nYEC bridge to
NEAR.** Both mint wYEC, wrapped YEC backed 1:1 by YEC locked in vaults.

Hawkeye is part of [Ycash vaults and Yellowback](https://github.com/boyfromcave/yellowback), a
proposed Ycash network upgrade that adds vaults: YEC locked under rules every node checks. Each
bridge attestor runs Hawkeye next to its own `ycashd` and an Ethereum or NEAR endpoint. The name is
the job: an attestor watches both chains like a hawk.

> **Status: in development.** Runs on regtest and on a one-laptop devnet against both node lines.
> Not audited, not deployed, and no bridge exists on mainnet.

## What it does

- **Lock → mint.** A depositor locks YEC in a vault tagged for the bridge (`WYEC` or `NYEC`).
  Hawkeye sees the confirmed lock and mints the same amount on the other chain: an EIP-712
  attestation for the Ethereum contract, a signed attestation for the `wyec-near` contract.
- **Burn → release.** A holder burns wYEC on Ethereum or NEAR. Hawkeye turns the finalized burn into a
  delayed release of the YEC on Ycash, to a transparent or a post-quantum address (`sq…`).
- **Watch everyone.** One attestor proposes, the others check. Anything Hawkeye cannot match is
  challenged or cancelled during the challenge window, and the attestor who signed it is slashed:
  its bond is frozen on Ycash.
- **Stay live.** Hawkeye sends heartbeats so the signer set stays live. If the whole set ever goes
  silent, depositors take their YEC back with `hawkeye recover`.

Ycash never reads Ethereum or NEAR. The vault rules on Ycash protect the YEC; Hawkeye and its
challenges protect the wrapped token. The design is
**one attestation, a challenge window, and slashing**: see the plan of record,
[`docs/hawkeye-bridge-plan.md`](docs/hawkeye-bridge-plan.md), and the NEAR plan,
[`docs/hawkeye-near-plan.md`](docs/hawkeye-near-plan.md).

## Keys: post-quantum owners, secp256k1 attestors

- **Vault owners are post-quantum.** Every bridge vault's owner is an SLH-DSA key (the owner slot
  ends in `OP_CHECKPQSIG`), and the lock policy mints only for SLH-DSA owners. Hawkeye holds no
  owner key and no post-quantum code: `hawkeye lock` asks the node for an owner
  (`vault_getnewowner`, or `--owner <address | pqkeyid>`), and the depositor's node signs the
  recovery.
- **Attestor keys stay secp256k1.** Each attestor has one member key: its seat in the Ycash signer
  set, its bond, and its guardian key on Ethereum or NEAR. The contracts still verify ordinary
  EC signatures (EIP-712, NEAR `ecrecover`).

Addresses: post-quantum Yellowback owner addresses are `yb…` on mainnet (`yt…` testnet, `yr…`
regtest); plain-YEC post-quantum addresses are `sq…` / `tq…` / `rq…`.

## Joining and leaving the signer set

An attestor posts a YEC bond to take a seat. The bond is locked for as long as the attestor is a
member, and slashable.

Leaving takes two steps and at least **14 days**:

1. **`hawkeye leave`** (stop the daemon first). The member removes itself from the set. From the
   next block its bond is in the **exit delay**: the set's `maturity`, at least **16,128 blocks
   (14 days)** on mainnet and testnet. The command prints when the bond becomes spendable.
2. **`hawkeye withdraw-bond [--to <address>]`** after the delay. Hawkeye signs the bond spend with
   the member key; the node refuses it one block early, or if the bond was frozen.

A member in its exit delay can still be slashed for anything it signed while it was a member, so
leaving right after a fault does not escape it. A key cannot rejoin while its old bond is unspent.

**Guardians are rotated off-chain.** Leaving the Ycash set does not touch the Ethereum or NEAR
contract: rotate the member's guardian key out of the contract in the same governance round
(`setGuardians` on Ethereum, `set_guardians` on NEAR). Until then Hawkeye's guardian-drift alarm reports the mismatch.

## Commands

| Command | Who | What |
|---|---|---|
| `hawkeye run` | attestor | the daemon: attest, watch, heartbeat, serve the API |
| `hawkeye status [--json]` | anyone | the ledger, the node and the other chain at a glance |
| `hawkeye enroll` | attestor | import the member key into the node wallet (no rescan) |
| `hawkeye keys derive --secret <hex>` | attestor | print the member key, its Ethereum address and NEAR guardian key |
| `hawkeye lock <YEC> --dest <account>` | depositor | lock YEC for the bridge, minting to an Ethereum address or NEAR account |
| `hawkeye burn <YEC> --recipient <address>` | holder | burn wYEC to a Ycash address (transparent or `sq…`) |
| `hawkeye recover` | depositor | reclaim every bridge vault this wallet owns, once its owner path opens |
| `hawkeye leave` | attestor | leave the signer set; the bond enters the 14-day exit delay |
| `hawkeye withdraw-bond` | attestor | spend the bond after the exit delay |

`rogue-unlock` and `rogue-mint` exist for devnet drills only and are refused on mainnet.

## Node requirement

Hawkeye needs `upgrade/vault` nodes, on either node line
([ycash-dd](https://github.com/boyfromcave/ycash-dd) or
[ycash6](https://github.com/boyfromcave/ycash6)), which carry the post-quantum layer (built on
`upgrade/quantum-vaults`, merged into `upgrade/vault`): the vault upgrade (branch ID `0x6d5b7a31`)
and `rpcversion` 8 (`yed_getinfo`; 5 was the vault upgrade, 7 post-quantum owners, 8 the fee
rules). It parses only the post-quantum owner shape, so a node from before the post-quantum layer
(`rpcversion` below 7) has no vault this Hawkeye recognises. The workspace's agent rules
(`AGENTS.md` rule 2, in [yellowback](https://github.com/boyfromcave/yellowback)) state the same
`rpcversion` for every client; keep the two in step.

Hawkeye reaches `ycashd` only through stock RPCs and the vault primitive's `set_*` / `vault_*`
RPCs (never `yed_*`), and Ethereum and NEAR only through their standard JSON-RPC. It never needs a
node change.

## Build and try it

```bash
cargo build --locked && make test      # make test = cargo test, failing (not skipping) without anvil
cd eth && ./tools/fetch-wyec.sh && forge test
```

The Ethereum-backed Rust suites need `anvil` on PATH; without it they print `SKIPPED` and pass
vacuously, which `make test` (and CI, `HAWKEYE_REQUIRE_ANVIL=1`) turns into a failure.

The Ethereum contracts come from [wyec](https://github.com/boyfromcave/wyec) at a pinned commit
(`eth/tools/fetch-wyec.sh`). To see the whole bridge work on one machine, real regtest nodes, anvil
(or a NEAR sandbox) and three Hawkeyes, follow [`devnet/README.md`](devnet/README.md):

```bash
devnet/hawkeye-devnet scenario demo --fresh                  # Ethereum
devnet/hawkeye-devnet scenario demo --fresh --foreign near   # NEAR
```

## Layout

| Path | What |
|---|---|
| `crates/hawkeye-core` | pure encodings and rules: templates, memo, recipient, lockId, EIP-712, policy, matching |
| `crates/hawkeye-ycash` | `ycashd` JSON-RPC client (`set_*`, `vault_*`, stock), v4 transaction codec, mock node |
| `crates/hawkeye-eth` | Ethereum adapter: bindings, finalized scanner, signer, mint submitter |
| `crates/hawkeye-near` | NEAR adapter: JSON-RPC client, Borsh transaction codec, `wyec-near` client and scanner, mock NEAR node |
| `crates/hawkeye-store` | SQLite ledger, sign-once records, evidence |
| `crates/hawkeye` | the daemon and CLI (`[foreign] kind = "ethereum"` or `"near"`) |
| `eth/` | Foundry project: wyec at a pinned commit, deploy scripts (anvil, Sepolia), vectors |
| `near/` | the `wyec-near` contract (NEP-141 token and bridge policy), its own cargo project |
| `config/` | sample configs: `ethereum-anvil.example.toml`, `near-sandbox.example.toml` |
| `devnet/` | regtest `ycashd` + anvil or a NEAR sandbox + several Hawkeyes, and the scenario drills |

## Contributing

Read [`AGENTS.md`](AGENTS.md) first. Every encoding has golden vectors, everything that signs goes
through the sign-once records, and anything tested against one node line is tested against the
other. Naming: Yellowback is the system, YED the unit, YEC the coin, wYEC the wrapped token.

## License

MIT.
