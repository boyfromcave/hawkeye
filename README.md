# Hawkeye

The attestor sidecar for the **wYEC bridge** between Ycash and Ethereum. Each bridge attestor runs
Hawkeye next to its own `ycashd` (the vault upgrade, `UPGRADE_VAULT` / branch ID `0x6d5b7a31`) and
an Ethereum endpoint. The name is the job: an attestor watches Ethereum like a hawk for wYEC
burns, and watches Ycash just as closely for any release that no burn paid for. Hawkeye:

- turns confirmed `WYEC` locks on Ycash into wYEC mints on Ethereum (EIP-712 attestations),
- turns finalized `BurnToYcash` events on Ethereum into delayed-release intents on Ycash,
- watches every other attestor: it cancels what it cannot match during the challenge window, and
  co-signs slashing of the attestor who signed it,
- heartbeats so the signer set stays live; depositors recover their YEC if it ever goes silent.

The Foundation's model is **one attestation, a challenge window, and slashing**: see
[`docs/hawkeye-bridge-plan.md`](docs/hawkeye-bridge-plan.md), the plan of record.

## Layout

| Path | What |
|---|---|
| `crates/hawkeye-core` | pure encodings and rules: templates, memo, recipient, lockId, EIP-712, policy, matching |
| `crates/hawkeye-ycash` | ycashd JSON-RPC client (`set_*`, `vault_*`, stock), v4 tx codec, mock node |
| `crates/hawkeye-eth` | Ethereum adapter (alloy): bindings, finalized scanner, signer, mint submitter |
| `crates/hawkeye-store` | SQLite ledger, sign-once records, evidence |
| `crates/hawkeye` | the daemon and CLI |
| `eth/` | Foundry project: wyec at a pinned commit, deploy scripts (anvil, Sepolia), vectors |
| `devnet/` | regtest `ycashd` + anvil + several Hawkeyes, scenario drills |

## Build

```
cargo build --locked && cargo test --locked
cd eth && ./tools/fetch-wyec.sh && forge test
```
