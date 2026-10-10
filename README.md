# Hawkeye

The attestor sidecar for the **wYEC bridge** between Ycash and Ethereum. Each bridge attestor runs
Hawkeye next to its own `ycashd` (the vault upgrade, `UPGRADE_VAULT` / branch ID `0x6d5b7a31`) and
an Ethereum endpoint. The name is the job: an attestor watches Ethereum like a hawk for wYEC
burns, and watches Ycash just as closely for cross-chain mints (implied by a user locking YEC
collateral in a vault). Hawkeye:

- turns confirmed YEC locks on Ycash — vaults carrying the bridge's application tag `WYEC` — into
  wYEC mints on Ethereum (EIP-712 attestations). The tag is opaque to consensus (no registered
  module: the generic vault primitive alone governs the YEC); Hawkeye uses it to tell bridge locks
  from every other vault,
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
| `crates/hawkeye-near` | NEAR adapter (NEAR plan NH4/NH5): JSON-RPC client, hand-rolled Borsh transaction codec (golden-vectored against `near-primitives`), relayer key, `wyec-near` client and block scanner, mock NEAR node, a test against a real sandbox (`tests/sandbox.rs`) and the devnet's set-up helper (`examples/near-admin.rs`) |
| `crates/hawkeye-store` | SQLite ledger, sign-once records, evidence (v4: chain-neutral accounts) |
| `crates/hawkeye` | the daemon and CLI (`[foreign] kind = "ethereum"` or `"near"`) |
| `eth/` | Foundry project: wyec at a pinned commit, deploy scripts (anvil, Sepolia), vectors |
| `near/` | the `wyec-near` contract (NEP-141 wYEC + bridge policy), its own cargo project; `tools/fetch-sandbox.sh` pins the NEAR sandbox node |
| `config/` | sample configs: `ethereum-anvil.example.toml`, `near-sandbox.example.toml` |
| `devnet/` | regtest `ycashd` + anvil (or, `--foreign near`, a NEAR sandbox) + several Hawkeyes, scenario drills |

## Build

```
cargo build --locked && cargo test --locked
cd eth && ./tools/fetch-wyec.sh && forge test
```
