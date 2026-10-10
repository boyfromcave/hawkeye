# wyec-near — Wrapped Ycash on NEAR

The NEAR side of the third vault application (`docs/hawkeye-near-plan.md`, phase NH2): one
contract that is both the **wYEC NEP-141 token** (with NEP-145 storage management and NEP-148
metadata: "Wrapped Ycash", `wYEC`, 8 decimals) and the **bridge policy**, mirroring the Ethereum
`WyecBridge` (wyec repo, `contracts/WyecBridge.sol`, `docs/wyec-contract-design.md` §4).
YEC locked on Ycash in `NYEC`-tagged vaults is minted here; wYEC burned here is released on Ycash.
Ycash consensus never reads NEAR, and this contract never reads Ycash (R2).

This is a standalone Cargo project (its own `[workspace]`): the Hawkeye workspace does not build it.

## Methods

| Method | Caller | Notes |
|---|---|---|
| `new(network_id, guardians, threshold, challenge_window_sec, mint_cap, cap_window_sec)` | deployer, once | `guardians`: hex of 64-byte uncompressed secp256k1 keys; `1 ≤ threshold ≤ len`; window > 0; `mint_cap` (U128 string) 0 = no limit, else `cap_window_sec` > 0 |
| `mint(lock_id, amount, receiver_id, sigs)` | anyone | threshold path; `sigs` ordered by **strictly ascending recovered public key**; more than `threshold` accepted; clears a pending proposal |
| `propose_mint(lock_id, amount, receiver_id, sig) → proposal_id` | anyone | one guardian's `Mint` signature; `eta = now + challenge_window_sec` |
| `challenge_mint(lock_id, proposal_id, sig)` | anyone | one guardian's `Challenge` signature; deletes the proposal, vetoes its proposer for that lock; works while paused |
| `execute_mint(lock_id)` | anyone | after `eta`, proposer still a guardian; rate limit applies |
| `burn(amount, ycash_recipient) → nonce` | holder | payable: ≥ 1 yocto **and** the record's storage cost (`burn_storage_deposit`), excess refunded |
| `set_guardians(guardians, threshold, sigs)`, `set_paused(paused, sigs)`, `set_mint_limit(mint_cap, cap_window_sec, sigs)` | anyone | threshold of the current set over the message with the shared `admin_nonce` |
| `ft_transfer`, `ft_transfer_call`, `ft_total_supply`, `ft_balance_of`, `ft_metadata`, `storage_*` | standard | NEP-141 / 145 / 148 (near-contract-standards) |
| views | anyone | `get_guardians`, `get_threshold`, `get_admin_nonce`, `is_paused`, `is_consumed`, `is_vetoed`, `get_proposal`, `proposal_status`, `get_burns(from_nonce, limit ≤ 100)`, `get_burn_count`, `burn_storage_deposit`, `mint_available`, `mint_digest`, `challenge_digest`, `config`, `contract_source_metadata` |

**Threshold signature ordering (the contract's choice; hawkeye-core leaves it here).** Every
`sigs` list (`mint` and the three admin acts) must be ordered by the **recovered 64-byte guardian
key, strictly ascending in lexicographic byte order** (`x ‖ y`, compared as unsigned bytes). This
is the Ethereum `WyecBridge` rule ("strictly ascending recovered address") restated for NEAR's
key identities: distinctness is one comparison per signature and a duplicated signature fails as
"not strictly ascending". The submitter (Hawkeye) recovers or knows each signer's key and sorts;
at least `threshold` signatures, more are accepted (each must be a current guardian).

Byte strings in JSON are lowercase-or-uppercase hex without `0x`: `lock_id` and `ycash_recipient`
32 bytes, guardian keys 64 bytes, signatures 65 bytes `r ‖ s ‖ v` (`v ∈ {0,1}`, low-S). Amounts are
zatoshi as NEP-141 `U128` strings.

**Digest** (plan §2.3): `SHA256("HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖
borsh(BridgeMessage))`, `contract_id = env::current_account_id()`. **Burn record** (plan §2.4):
`get_burns` returns each record with `record_hash = SHA256(borsh(BurnRecord))`, the `HKN1` memo's
`data`. Golden vectors: [`vectors/messages.json`](vectors/messages.json).

**Events** (NEP-297, `EVENT_JSON:` logs): `nep141` `ft_mint` / `ft_burn` / `ft_transfer`, and
`{"standard":"wyec_bridge","version":"1.0.0","event":…,"data":[{…}]}` for `minted`,
`mint_proposed`, `mint_challenged`, `burn_to_ycash`, `guardians_changed`, `paused`,
`mint_limit_changed`. Hawkeye reads state, not events (N-8): per final block, the receipts that
changed this contract's state (`EXPERIMENTAL_changes`, `EXPERIMENTAL_receipt`), completed with view
calls at that block (`crates/hawkeye-near/src/contract.rs`).

## Differences from the Ethereum `WyecBridge`

- **Burn pays for its record.** On NEAR a contract pays for its own storage, so a 1-yocto burn
  that appends a ~130-byte `BurnRecord` would let anyone drain the contract balance with zero-amount
  burns (and then block mints). `burn` therefore requires the record's storage cost
  (`burn_storage_deposit(account_id)` = (121 + account id length) bytes × storage price, about
  0.0013–0.0019 NEAR) and refunds any excess; a 0-yocto call still fails with the standard
  1-yocto message. Zero-amount burns still consume a nonce, as on Ethereum.
- **No `setBridge`/successor hand-off**: token and bridge are one contract (N-7) with no upgrade
  path in v1 (N-9, NQ-2).
- **Times are seconds** of `block_timestamp` (`eta_sec`, rate-limit windows
  `floor(now_sec / cap_window_sec)`), as `block.timestamp` is on Ethereum.
- **Storage auto-registration** on mint (N-10), paid from the contract balance.
- `storage_unregister(force: true)` with a positive balance destroys it per NEP-145 (an `ft_burn`
  event with memo `unregistered`, no `BurnRecord`, no Ycash release): supply only shrinks.

## Build

Toolchain: Rust 1.97.0 with `wasm32-unknown-unknown` (pinned in `rust-toolchain.toml`).

```sh
cd near
cargo build --target wasm32-unknown-unknown --release
# → target/wasm32-unknown-unknown/release/wyec_near.wasm
```

`.cargo/config.toml` adds the flags `cargo near build` uses (`-C link-arg=-s --cfg near`): near-sdk
5.29 calls the NEAR host functions only under `--cfg near`, so a plain wasm build without it is
not deployable. A `RUSTFLAGS` environment variable *replaces* those flags; unset it. The wasm
uses the bulk-memory and non-trapping float-to-int features rustc ≥ 1.87 emits; nearcore accepts
them from protocol version 84, which near-sdk 5.29.1 declares as its minimum (cargo-near does the
same check), and the contract imports near-sdk 5.29's full host-function set (including the
gas-key promise actions), so it needs a network at that protocol version or later.
`cargo near build non-reproducible-wasm --no-abi` (cargo-near ≥ 0.17) produces the same contract
plus a `wasm-opt` size pass, if cargo-near is installed.

## Test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                   # unit tests (near-sdk mocked blockchain)
WYEC_NEAR_WRITE_VECTORS=1 cargo test vectors_file   # regenerate vectors/messages.json
```

Sandbox integration tests (`tests/sandbox.rs`, near-workspaces) deploy the release wasm to a real
NEAR sandbox node. They are skipped unless `NEAR_SANDBOX=1`; the sandbox binary is downloaded on
first use (or set `NEAR_SANDBOX_BIN_PATH`):

```sh
cargo build --target wasm32-unknown-unknown --release
NEAR_SANDBOX=1 cargo test --test sandbox -- --nocapture   # prints gas burnt per call
```

`hawkeye_core_vectors_agree` cross-checks this contract against hawkeye-core's
`crates/hawkeye-core/tests/data/near_vectors.json` (skipped if the file is absent): the guardian
key of each fixed secret, every message's Borsh bytes, tag, preimage and digest (computed by the
contract in the mocked runtime with `current_account_id` set to the vector's contract id), the key
each signature recovers to through the host's `ecrecover(…, malleability_flag = true)`, and every
`BurnRecord`'s Borsh bytes and SHA-256 (also through the contract's `record_hash`).
`vectors_file` keeps this contract's own `vectors/messages.json` byte-stable, and
`vectors_verify_in_the_contract` re-verifies it through the host functions.

`tests/tx_vectors.rs` (not a sandbox test) builds and signs NEAR transactions with
`near-primitives` / `near-crypto` 0.37.4 and keeps
`../crates/hawkeye-near/tests/data/tx_vectors.json` byte-stable; Hawkeye's hand-rolled codec
(`crates/hawkeye-near/src/tx.rs`) is checked against it (`WYEC_NEAR_WRITE_TX_VECTORS=1 cargo test
--test tx_vectors` regenerates it).

## Deploy (testnet, near-cli-rs)

```sh
NET=testnet; C=wyec.<you>.testnet
near account create-account fund-myself $C '10 NEAR' autogenerate-new-keypair \
  save-to-keychain sign-as <you>.testnet network-config $NET sign-with-keychain send
near contract deploy $C use-file target/wasm32-unknown-unknown/release/wyec_near.wasm \
  with-init-call new json-args '{
    "network_id": "testnet",
    "guardians": ["<64-byte key hex>", "<…>", "<…>"],
    "threshold": 2,
    "challenge_window_sec": 3600,
    "mint_cap": "100000000000",
    "cap_window_sec": 86400
  }' prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
  network-config $NET sign-with-keychain send
# N-9: no full-access key after deployment, no upgrade method — remove the deploy key:
near account delete-keys $C public-keys <ed25519:…> network-config $NET sign-with-keychain send
```

Fund the contract account for storage (N-10): every first mint to a new holder registers it from
the contract balance (`storage_balance_bounds().min`, ~0.00125 NEAR), and every proposal and
consumed lock is stored there too. Burns pay for their own record.

Views and calls:

```sh
near contract call-function as-read-only $C config json-args '{}' network-config $NET now
near contract call-function as-read-only $C get_burns json-args '{"from_nonce":0,"limit":100}' \
  network-config $NET now
near contract call-function as-transaction $C burn \
  json-args '{"amount":"100000000","ycash_recipient":"0100…<hash160>"}' \
  prepaid-gas '30 Tgas' attached-deposit '0.01 NEAR' \
  sign-as <holder>.testnet network-config $NET sign-with-keychain send
```

## NEAR Intents

wYEC is a plain NEP-141 token, so it works with `intents.near` unchanged: a holder deposits with
`ft_transfer_call(receiver_id: "intents.near", amount, msg)` and solvers trade it like any other
token. `intents.near` must be storage-registered here first (`storage_deposit` with
`account_id: "intents.near"`, anyone may pay). Pause does not stop transfers, so wYEC already in
Intents stays tradable while the bridge is paused. Listing on swap front ends is a business step,
not code.
