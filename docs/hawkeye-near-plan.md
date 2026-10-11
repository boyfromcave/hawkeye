# Wrapped Ycash on NEAR — the third vault application

**Revision 4, 2026-10-11 (post-quantum burn recipients: §2.4 BurnRecord v2, NQ-5 decided, §5 NH-R3/NH-R5; revision 3, 2026-10-11: post-quantum owners, below and §5; revision 2, 2026-10-10: NH5 as built,
§4 item 6). Branch `claude/hawkeye-near-wyec` (exploratory: built so the option is ready, not a
commitment to ship).** Extends the Hawkeye plan of record
([`hawkeye-bridge-plan.md`](hawkeye-bridge-plan.md), "the main plan") from one foreign chain
(Ethereum) to two. Decisions are numbered **N-\***, phases **NH0–NH6**, open questions **NQ-\***.

**Post-quantum owners (quantum line `upgrade/quantum-vaults`, merged into this branch 2026-10-11 as
`e8299e8`).** `NYEC` vaults have post-quantum owners exactly as `WYEC` vaults do (main plan,
"Post-quantum owners"; the workspace's `yellowback-quantum-spec.md` §1, quantum plan D-Q-1): the
same V and I templates with the owner slot `<ownerHash:32> OP_1|OP_2 OP_CHECKPQSIG`, the same
lock-policy rule (SLH-DSA-SHA2-128s, scheme 1, owners only: main plan §4.1 rule 1; a Falcon-owned
`NYEC` vault is never minted and its owner recovers at `ownerHeight`), the same
`hawkeye lock --owner <PQ address | pqkeyid>` (without it, a new owner of the depositor's node
wallet from `vault_getnewowner`), the same `hawkeye recover` through `vault_ownerspend` (the
depositor's node signs; Hawkeye holds no owner key and no post-quantum code), and a roll copies the
owner slot byte for byte. **Nothing changes on the NEAR side**: the `wyec-near` contract, the `NR1`
destination (§2.1), the `HKN1` memo (§2.2) and the N-6 attestation digests are untouched, because
attestors and bridge guardians stay secp256k1 (quantum plan D-Q-5) and the contract never sees a
vault owner. `BurnRecord.ycash_recipient` (§2.4) stays the main plan's §4.2 **transparent** P2PKH /
P2SH recipient (HK-5): a post-quantum `TX_PQPKH` recipient (a plain-YEC `sq…` address, D-Q-20)
would need a new recipient kind — recorded as **NQ-5**, not implemented. Mainnet PQ Yellowback
addresses on this line are `yb…` (mainnet version `0x56AB`; testnet `yt…`, regtest `yr…`;
D-Q-21). **Node requirement:** this branch parses only the post-quantum owner
shape, so it runs against `upgrade/quantum-vaults` nodes only, on both lines (at the merge:
ycash-dd `d41026209`, ycash6 `0c6c5fdf2`; an `upgrade/vault` node has no vault template this
Hawkeye recognises); `devnet-e2e` builds the node from that branch by default (`NODE_REF`).

## 0. The answer in one page

1. **Why NEAR.** NEAR Intents (the `intents.near` verifier, solvers, cross-chain swaps) lists any
   **NEP-141** fungible token. Ycash gets NEAR-side liquidity and swap routing by existing there as a
   standard NEP-141 token backed 1:1 by vaulted YEC. Nothing about Intents needs to know Ycash.
2. **Ycash's vault primitive now carries three applications**, each a different 4-byte **vault
   tag** (the "magic bytes" consensus already carries but never interprets):

   | # | Application | Vault tag | Consensus module | Foreign side |
   |---|---|---|---|---|
   | 1 | Yellowback (YED) | `YED\0` | registered (rule module) | — |
   | 2 | wYEC on Ethereum | `WYEC` | none (primitive only) | `WrappedYcash` + `WyecBridge` (wyec repo) |
   | 3 | **wYEC on NEAR** | **`NYEC`** (0x4E 0x59 0x45 0x43) | **none (primitive only)** | `wyec-near` NEP-141 contract (this branch, `near/`) |

   **No node change, no new branch ID, no new module.** An unregistered tag is governed by the
   primitive alone (upgrade plan §3.8, §15.7), exactly like `WYEC`. Ycash consensus never reads NEAR
   (R2), as it never reads Ethereum.
3. **Same safety model as Ethereum (main plan HK-1, wyec#1).** Ycash → NEAR: one attestation +
   challenge window + veto (optimistic mint) with a k ≥ 2 fast path; NEAR → Ycash: the vault
   primitive's delayed intent, cancel by any one attestor, slashing on Ycash.
4. **Same attestor keys work on NEAR.** NEAR contracts can verify secp256k1 signatures natively
   (`env::ecrecover`), so the member key registered on Ycash signs NEAR attestations too. Gas on NEAR
   is paid by a separate ed25519 NEAR account per operator (relayer key), which never attests.
5. **Hawkeye runs one process per bridge** beside the same `ycashd`: an Ethereum Hawkeye (tag
   `WYEC`) and a NEAR Hawkeye (tag `NYEC`), each with its own config, ledger and signer set. The
   engine is generalized from "Ethereum" to a **foreign-chain adapter**; the Ycash half is shared.

## 1. Decisions

| # | Decision | Why |
|---|---|---|
| N-1 | Vault tag `NYEC` for NEAR locks; `WYEC` stays Ethereum's | separate pools: a NEAR mint is backed only by NEAR-tagged vaults, so one bridge's failure never drains the other's backing; Hawkeye tells the two apart by tag |
| N-2 | **A separate signer set per bridge** (same operators may join both, with distinct member keys recommended) | the primitive's rate limit, locked value, liveness and dormancy are per set: a NEAR incident (dormancy, rate cap, slashing) never touches Ethereum depositors; recovery stays independent |
| N-3 | Destination `OP_RETURN` on a NEAR lock: `"NR1"` (0x4E 0x52 0x31) ‖ NEAR account id (UTF-8, 2–64 bytes, NEAR account-id rules); total ≤ 67 bytes | NEAR accounts are names or 64-hex implicit accounts, not 20-byte addresses; never begins `0x5956` (`YV`, upgrade finding (27)) |
| N-4 | `lockId = SHA256(txid ‖ vout)` as on Ethereum | one lock id scheme across bridges; tags keep the pools apart |
| N-5 | Burn-reference memo `"HKN1"`, same 73-byte layout as `HKB1` (main plan §4.3) | one memo parser; the magic says which bridge, and a memo for one bridge is unmatched on the other |
| N-6 | Attestation messages: `SHA256("HawkeyeNear-v1" ‖ borsh(network_id) ‖ borsh(contract_id) ‖ borsh(msg))`, signed secp256k1, 65-byte `r‖s‖v` with `v ∈ {0,1}`, low-S | `env::ecrecover` takes a 32-byte hash, 64-byte sig and `v`; the domain prefix and both ids stop cross-network and cross-contract replay (the EIP-712 domain's job on Ethereum) |
| N-7 | One contract, `wyec-near`: NEP-141 + NEP-145 + NEP-148 token **and** the bridge policy | NEAR cross-contract calls are asynchronous; a token/bridge split (as on Ethereum) adds callback failure modes for no benefit; the contract stays small |
| N-8 | **Burns, mints and proposals are recorded in contract state and read with view calls at `finality: final`**; Hawkeye finds them **per final block**: `EXPERIMENTAL_changes` (`data_changes` of the contract) names every receipt that changed its state, `EXPERIMENTAL_receipt` gives each one's calls, and views at that block (`block_id`) complete them (`get_proposal` after a `propose_mint`, before an `execute_mint`; `get_burns` between the burn counts before and after a block with a `burn`) | NEAR RPC has no log filter; an on-chain burn log (`get_burns(from_nonce, limit)`) is a deterministic, reorg-free source; the memo's `data` is the SHA-256 of the burn record. The watcher must see **every** proposal, including one for a lockId Hawkeye has never seen and one sent through another contract, which no view can enumerate; a state change cannot be hidden, whoever sent the receipt (NH4) |
| N-9 | No full-access key after deployment; no upgrade method in v1 (NQ-2) | the Ethereum side has no proxy and no admin key; same trust statement on NEAR |
| N-11 | A burn pays the storage of its own `BurnRecord` (refund of any excess) instead of 1 yoctoNEAR | on NEAR the contract pays for stored bytes; 1-yocto burns would let anyone drain its balance with zero-amount burns and then block mints |
| N-12 | Threshold signatures sorted strictly ascending by recovered 64-byte key | one comparison per signature for distinctness, as the Ethereum contract's ascending-address rule |
| N-10 | Mint auto-registers the receiver's storage (NEP-145), paid from the contract balance; the deployer funds it | a depositor on Ycash cannot register storage on NEAR; the cost is ~0.00125 NEAR per new holder |

## 2. Normative encodings (implemented in `hawkeye-core::near`, golden-vectored, mirrored in the contract)

### 2.1 Lock destination (N-3)

`OP_RETURN <push: "NR1" ‖ account_id>` — the single `OP_RETURN` of the lock transaction, one push.
`account_id` must satisfy NEAR's rules: length 2–64; characters `a-z 0-9 _ - .`; parts separated by
`.`, `-` or `_` with no two separators adjacent and none leading or trailing. Implicit accounts
(64 lowercase hex) and EVM-style implicit accounts (`0x` + 40 hex) are valid. Anything else is
refused by lock policy (never minted; owner recovers at `ownerHeight`).

### 2.2 Memo `HKN1` (N-5)

```
magic    4   "HKN1"
kind     1   0x01 burn release | 0x02 roll
chainId  8   u64 LE = first 8 bytes of SHA256("near:" ‖ network_id)   (mainnet, testnet, sandbox…)
bridge  20   first 20 bytes of SHA256(contract account id)
ref      8   kind 1: burn nonce | kind 2: new ownerHeight
data    32   kind 1: SHA256(borsh(BurnRecord)) | kind 2: SHA256(new V spk)
```

### 2.3 Messages (N-6)

```rust
#[derive(BorshSerialize)]
enum BridgeMessage {
    Mint { lock_id: [u8; 32], amount: u128, receiver_id: String },              // tag 0
    Challenge { lock_id: [u8; 32], proposal_id: u64 },                          // tag 1
    SetGuardians { guardians: Vec<[u8; 64]>, threshold: u8, admin_nonce: u64 }, // tag 2
    SetPaused { paused: bool, admin_nonce: u64 },                               // tag 3
    SetMintLimit { mint_cap: u128, cap_window_sec: u64, admin_nonce: u64 },     // tag 4
}
digest = SHA256( b"HawkeyeNear-v1" ‖ borsh(network_id: String) ‖ borsh(contract_id: String) ‖ borsh(msg) )
```

Guardians are identified by the **64-byte uncompressed secp256k1 public key** (x ‖ y, no `0x04`),
which is what `env::ecrecover` returns; Hawkeye derives it from the Ycash member key. Amounts are
zatoshi (`decimals = 8`), carried as `u128` (NEP-141 `U128` in JSON).

### 2.4 Burn record (N-8)

```rust
#[derive(BorshSerialize)]
struct BurnRecord { nonce: u64, from: String, amount: u128, ycash_recipient: Vec<u8>, block_height: u64, timestamp_ns: u64 }
```
`ycash_recipient` is the main plan's §4.2 **revision 2** recipient (22 or 35 bytes: version `0x02`,
kind P2PKH / P2SH / PQPKH, then hash160 or `scheme ‖ keyHash`), borsh-encoded as a `Vec<u8>` (u32 LE
length, then the bytes). The contract validates it exactly as wyec does (length, version, kind,
scheme) and refuses anything else. This is **BurnRecord v2** (revision 4, NQ-5): the layout and so
`record_hash` = the HKN1 memo's `data` differ from v1's `[u8; 32]`; v1 never shipped. `burn` takes
the recipient as hex (44 or 70 digits); `burn_storage_deposit` prices the record by the longest
recipient (35 bytes), the excess refunded as before (N-11).

## 3. The `wyec-near` contract

| Method | Who | What |
|---|---|---|
| `ft_*`, `storage_*`, `ft_metadata` | anyone | standard NEP-141 / NEP-145 / NEP-148; name "Wrapped Ycash", symbol `wYEC`, decimals 8 |
| `mint(lock_id, amount, receiver_id, sigs)` | anyone | threshold fast path (k ≥ 2 on mainnet), consumes `lock_id` |
| `propose_mint(lock_id, amount, receiver_id, sig)` | anyone | one guardian's Mint signature; opens a proposal with `eta = now + challenge_window` |
| `challenge_mint(lock_id, proposal_id, sig)` | anyone | any one guardian's Challenge signature deletes the proposal and **vetoes the proposer for that lock** (wyec#1's rule) |
| `execute_mint(lock_id)` | anyone | after `eta`, proposer still a guardian; consumes `lock_id`; rate limit |
| `burn(amount, ycash_recipient)` | holder, deposit ≥ the record's storage cost (`burn_storage_deposit`, ~0.0013–0.0019 NEAR; excess refunded) | burns, appends a `BurnRecord`, emits NEP-297 events `ft_burn` and `wyec_bridge/burn_to_ycash` (N-11) |
| `set_guardians`, `set_paused`, `set_mint_limit` | threshold of current guardians | admin acts with `admin_nonce`; pause stops mint/propose/execute/burn, never challenge or transfers |
| views | anyone | `get_guardians`, `get_threshold`, `is_consumed`, `get_proposal`, `get_burns(from_nonce, limit)`, `get_burn_count`, `mint_available`, `config` |

**NEAR Intents.** `wyec-near` is a plain NEP-141 token, so it can be deposited into `intents.near`
with `ft_transfer_call` and traded by solvers like any other token; listing on swap front ends is a
business step, not code.

## 4. Hawkeye changes

1. `hawkeye-core::near`: §2 codecs, account-id validation, digests, secp256k1 signing with `v ∈ {0,1}`,
   uncompressed-key derivation; golden vectors shared with the contract tests.
2. **Foreign-chain adapter.** The engine's Ethereum calls become a trait (`ForeignChain`: scan
   finalized burns, read lock/mint/proposal state, submit threshold / propose / challenge / execute,
   read the guardian set and supply). `hawkeye-eth` implements it as today; a new `hawkeye-near`
   crate implements it over NEAR JSON-RPC (view calls at `finality: final`, `broadcast_tx_commit`
   with the operator's ed25519 relayer key).
3. **Tag-parameterized Ycash half.** Every `TAG_WYEC` comparison becomes the bridge's configured tag;
   the memo magic follows the chain kind.
4. Config: `[foreign] kind = "ethereum" | "near"`, `[near] rpc_url, network_id, contract_id,
   relayer_account, relayer_key_file, start_block, gas_tgas`, `[bridge] tag`.
5. **As built (NH4).** `crates/hawkeye-near`: JSON-RPC client (`query` views at `final` or a
   block, `block`, `EXPERIMENTAL_changes`, `EXPERIMENTAL_receipt`, `view_access_key`, `send_tx`
   with `wait_until: FINAL`); a hand-rolled Borsh codec for `TransactionV0` / `SignedTransaction`
   with `FunctionCall` actions, signed with the relayer's ed25519 key from a NEAR credentials JSON
   (byte-for-byte golden vectors built and signed by `near-primitives` / `near-crypto` 0.37.4 in
   `near/tests/tx_vectors.rs`); the `wyec-near` client (nonce = access-key nonce at `final`, never
   below the last used, + 1; an `InvalidNonce` is re-read and retried once; the envelope is
   rebuilt, the attestation in it is the engine's sign-once record); the N-8 scanner (cursor =
   final block height; a height NEAR skipped has no changes; a burn's id is
   `SHA256(borsh(BurnRecord))`, a mint's or proposal's its receipt id); contract panics mapped to
   the Ethereum bridge's error names (`wyec: lock consumed` → `LockConsumed`, …); a mock NEAR
   node with a model of the contract. `crates/hawkeye/src/foreign/near.rs`: `NearChain` /
   `NearScheme`. Ledger schema v4: chain-neutral accounts (`ethereum:0x…` / `near:<id>`) and
   guardians (`ethereum:0x…` / `secp256k1:<x‖y>`), cursor `foreign`; v3 ledgers migrate losslessly.
   Status: `foreign_kind`, `guardian`, `foreign` (the old `eth_address` / `ethereum` kept).
6. **As built (NH5): against a real nearcore.** The NEAR sandbox node is pinned at nearcore
   **2.13.4** (`near/tools/fetch-sandbox.sh`, SHA-256 checked; the version near-workspaces 0.23 /
   near-sandbox 0.3.16 uses, so the contract tests, the adapter test and the devnet run one node).
   `crates/hawkeye-near/tests/sandbox.rs` (env-gated: `HAWKEYE_NEAR_SANDBOX_RPC`,
   `HAWKEYE_NEAR_SANDBOX_KEY`) drives every RPC shape the NH4 client had only seen from its mock;
   two differed and are fixed in the client and the mock: (a) a **view call that panics** is
   answered in `result.error` as `wasm execution failed with error: HostError(GuestPanic {
   panic_msg: "…" })` (a missing contract: `CompilationError(CodeDoesNotExist …)`), not with the
   `Smart contract panicked:` wording of a failed transaction; (b) `send_tx` outcomes carry
   `gas_burnt`, now summed into `TxOutcome` / `CallOutcome`. Blocks, `status`,
   `view_access_key`, `EXPERIMENTAL_changes` (`cause.receipt_hash`), `EXPERIMENTAL_receipt`,
   transaction panics and `InvalidNonce` matched the mock; the N-8 scanner found a threshold mint,
   two proposals, a challenge, an execute and a burn at their blocks with the right keys on the
   first real run. The codec gained `CreateAccount`, `DeployContract` and a full-access `AddKey`
   (golden-vectored against `near-primitives`), used only by set-up code (`admin.rs`,
   `examples/near-admin.rs`); the daemon never creates accounts or deploys. The devnet raises the
   sandbox's `epoch_length` to 100 000 so no epoch change or garbage collection happens within a
   run (the scanner needs every block since `start_block`; a production RPC must keep them, or be
   archival, as before). The sandbox binary needs glibc ≥ 2.39: its CI jobs run on ubuntu-24.04.

## 5. Phases

| Phase | Content | Exit |
|---|---|---|
| NH0 | this plan, branch | — |
| NH1 ✅ | `hawkeye-core::near` encodings + vectors | vectors pass in Rust and in the contract |
| NH2 ✅ | `near/` contract: token + bridge, unit tests (`near-sdk` test env), wasm build, sandbox integration tests (`near-workspaces`, CI) | all green; wasm size and gas measured |
| NH3 ✅ | `ForeignChain` trait; Ethereum behind it with no behaviour change (all existing tests and drills still pass) | Ethereum devnet demo PASS on both node lines |
| NH4 ✅ | `hawkeye-near` adapter + daemon support | engine tests against a NEAR mock RPC |
| NH5 ✅ | NEAR devnet: real regtest ycashd + NEAR sandbox + Hawkeyes; `scenario demo` and `rogue-mint` (`devnet/hawkeye-devnet --foreign near`); the adapter against a real sandbox (CI `near-adapter-sandbox`) | PASS on both node lines: devnet-e2e run 38041601513 (ycash-dd v4.5.0 and ycash6 6.22.0-rc1 × ethereum and near, all green, transcripts as artifacts `devnet-<line>-<foreign>`); ci run 38039974967 (`near-adapter-sandbox`) |
| NH5-PQ ✅ | post-quantum vault owners on the NEAR line (merge `e8299e8`, 2026-10-11, "Post-quantum owners" above): the NEAR engine tests and the core memo test build their vaults with a PQ owner (`new_wallet_owner`); `hawkeye lock` takes a kind-aware `--dest` and the PQ `--owner`; the devnet's `--foreign near` runs unchanged on the quantum nodes; no NEAR contract, HKN1 or NR1 change | green on the quantum nodes (ycash-dd `d41026209`, ycash6 `0c6c5fdf2`), both bridges: `ci` run 38153755234 (12 jobs) and `devnet-e2e` run 38153755261 (node × 2, demo line × foreign × 2: `demo` and `rogue-mint` PASS on NEAR and Ethereum on both lines; `hawkeye lock` returned a scheme-1 `owner` and a regtest `yr…` `owner_address` on the real node) |
| NH-R3 | post-quantum burn recipients on NEAR (main plan §9.1 R3): `burn` with the §4.2 revision-2 recipient, BurnRecord v2, regenerated vectors, sandbox tests | green on the real sandbox (CI) |
| NH-R5 | the `pq-recipient` drill with `--foreign near` on the real quantum nodes (main plan §9.1 R5) | PASS on both lines (CI) |
| NH6 | testnet trial, audit, Foundation parameters | — |

## 6. Open questions

| # | Question | Recommendation |
|---|---|---|
| NQ-1 | One bridge set per chain (N-2) or one shared set | separate sets |
| NQ-2 | Contract upgrades on NEAR | none in v1; a successor contract with a threshold-signed migration if ever needed |
| NQ-3 | Who funds NEAR storage and gas (N-10) | the bridge operators' treasury; ~0.00125 NEAR per new holder. Measured on the 2.13.4 sandbox (gas burnt, transaction + receipts; NH5): threshold mint (k = 2, registering the receiver) 3.40 TGas, `propose_mint` 2.88, `challenge_mint` 2.85, `execute_mint` 2.71, `burn` 2.61, deploy + `new` 24.09 (297 200-byte wasm); Hawkeye attaches 100 TGas per call (`gas_tgas`) and is refunded the rest |
| NQ-4 | Direct NEAR ↔ Ethereum wYEC routing | out of scope: each bridge is backed by its own vaults; moving between them is burn on one + lock on the other |
| NQ-5 | A post-quantum burn recipient (`TX_PQPKH`, the plain-YEC `sq…` address of quantum plan D-Q-20; `scheme ‖ keyHash` is 33 bytes, one more than a `bytes32` leaves) | **Decided (owner, 2026-10-11), with the main plan's Q-7: both bridges together.** Main plan §4.2 revision 2 (a 22/35-byte versioned recipient with a PQPKH kind) and §2.4 here (BurnRecord v2); phases R3 (contract + vectors) and R4–R5 (Hawkeye, the devnet drill on both bridges) in the main plan §9.1. No node change. |
