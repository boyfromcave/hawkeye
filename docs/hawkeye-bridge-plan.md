# Hawkeye — the wYEC bridge attestor sidecar: development plan

**Revision 1, 2026-10-07.** Status: plan of record for the `hawkeye` repository. Builds on the
workspace's [vault upgrade plan](https://github.com/boyfromcave/yellowback/blob/harden/yellowback/docs/plans/yellowback-upgrade-plan.md)
("the upgrade plan", revision 2: §3 the primitive, §4 the bridge, §15 the implementation spec,
findings (1)–(93)), the node's [`doc/vault-rpc.md`](https://github.com/boyfromcave/ycash-dd/blob/upgrade/vault/doc/vault-rpc.md)
and the [wYEC contract design](https://github.com/boyfromcave/wyec/blob/main/docs/wyec-contract-design.md)
(`wyec` @ `d2e382b`). Decisions here are numbered **HK-\***, change requests to other repositories
**CR-\***, open questions for the owner and the Foundation **Q-\***, and phases **H0–H8**.

Naming: **Hawkeye** is the software. An **attestor** is a Ycash participant who runs it and holds a
seat in the bridge's signer set. **wYEC** is the ERC-20 on Ethereum. A **lock** is a `WYEC`-tagged
vault output on Ycash, a **burn** is a `BurnToYcash` event on Ethereum, an **intent** is the
primitive's delayed-release output (§15.3 of the upgrade plan).

---

## 0. The answer in one page

1. **What Hawkeye is.** The off-chain half of the wYEC bridge: a Rust daemon each attestor runs next
   to its own `ycashd` (either node line, `upgrade/vault`) and an Ethereum JSON-RPC endpoint. It
   attests locks on Ycash into mints on Ethereum, attests burns on Ethereum into intents on Ycash,
   **watches every other attestor's work** and cancels and slashes what it cannot match. It is the
   production replacement of the devnet's Python `bridge-sim` (ycash-dd
   `contrib/yellowback/devnet/bridge-sim`), which proved the Ycash half against a mock burn feed.
2. **The node side is done, and Hawkeye needs no consensus change.** The primitive (`UPGRADE_VAULT`,
   `0x6d5b7a31`) is on both node lines with its `set_*` / `vault_*` RPCs; Hawkeye reaches the node
   only through those and stock RPCs (workspace rule 2). Two small RPC conveniences would simplify
   it (CR-N1, CR-N2) and are not blocking: Hawkeye builds the bytes itself until they land.
3. **The Foundation's model — one attestation, a challenge window, slashing — is a parameter row of
   the primitive, not a new shape** (HK-1). All attestors are members of **one** signer set with
   `unlockThreshold = 1` (one attestation unlocks), `cancelThreshold = 1` (any one member cancels
   during the window), the vault's `delay` as the challenge window, and `slashThreshold` = a
   majority of the *other* members, who burn a fraudulent member's bond with `SET_REMOVE burn=1`.
   This sidesteps upgrade-plan finding (26) — a one-seat relayer set cannot be slashed by a separate
   challenger set — without touching consensus.
4. **The Ethereum mint side needs one contract change for the same model** (CR-W1). Today's
   `WyecBridge.mint` is immediate under a k-of-n threshold; with `k = 1` one stolen key mints to
   the cap with no window. Hawkeye's mainnet configuration therefore requires either `k ≥ 2`
   (immediate) or the optimistic mint of CR-W1 (`proposeMint` by one attestor → challenge window →
   `executeMint`; any attestor challenges). Sepolia development runs on today's contract at `k = 1`.
5. **Two bridge-safety findings that Hawkeye enforces by policy** (§3): an unconditional
   owner-recovery height on bridge vaults (`ownerHeight = lockHeight + BRIDGE_MAX_AGE`) lets a
   depositor who has sold their wYEC take the YEC back once that height passes; and an intent commits only
   `(recipientHash, value)`, so burn-to-intent matching is ambiguous without a reference.
   Hawkeye answers both: a minimum owner age before it will mint plus vault **rolls** before
   expiry (HK-6), and a 73-byte **burn-reference memo** in every unlock transaction (HK-4).
6. **Stack.** Rust (edition 2024, pinned toolchain), `tokio`, `alloy` for Ethereum, a typed
   JSON-RPC client for `ycashd`, SQLite for the attestor's ledger, `k256` for secp256k1; Foundry
   (forge / anvil / cast) for the contracts' local chain, Sepolia for the public integration.
7. **Deliverables in order:** core encodings with golden vectors (H1) → Ycash and Ethereum adapters
   (H2, H3) → the engine and its ledger (H4) → the daemon (H5) → end-to-end on anvil + regtest (H6)
   → Sepolia + public Ycash devnet (H7) → audit and release with the upgrade's P7/P8 gates (H8).

---

## 1. The bridge, end to end

### 1.1 Actors

| Actor | Runs | Holds |
|---|---|---|
| Depositor (Ycash user) | a Ycash wallet that can write a `WYEC` lock (Hawkeye's CLI `hawkeye lock` until YecWallet/YEW ship it) | the vault's owner key |
| wYEC holder (Ethereum user) | any Ethereum wallet, or `hawkeye burn` | wYEC |
| Attestor (one per seat, 5–15 seats) | `hawkeye` + its own `ycashd` + an Ethereum endpoint | one secp256k1 **member key** (Ycash set member, Ethereum guardian address), a YEC bond, fee coins on both chains |
| Anyone | — | may submit a signed mint, release a matured intent (U-15), submit an equivocation proof |

### 1.2 Lock YEC → mint wYEC

```
Depositor                     Ycash (consensus)                 Hawkeye (every attestor)              Ethereum
   │ lock tx: V(WYEC, setId=A,     │                                  │                                    │
   │  cancelSetId=A, delay=D,      │                                  │                                    │
   │  ownerHeight=L+AGE, app=0)    │                                  │                                    │
   │  + OP_RETURN dest(bytes32)───▶│ V-1: set exists, lockedValue+=v  │                                    │
   │                               │──────── confirmations ≥ C_Y ────▶│ L-policy (§4.1) ok?                │
   │                               │                                  │ lockId = sha256(txid‖vout)         │
   │                               │                                  │ sign EIP-712 Mint(lockId,v,to) once│
   │                               │                                  │ leader submits ───────────────────▶│ mint (k sigs) or
   │                               │                                  │                                    │ proposeMint→window→execute (CR-W1)
   │                               │                                  │ watchers: every Minted/MintProposed │
   │                               │                                  │  must match a lock, else challenge  │
   │                               │                                  │  + slash vote (§5.3)               │
```

- The lock is the depositor's own transaction; consensus checks only the primitive (V-1). The
  destination is the ABI `bytes32` of an Ethereum address, left-padded, in an `OP_RETURN` next to
  the vault (bridge-sim's convention, upgrade finding (27): never beginning `0x5956`).
- Every attestor verifies the lock against the **lock policy** (§4.1) independently. A lock that
  fails policy is never minted; its owner recovers it at `ownerHeight` (or on dormancy).
- `amount` crosses unscaled: 1 zatoshi = 1 wYEC base unit (wYEC has 8 decimals).

### 1.3 Burn wYEC → release YEC

```
Holder                 Ethereum                Hawkeye (leader for nonce n)       Ycash (consensus)          Hawkeye (every attestor)
  │ burn(v, recip32) ─▶│ BurnToYcash(n,...)     │                                    │                          │
  │                    │── finalized ──────────▶│ R-policy ok? choose vault(s)       │                          │
  │                    │                        │ vault_buildunlock + memo(n) ──────▶│ S-2, S-3 rate limit      │
  │                    │                        │ set_signunlock (1 sig) + send      │ intent I (D blocks)      │
  │                    │                        │                                    │──── mempool / block ────▶│ match memo n ↔ burn n
  │                    │                        │                                    │                          │ (value, recipientHash,
  │                    │                        │                                    │                          │  burn unconsumed)?
  │                    │                        │                                    │◀── no: vault_buildcancel │
  │                    │                        │                                    │   + set_signcancel + send│ + slash vote vs signer
  │                    │                        │ after D: vault_release ───────────▶│ I-1: pays recipient      │
```

- Only burns in **finalized** Ethereum blocks become intents (upgrade plan §11 row 3).
- The release pays the burner's Ycash recipient from **any** `WYEC` vault of the set — the vaults
  are a pool, not per-depositor accounts. "Redeem your vault" in the user story means "redeem your
  wYEC for YEC"; a depositor's own vault is only theirs again on dormancy, wind-down or
  `ownerHeight` (§3.1).
- The challenge window is the intent's `delay` D: any one attestor may cancel back into the vault
  (I-2) before it matures, from the moment the intent is in the mempool (upgrade finding (65)).
- After D, anyone may broadcast the release (U-15); every attestor's Hawkeye does, idempotently.

### 1.4 Liveness and recovery (R1)

| Event | What happens | Hawkeye's part |
|---|---|---|
| Attestors heartbeat | `SET_HEARTBEAT` every `heartbeat_blocks`; the set stays live | sends heartbeats; alarms when the set's live count nears `cancelThreshold` |
| All attestors silent ≥ `livenessWindow` | set DORMANT → every vault's owner branch (selector 3) opens | `hawkeye recover` for depositors; watchers alarm long before |
| Wind-down (`SET_WINDDOWN` by `slashThreshold`) | released after `livenessWindow`; owners recover | the orderly exit (Ethereum dead, contract lost, Foundation decision) |
| `ownerHeight` reached | the owner may spend the vault (selector 2) **even while the bridge is live** | §3.1: minimum owner age + rolls |

---

## 2. The signer set: the Foundation's model as one parameter row (HK-1)

| Parameter (`set_create`) | Meaning here | Regtest / devnet | Sepolia devnet | Mainnet proposal (Q-1, O-13) |
|---|---|---|---|---|
| `seats` | attestor seats | 3 | 5 | 7 (max 15) |
| `unlockThreshold` | **one attestation** unlocks | 1 | 1 | 1 |
| `cancelThreshold` | one member cancels | 1 | 1 | 1 |
| `slashThreshold` | members other than the target to `SET_REMOVE` (burn or not) and to admit a joiner | 2 | 3 | 4 (majority of the other 6) |
| `open` | permissioned | false | false | false |
| vault `delay` = **challenge window** | blocks an intent waits | 6 | 60 (75 min) | 1,152 (24 h) |
| `ratelimitbps` / `ratewindow` | cap per epoch | 5,000 / 20 | 2,000 / 288 | ≤ `bondMin` / locked, per 1,152 |
| `livenessWindow` | silence → DORMANT | 60 | 2,304 | 8,064 (7 d); ≥ 4 × heartbeat (D-U5) |
| `heartbeat_blocks` (Hawkeye) | | 10 | 288 | 288 (6 h) |
| `bondMin` | stake per seat | 1 YEC | 10 YEC | ≥ one epoch's cap (§2.2) |
| `maturity` | blocks before a joiner counts | 2 | 20 | 1,152 |

The vault's `cancelSetId` is the attestor set itself (HK-2).

### 2.1 Why one set, not "relayer + open challengers" (HK-2)

The devnet's `relayer` shape (`bridge-sim up --shape relayer`) puts a one-seat relayer set in front
of an **open** challenger set. Two defects, both recorded upstream as open:

1. **The relayer cannot be slashed for fraud** (upgrade finding (26)): `SET_REMOVE` is signed by
   members of the target's own set; a one-seat set has no other member. Only equivocation reaches it.
2. **An open challenger set (≤ 15 seats) can be filled by an attacker**, who then cancels every
   honest intent (liveness attack), and removal needs `slashThreshold` of that same set, which
   the attacker controls.

One permissioned set with `unlockThreshold 1` gives the same economics (any one bonded party can
attest, any one can challenge, a majority slashes) using only rules the primitive already has.
If the Foundation insists on an open challenger population, that needs a node change (CR-N3).

### 2.2 The economic bound

With `unlockThreshold = 1`, a captured member whose fellow members are **all** silent for D blocks
steals at most one epoch's cap. So `rateLimit × lockedValue ≤ bondMin` per epoch (upgrade plan O-9
recommendation) is the condition under which theft never pays. The cap and the bond are set
together; the expected locked value bounds `ratelimitbps` from above. `yb-calibration` derives the
mainnet row (Q-1).

### 2.3 Slashing, concretely

| Fault | Evidence (objective, public) | Consequence | Who acts |
|---|---|---|---|
| Two set signatures by one key over two different spends of one outpoint | the two signatures | `SET_EQUIVOCATION`: EJECTED, bond frozen | anyone; Hawkeye submits automatically |
| A fraudulent intent (no finalized burn behind it, or the wrong value or recipient, or a burn already consumed) | the intent tx: its set signature recovers to the signer's key (§15.2 step 4); the memo or its absence | cancel (I-2) + `SET_REMOVE burn=1` | cancel: any one Hawkeye at once; slash: `slashThreshold` Hawkeyes co-sign a slash proposal after independent verification (§5.3) |
| A fraudulent mint signature or proposal (no lock behind the `lockId`, or a different amount or recipient) | the EIP-712 signature over `Mint(lockId, amount, to)` recovers to the signer | challenge (CR-W1) + `SET_REMOVE burn=1` on Ycash | same |
| Griefing (cancelling or challenging honest work) | the cancel's signer vs a matching burn | `SET_REMOVE burn=0` (O-6, bond returned) | `slashThreshold` |
| Equivocating EIP-712 Mint signatures (one `lockId`, two `(amount, to)`) | the two signatures | `SET_REMOVE burn=1` | `slashThreshold` |

Ycash consensus records the slash, never the reason (upgrade plan §3.6); Hawkeye records the reason
in its ledger and publishes the evidence bundle (§5.3).

---

## 3. Bridge-safety findings and Hawkeye's answers

### 3.1 F-1: the owner branch opens at `ownerHeight` even while the bridge is live (HK-6)

The upgrade plan's §4.1 recovery row reads "`height ≥ lockHeight + BRIDGE_MAX_AGE` **and no intent
names it**", but the template (§15.3, selector 2) is `<ownerHeight> CLTV <ownerKey> CHECKSIG`:
unconditional, and `vault_bridge.py` tests "owner recovers a lock older than `BRIDGE_MAX_AGE`
(guardians live)". So a depositor who minted wYEC and sold it can take the YEC back once that
height passes. The wYEC stays in circulation and is no longer backed.

Hawkeye's answer, no consensus change:

1. **Minimum owner age** — the lock policy (§4.1) refuses to mint for a vault with
   `ownerHeight − lockHeight < MIN_OWNER_AGE` (mainnet proposal: 2 years ≈ 841,000 blocks; devnet
   short). Wallets that offer bridging write `ownerHeight = lockHeight + BRIDGE_MAX_AGE` with
   `BRIDGE_MAX_AGE ≥ MIN_OWNER_AGE`.
2. **Rolls.** Before any vault's `ownerHeight − ROLL_MARGIN`, the leader unlocks it (selector 1)
   into an intent whose recipient is a **fresh V** with the same tag, sets, delay and owner key and
   `ownerHeight = tip + BRIDGE_MAX_AGE`, with a roll memo (kind 2, §4.3) carrying the new V's
   parameters so every watcher can recompute `recipientHash`; after D anyone releases it into the
   new vault (V-1 applies). A roll uses rate-limit budget and is scheduled in the quietest epoch.
3. **Drain order** — releases spend the vaults with the nearest `ownerHeight` first.
4. **Supply alarm** — every block: `wYEC.totalSupply() ≤ Σ value of live WYEC vaults with
   ownerHeight > tip + ROLL_MARGIN` (minus burns not yet released). A breach pages the operators;
   Q-2 asks whether a breach should also pause the bridge (`setPaused`).

What is given up: an owner key whose vault was minted keeps a recovery option at the end of the
roll horizon if every attestor fails to roll it. That is no worse than dormancy, which R1 requires.
Recorded for the upgrade plan as CR-U1 (correct the §4.1 text; optionally make the age branch
conditional in a later upgrade).

### 3.2 F-2: an intent does not name its burn (HK-4)

An intent commits `SHA256(recipient script)` and its value. Two burns of the same amount to the
same address are indistinguishable, and a dishonest attestor could post a second intent for a burn
already paid. Hawkeye puts a **burn-reference memo** `OP_RETURN` in every unlock (S-2 permits
OP_RETURN outputs; the set signature, SIGHASH_ALL, covers it), so matching is exact and one burn
pays once:

- a burn is **consumed** by the first intent carrying its memo that is mined and not cancelled;
- an intent whose memo names an already-consumed burn, an unknown burn, a burn with a different
  value or recipient, or that has no memo, is **unmatched** → cancelled, and slashed unless it is a
  benign race (§5.2: two leaders' intents for one burn inside the takeover window are cancelled
  but not slashed).

Until CR-N2 lands, Hawkeye inserts the memo into `vault_buildunlock`'s unsigned hex itself (the fee
inputs are unsigned and no set signature exists yet), which needs a v4 transparent transaction
codec in `hawkeye-ycash` (§6).

### 3.3 F-3: the Ethereum mint has no window at k = 1 (CR-W1)

See §0 item 4 and CR-W1. Hawkeye implements both mint modes behind one trait; the configured
mode must satisfy `mode = optimistic ∨ k ≥ 2` on mainnet (enforced at start-up).

### 3.4 F-4: recipient bytes are opaque on both chains (HK-5)

`burn(amount, bytes32 ycashRecipient)` is unconditional and the contract never parses the
recipient (R2). A malformed recipient cannot be paid. Hawkeye defines the encoding (§4.2), the
`hawkeye burn` CLI and any dapp built on it validate before sending, and a burn whose recipient
does not decode is held as **orphaned**: never released, reported, and refundable by a threshold
mint to the burner with the synthetic `lockId = sha256("hawkeye-refund" ‖ chainId ‖ bridge ‖
nonce)` (Q-3: the Foundation's call; needs `k`-of-n signatures, never one).

### 3.5 F-5: one key, two chains, and signing it twice (HK-7)

The member key is the bond key, the heartbeat key, the Ycash set-signing key and the Ethereum
guardian key (upgrade plan D-U4, wyec design §2.5). Hawkeye:

- signs on Ycash through the node wallet (`set_signunlock`, `set_signcancel`, `set_heartbeat`,
  `set_signact`), so the node's **sign-once guard** (upgrade finding (70)) protects the Ycash side;
- signs EIP-712 itself and keeps its own persistent sign-once record keyed by `lockId` (one
  `(amount, to)` ever) — the mint-side equivalent of the guard;
- holds the key in an encrypted keystore (Ethereum keystore v3, scrypt) and imports it into the
  node wallet once at enrolment (`importprivkey`, no rescan); a remote-signer backend (KMS/HSM,
  `web3signer`) is a phase-H8 option behind the same `Signer` trait;
- checks at start-up that `keccak256(uncompressed pubkey)[12:]` of every current set member is a
  guardian on the contract and vice versa; a mismatch refuses to start (rotation drift).

---

## 4. Normative encodings (implemented in `hawkeye-core`, golden-vectored)

All Ycash hashes and outpoints are in **internal byte order** unless stated; the RPCs print txids
reversed (display order) — `hawkeye-core` converts once at the boundary (upgrade finding (59)).

### 4.1 Lock policy (L-policy)

A confirmed output is a mintable lock iff all hold:

1. it parses as a V (§15.3, exact byte shape) with tag `WYEC`, `setId = cancelSetId =` the
   configured attestor set, `delay =` the configured D, `appHeight = 0`;
2. `ownerHeight − coinHeight ≥ MIN_OWNER_AGE` (§3.1);
3. the same transaction has exactly one `OP_RETURN` whose single push is 32 bytes, the first 12 of
   which are zero (an Ethereum address, left-padded), not beginning `0x5956`; and exactly one
   `WYEC` V output (a lock transaction with two V outputs is not minted, HK-3: keeps `lockId ↔
   destination` unambiguous);
4. value ≥ `MIN_LOCK` and ≤ `MAX_LOCK` (operator policy, for the Ethereum mint cap);
5. ≥ `C_Y` confirmations (mainnet proposal 40 ≈ 50 min; Q-1) and the block is still on the
   attestor's active chain at signing time.

`lockId = SHA256(txid_internal(32) ‖ vout(u32 LE))` (wyec design E-5, made exact here). Mint
`to` = the last 20 bytes of the destination; `amount` = the V's value in zatoshi.

### 4.2 `ycashRecipient` (bytes32)

```
byte 0      version = 0x01
byte 1      kind    = 0x00 P2PKH | 0x01 P2SH
bytes 2..11 zero
bytes 12..31 hash160
```
The recipient script is `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` or
`OP_HASH160 <20> OP_EQUAL`; `recipientHash = SHA256(script)`. Shielded recipients are out of scope
(intents commit a transparent script; cf. upgrade D-U1): the user shields after release. Ycash
address prefixes: mainnet `{0x1C,0x28}` P2PKH / `{0x1C,0x2C}` P2SH; testnet and regtest
`{0x1C,0x95}` / `{0x1C,0x2A}` (ycash-dd `src/chainparams.cpp:155,157,420,422`).

### 4.3 The Hawkeye memo (`OP_RETURN`, 73 data bytes ≤ 80, script 75 bytes `6a 49 …`, `MAX_OP_RETURN_RELAY`)

```
magic    4   "HKB1" (0x48 0x4B 0x42 0x31) — never 0x5956 ("YV"), so never parsed as an act
kind     1   0x01 burn release | 0x02 roll
chainId  8   u64 LE, the Ethereum chain id (1 mainnet, 11155111 Sepolia, 31337 anvil)
bridge  20   the WyecBridge address
ref      8   u64 LE: kind 1 → the burn nonce; kind 2 → the new V's ownerHeight
data    32   kind 1 → the burn's Ethereum txhash; kind 2 → SHA256(new V scriptPubKey)
```
A roll is checked inside the window from the intent alone: the watcher rebuilds the new V from the
spent V (same tag, sets, delay, owner key, appHeight 0) with `ownerHeight = ref`, and requires
`SHA256(new V spk) = data = the intent's recipientHash`, the spent V to match the intent's
`vaultHash`, and `ref ≥ tip + MIN_OWNER_AGE − ROLL_MARGIN` (revision 1 had `ref = 0` and a parameter
hash, which a watcher cannot invert before the release reveals the V).

An unlock carries exactly one memo; one burn ↔ one intent (no batching in v1; HK-8). The memo's
`(chainId, bridge)` must equal the configured deployment, so a memo for another deployment (Sepolia
replayed on mainnet) is unmatched.

### 4.4 EIP-712

Domain `{name: "WyecBridge", version: "1", chainId, verifyingContract: bridge}`; types exactly as
`WyecBridge.sol` (`Mint(bytes32 lockId,uint256 amount,address to)`, `SetGuardians(address[]
guardians,uint8 threshold,uint256 adminNonce)`, `SetPaused(bool paused,uint256 adminNonce)`,
`SetBridge(address newBridge,uint256 adminNonce)`). Signatures are 65-byte `r‖s‖v`, low-S, sorted by
recovered address ascending in `sigs[]` (the contract's distinctness rule). Vectors are generated
by Foundry against the pinned wyec commit and checked by `hawkeye-core` (§7).

### 4.5 Set-signature attribution

For an intent spend, Hawkeye recomputes `msg = SHA256d("YcashSetSig" ‖ setId ‖ role ‖ prevout ‖
sighash)` (§15.2 step 4), taking `sighash` from the node (`set_signunlock`/`set_signcancel` results,
or ZIP-243 recomputed in H8), and recovers the signer from the 65-byte signature in the scriptSig.
Vectors: the node's `src/test/data/vault_vectors.json` (`setSigMsgs`, `signatures`), byte-identical on
both lines.

---

## 5. The engine

### 5.1 State machines (persisted in SQLite, one row per object, every transition logged)

```
Lock:   SEEN → CONFIRMED → POLICY_OK | POLICY_REJECTED
        POLICY_OK → SIGNED → (MINT_SUBMITTED | PROPOSED → CHALLENGED | EXECUTED) → MINTED
        any → REORGED (the lock left the active chain: signatures already given are recorded as
              exposure; with CR-W1 the proposal is challenged)
Burn:   SEEN(unfinalized) → FINALIZED → (ORPHANED | ASSIGNED(leader, deadline))
        ASSIGNED → INTENT_PENDING(intent) → INTENT_CONFIRMED → RELEASED
        INTENT_* → CANCELLED (by a watcher; the burn returns to FINALIZED for reassignment)
        FINALIZED → WAITING_CAP(epoch) when S-3 would refuse
Intent (any, seen on Ycash): OBSERVED → MATCHED(burn | roll) | UNMATCHED → CANCEL_SENT →
        CANCELLED | MATURED_UNMATCHED (alarm: the window was missed)
Vault:  LIVE → ROLL_DUE → ROLLING → ROLLED ; LIVE → SPENT
SlashCase: OPENED(evidence) → VOTED(mine) → SUBMITTED → SLASHED | EXPIRED
```

### 5.2 Leader schedule (HK-9)

Attestors are ordered by member key. For burn nonce `n` the leader is `live[n mod |live|]`; if no
intent for `n` appears within `TAKEOVER` blocks (mempool counts), the next attestor in order takes
over, and so on. Mints use the same rule over `lockId mod |live|`. Every attestor still *verifies*
every mint and intent; leadership only decides who spends fees. Two intents for one burn within the
takeover overlap are a benign race: the later one is cancelled, nobody is slashed.

### 5.3 Watcher and slash flow

1. On every new Ycash tip **and** every mempool change: list `WYEC` intents under the set
   (`vault_list {"tag":"WYEC","kind":"intent"}`, plus mempool transactions spending `WYEC` vaults,
   decoded locally), classify (§3.2), and cancel unmatched ones at once: `vault_buildcancel` →
   `set_signcancel` → `vault_send`. One cancel per intent per attestor (the node returns the same
   cancel while its fee inputs are unspent, finding (65)); Hawkeye never re-funds a cancel.
2. On every finalized Ethereum block: list `Minted` (and, with CR-W1, `MintProposed`) events,
   check each against a policy-OK lock; challenge unmatched proposals at once.
3. Each fault opens a `SlashCase` with a self-contained evidence bundle (transactions, signatures,
   the recovered key, the reason). The case is gossiped to other Hawkeyes over the authenticated peer
   channel (H5, §6) or exchanged out of band; each Hawkeye **verifies independently**, then
   contributes its act signature: `set_buildact remove {burn:1}` by the case owner →
   `set_signact` on each verifying peer's node → `set_sendact` once `slashThreshold` is reached.
   `auto_slash = true|false` per operator (default false on mainnet: an operator confirms).
4. Equivocation proofs (`set_equivocation`) need no vote and are submitted automatically.

### 5.4 Reorgs

- Ycash: Hawkeye follows `getbestblockhash` and rewinds its ledger by block hash; a lock that leaves
  the chain after its mint was signed is an **exposure** (alarm); `C_Y` makes it rare.
- Ethereum: only `finalized` blocks are acted on; `latest` is used for display and early warning.

### 5.5 Rate limit and fees

Before building an unlock, the leader reads `set_getinfo.unlockavailable`; if the burn does not fit,
it waits for the next epoch (as bridge-sim does), FIFO by burn nonce, never splitting a burn across
epochs in v1 (HK-8). Ycash fees come from the leader's transparent coins (keep ≥ 8 coins, finding
(76)); Ethereum gas from the leader's account. Protocol fees (O-2 "bps fee") are out of v1 (Q-4).

---

## 6. Architecture

```
hawkeye/                     Cargo workspace, edition 2024, rust-toolchain pinned
├── crates/
│   ├── hawkeye-core/        pure, no I/O: §4 encodings, V/I/bond template parsers (port of
│   │                        vault.py), memo codec, recipient codec, lockId, EIP-712 digests,
│   │                        recoverable secp256k1 (k256), eth address derivation, lock policy,
│   │                        intent/mint matching, leader schedule — golden vectors in tests/
│   ├── hawkeye-ycash/       ycashd JSON-RPC client typed to vault-rpc-contract.json (+ stock RPCs),
│   │                        a v4 transparent tx codec (decode, insert memo, re-encode, txid),
│   │                        a mock ycashd for tests
│   ├── hawkeye-eth/         alloy: WyecBridge/WrappedYcash bindings (sol! from the pinned ABI),
│   │                        finalized-block event scanner, EIP-712 signer, mint submitter (both
│   │                        modes), guardian-set reader
│   ├── hawkeye-store/       SQLite ledger (rusqlite, migrations), sign-once table, evidence store
│   └── hawkeye/             the binary: config, engine (§5), roles, CLI, metrics, logging
├── eth/                     Foundry: fetches wyec at a pinned commit, deploy scripts (anvil,
│                            Sepolia), tests of Hawkeye's assumptions about the contract,
│                            EIP-712 vector generator
├── devnet/                  anvil + regtest ycashd orchestration, scenario scripts
├── docs/                    this plan, operator guide, runbooks
└── config/                  hawkeye.toml samples per network
```

**Interfaces only (workspace rule 2).** `ycashd`: `getblockchaininfo`, `getbestblockhash`,
`getblock`, `getrawtransaction`, `getrawmempool`, `validateaddress`, `importprivkey`, `listunspent`,
the 21 `set_*`/`vault_*` RPCs. Ethereum: standard JSON-RPC (`eth_getLogs` with `finalized`,
`eth_call`, `eth_sendRawTransaction`, `eth_chainId`). No `yed_*` call: `WYEC` is not a module tag.

**Config** (`hawkeye.toml`): network; ycashd URL and cookie; Ethereum URL, chain id, bridge and
token addresses, deploy block; set id; mint mode and `k`; `C_Y`, `MIN_OWNER_AGE`, `ROLL_MARGIN`,
`TAKEOVER`, `heartbeat_blocks`, `MIN_LOCK`/`MAX_LOCK`; keystore path; `auto_slash`; peers.

**Operations.** Structured logs (`tracing`, JSON), Prometheus metrics (`/metrics`: heights, lag,
pending burns, intents, cancels, supply margin, set liveness, key balance), a read-only status API
(`/status`, `/burns/<nonce>`, `/locks/<lockId>` with the mint signatures so users can self-submit),
a systemd unit and a container image. Peer channel (H5): authenticated by member keys; v1 may use
plain HTTPS between known operators, reusing the attest agent's iroh-gossip later (ycash-dd
`contrib/yellowback/attest`).

**Dependencies.** Exact pins, `Cargo.lock` committed, `cargo build --locked`, `cargo deny` (the
attest agent's discipline). Candidate set: `tokio`, `alloy` (provider, sol-types, signer-local,
rpc-types), `k256` (ecdsa, recoverable), `sha2`, `sha3`, `rusqlite` (bundled), `reqwest` (rustls),
`serde`/`serde_json`/`toml`, `clap`, `tracing`, `thiserror`/`anyhow`, `hex`, `axum` (status API),
`eth-keystore`.

---

## 7. Tooling and test strategy

| Layer | Tool | What it proves |
|---|---|---|
| Encodings | `cargo test` + golden vectors: node `vault_vectors.json` (templates, set-sig messages, signatures), Foundry-generated EIP-712 vectors, Hawkeye's own memo/recipient vectors | byte-exact agreement with both node lines and the contract |
| Contract assumptions | `forge test` in `eth/` against wyec @ pinned commit | `lockId` replay, ascending signers, `BurnToYcash` shape, predicted-address deploy, guardian rotation, pause |
| Ycash adapter | mock ycashd answering per `vault-rpc-contract.json`; recorded fixtures | request shapes, error-reason mapping (−26 `bad-vault-*`, `set-sign-once`, …) |
| Ethereum adapter | anvil (local, instant finality via `--slots-in-an-epoch 1`) | scanning `finalized`, mint submission, both modes (CR-W1 via a test double until wyec ships it) |
| Engine | deterministic simulation: fake chains, injected faults | every state machine edge, reorgs, races, takeover |
| End to end | anvil + regtest `ycashd` (`-nuparams=6d5b7a31:<h>`), 3 Hawkeyes | the flows of §1 and the drills of §8 on both node lines |
| Public | Sepolia + a public Ycash devnet (or testnet once it has the upgrade) | real finality, real gas, real operators |

Local Ethereum tooling: Foundry (`forge`, `anvil`, `cast`). In environments where the Foundry
installer and the native `solc` download are blocked, Foundry's npm packages
(`@foundry-rs/forge`, `@foundry-rs/anvil`, `@foundry-rs/cast`) with `solc`-js behind a small
`--standard-json` shim work (`eth/tools/solc-shim.js`).

---

## 8. Adversarial drills (H6 on regtest, H7 on Sepolia + devnet; feed upgrade gate G-12)

| # | Drill | Pass condition |
|---|---|---|
| D-1 | Happy path, both directions, 3 attestors | lock → mint; burn → intent → release; supply invariant holds |
| D-2 | Rogue intent (a member signs an unlock with no burn) | cancelled within the window by ≥ 1 other Hawkeye; slash case reaches `SET_REMOVE burn=1` |
| D-3 | Double release (second intent for a consumed burn) | cancelled; slashed (outside the race window) |
| D-4 | Wrong amount / wrong recipient intent | cancelled; slashed |
| D-5 | Rogue mint (k = 1 today; proposal with CR-W1) | today: detected and alarmed, slash case opened; CR-W1: challenged before execute |
| D-6 | Equivocation (one key, two unlocks of one vault) | `set_equivocation` submitted automatically; member ejected |
| D-7 | Leader down | takeover after `TAKEOVER` blocks; exactly one release |
| D-8 | Rate limit exhausted | burns wait FIFO for the next epoch; none lost |
| D-9 | Ycash reorg across a lock before `C_Y` | no mint; after `C_Y` alarm path exercised with `invalidateblock` |
| D-10 | Ethereum reorg (anvil `anvil_reorg`) below finality | no intent posted for an unfinalized burn |
| D-11 | All attestors silent | set DORMANT; `hawkeye recover` returns every vault to its owner |
| D-12 | Wind-down | `SET_WINDDOWN`; owners recover after `livenessWindow` |
| D-13 | Vault approaching `ownerHeight` | rolled into a fresh vault; watchers verify the roll memo |
| D-14 | Orphaned burn (malformed recipient) | held, reported, never released |
| D-15 | Guardian rotation (join + remove on Ycash, `setGuardians` on Ethereum) | Hawkeye detects drift, refuses to sign until both agree |
| D-16 | Restart / crash mid-flow | no double signature, no lost burn (ledger + sign-once) |

---

## 9. Phases

| Phase | Content | Exit criterion |
|---|---|---|
| **H0** plan + skeleton | this document; Cargo workspace; CI; README; AGENTS.md | `cargo test` green on the empty workspace |
| **H1** core | §4 encodings, template parsers, memo/recipient codecs, lockId, EIP-712, key derivation, set-sig recovery, lock policy, matcher, leader schedule | node vectors and Foundry vectors pass; ≥ 90 % line coverage on `hawkeye-core` |
| **H2** Ycash adapter | typed client for the 21 vault RPCs + stock RPCs; v4 tx codec + memo insertion; mock ycashd | client round-trips every contract shape; codec reproduces txids of node fixtures |
| **H3** Ethereum adapter + `eth/` | Foundry project pinned to wyec; deploy scripts (anvil, Sepolia); vector generator; alloy bindings, finalized scanner, signer, submitter | `forge test` green; adapter tests against anvil green |
| **H4** store + engine | SQLite ledger, sign-once, state machines, leader schedule, watcher, slash cases, simulation tests | every §5.1 transition covered in simulation, incl. D-2..D-8, D-16 in sim |
| **H5** daemon | config, roles, CLI (`init`, `enroll`, `run`, `status`, `lock`, `burn`, `recover`, `slash`), metrics, status API, peer channel v1 | `hawkeye run` against anvil + mock ycashd completes D-1 |
| **H6** end to end | devnet orchestration with real regtest ycashd (both lines) + anvil; drills D-1..D-16 | all drills green on ycash-dd and ycash6 `upgrade/vault` |
| **H7** Sepolia | deploy wyec @ pin to Sepolia (predicted-address script, Etherscan verify); 3–5 operator Hawkeyes against a public Ycash devnet; a public test week | drills D-1, D-2, D-5, D-7, D-11 on Sepolia; runbook reviewed |
| **H8** release | external review of Hawkeye + the contract audit (P5); remote signer; mainnet parameters (Q-1); release with the upgrade's P8 | the upgrade plan's gates; Foundation sign-off |

H1, H2 and H3 run in parallel; H4 needs H1; H5 needs H2–H4; H6 needs a built `ycashd`.

**The success criterion of this round (owner, 2026-10-07):** Hawkeye demonstrably runs as a sidecar
next to a real `ycashd`. `devnet/` therefore owns a self-contained devnet: N regtest `ycashd` nodes
built from `ycash-dd` `upgrade/vault` (later also `ycash6`), activated with
`-nuparams=6d5b7a31:<h>`, one anvil chain with wyec deployed by `eth/script/Deploy.s.sol`, and one
Hawkeye per attestor node, each talking only to its own node's RPC. `devnet/hawkeye-devnet up |
lock | burn | rogue | silence | status | down` mirrors `bridge-sim`'s commands so the two can be
compared; the drills of §8 run as scripted scenarios with a transcript committed as evidence.
The node binary is built outside this repository (`devnet/README.md` records the recipe);
Hawkeye never patches the node.

### Sepolia runbook (H7, run where Sepolia is reachable)

```
cd eth && ./tools/fetch-wyec.sh            # wyec @ pinned commit into eth/vendor/wyec (gitignored)
export SEPOLIA_RPC_URL=... DEPLOYER_KEY=... ETHERSCAN_API_KEY=...
GUARDIANS=0x..,0x..,0x.. THRESHOLD=1 forge script script/Deploy.s.sol \
    --rpc-url $SEPOLIA_RPC_URL --private-key $DEPLOYER_KEY --broadcast --verify
# writes deployments/sepolia.json {chainId, bridge, token, deployBlock, guardians, threshold}
hawkeye --config config/sepolia.toml status
```
Guardian addresses come from the Ycash set: `hawkeye keys eth-address --set <setid>` derives them
from the members' compressed keys.

---

## 10. Change requests outside this repository (owner / coordinator; Hawkeye commits none of them)

| # | Repo | Change | Why | Blocking? |
|---|---|---|---|---|
| CR-W1 | wyec | Optimistic mint: `proposeMint(lockId, amount, to, sig)` by one guardian → `MINT_CHALLENGE_WINDOW` → `executeMint(lockId)` by anyone; `challengeMint(lockId)` by any guardian deletes the proposal (re-proposable); events `MintProposed`, `MintChallenged`; optional mint `RateLimiter` (E-6); keep the k-of-n `mint` | the Foundation's model on the mint side (§3.3) | mainnet at k = 1 only |
| CR-W2 | wyec | Foundry project (replacing `compile.js`), `Deploy.s.sol` with the predicted-address assertion, ABI artefacts committed | Hawkeye binds the ABI; Sepolia deploy | no (Hawkeye's `eth/` carries it meanwhile) |
| CR-W3 | wyec | Document §4.2's recipient encoding in the contract's NatSpec | one definition | no |
| CR-N1 | ycash-dd, ycash6 | `vault_lock` `"data"` parameter (finding (73)) | wallets write the destination without hand-built transactions | no |
| CR-N2 | ycash-dd, ycash6 | `vault_buildunlock` `"data"` parameter (an OP_RETURN output) | the memo without a tx codec in Hawkeye | no |
| CR-N3 | ycash-dd, ycash6 | cross-set `SET_REMOVE` (finding (26)) | only if the Foundation insists on an open challenger set (§2.1) | no |
| CR-U1 | workspace | upgrade plan §4.1: the recovery row's "no intent names it" is not what the template does; add the single-attestation row to §4.2; reference this plan from §4.3 and P5 | accuracy (§3.1) | no |
| CR-WS | workspace | `repos.yaml`, README components table, CLAUDE.md layout, `docs/mapping.md` §23 rows for Hawkeye | the workspace manifest | no |

---

## 11. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q-1 | Mainnet row of §2 (seats, `delay`, cap, `bondMin`, `livenessWindow`, `C_Y`, `MIN_OWNER_AGE`) | `yb-calibration` derives it with O-13; §2's column is a starting point |
| Q-2 | Should a supply-invariant breach auto-pause the bridge? | alarm only in v1; pause needs `k` signatures anyway |
| Q-3 | Refunds for orphaned burns | threshold mint with the synthetic `lockId`; never at k = 1 |
| Q-4 | Bridge fee (O-2 "bps fee") and who pays Ethereum gas | v1: none; attestors absorb fees; revisit with CR-W1 |
| Q-5 | Who may be an attestor (Foundation-chosen operators?) and the admission key's custody | the Foundation picks the first set; `admitKey` retires once `slashThreshold` members are current |
| Q-6 | Ethereum L1 only (O-4) or also an L2 | L1 first; the memo's `chainId` keeps deployments apart |

---

## 12. Decision record

| # | Decision |
|---|---|
| HK-1 | The Foundation's model is one permissioned set with `unlockThreshold = cancelThreshold = 1`, `slashThreshold` = a majority of the others |
| HK-2 | The vault's `cancelSetId` is the attestor set itself; no open challenger set |
| HK-3 | One `WYEC` V per lock transaction is mintable; others are refused by policy |
| HK-4 | Every unlock carries the 73-byte `HKB1` memo; one burn pays once |
| HK-5 | `ycashRecipient` = version, kind, 10 zero bytes, hash160; transparent only |
| HK-6 | Minimum owner age, drain-nearest-expiry, rolls, and a supply alarm answer F-1 |
| HK-7 | One key on both chains; Ycash signing via the node wallet (its sign-once guard), EIP-712 via Hawkeye with its own sign-once record |
| HK-8 | No batching and no burn splitting in v1 (one burn ↔ one intent ↔ one vault input) |
| HK-9 | Deterministic leader by `nonce mod |live|`, takeover after `TAKEOVER` blocks; every attestor verifies everything |
| HK-10 | Hawkeye reaches the node only through stock and `set_*`/`vault_*` RPCs, and Ethereum only through standard JSON-RPC |
