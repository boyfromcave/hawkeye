# Operating a Hawkeye bridge attestor

This is the operations runbook for a member of a wYEC (Ethereum) or nYEC (NEAR) bridge attestor
set: the person who runs `ycashd` and `hawkeye` with a member key. It is normative for operators.
Print the checklists. Read sections 1–5 before `hawkeye enroll`.

The design is in [`hawkeye-bridge-plan.md`](hawkeye-bridge-plan.md); the commands are in the
[README](../README.md). This is **not** the YED price attestor guide (`yellowback-attest`,
`ycash-dd/doc/yellowback-attestor.md`): that is another program with another key.

Contents: 1 what you run and what it can lose · 2 the single-instance rule · 3 hosts and users ·
4 key ceremony · 5 backups and `audit-ledger` · 6 moving hosts · 7 rotation order · 8 parameters
that must agree · 9 monitoring and the alarm table · 10 incident response · 11 upgrades and
migrations · 12 quick reference.

---

## 1. What you are running and what it can lose

One **member key** (secp256k1) is, at once: your seat and set signature in the Ycash attestor set,
the key your **bond** is bound to, and your **guardian** key in the bridge contract (EIP-712 on
Ethereum, `ecrecover` on NEAR). On mainnet a separate **gas key** (`[eth] sender_keystore`) sends and
pays for your Ethereum transactions; the member key only signs.

| Who holds a copy of… | …can do |
|---|---|
| the member key | sign fraudulent intents, cancels and slash votes on Ycash; sign fraudulent `Mint` proposals and admin rounds on the bridge; spend your bond once its exit delay has passed; make you equivocate (below) |
| `wallet.dat` in `ycash_signing = "wallet"` mode | the member key, in clear (Ycash has no wallet encryption) |
| the RPC cookie or password in `"wallet"` mode | the member key (`dumpprivkey`) and every set signature |
| the gas key | your gas balance only |
| `hawkeye.db` | no key; but a stale or second copy can make you equivocate |

**The equivocation rule.** Two different set signatures by one key over two different spends of one
outpoint (the same `(set, prevout)`) are public, objective proof: anyone submits
`SET_EQUIVOCATION` and you are **ejected with your bond frozen** (plan §2.3). Two unlocks for one
burn are also a double release the other attestors must cancel. Hawkeye never does this on its
own: every signature goes through a sign-once record (the node wallet's `vaultsetsig` record in
`"wallet"` mode, and Hawkeye's ledger `hawkeye.db` always). Those records are **per machine**. The
rest of this runbook exists to keep exactly one machine signing.

## 2. The single-instance rule

Exactly one `ycashd` that can sign with the member key, exactly one `hawkeye run`, one ledger file,
**ever**. Forbidden:

- a hot standby holding a copy of `wallet.dat`, the keystore or `hawkeye.db`;
- starting a restored backup while the original host may still run;
- a second Hawkeye on a second node with the same key;
- `hawkeye run` twice against one node or one ledger (SQLite serialises the writes, but each process
  has its own in-memory state and will build its own unlock);
- cloud auto-recovery or an autoscaling group that boots a VM image containing `wallet.dat`,
  the keystore or `hawkeye.db`.

In `ycash_signing = "self"` mode (the mainnet example) the node wallet never holds the member key,
so **`hawkeye.db` is the only equivocation guard**. Treat it like the key itself.

## 3. Hosts and users

- A dedicated host or VM per attestor. `ycashd` and `hawkeye` run as two separate unprivileged
  users; only the `hawkeye` user reads the keystore and the ledger.
- `ycashd` with `txindex=1`, `rpcbind=127.0.0.1`, cookie or user/password auth. Hawkeye refuses a
  plain `http://` RPC URL to another host unless `[ycash] allow_insecure_rpc = true` (mainnet logs
  it as an error).
- `wallet.dat`, the keystore, the gas keystore and `hawkeye.db` on an encrypted volume.
- The API (`[api] listen`, default `127.0.0.1:7801`) on loopback behind a reverse proxy that
  terminates TLS. Only the other attestors reach it (firewall, and optionally `[peers]
  allow_from`). `[peers] urls` are `https://` (mainnet refuses anything else that is not loopback).
- File modes: `hawkeye.toml` 0600 (if it holds a secret), keystores 0600, `hawkeye.db` and its
  `-wal`/`-shm` 0600 (Hawkeye creates the ledger 0600 and holds the side files to it), the node's
  `.cookie` 0600. On mainnet Hawkeye refuses group- or world-readable key files, configs with
  secrets and ledgers (`--insecure-file-permissions` overrides; don't).
- Your own Ethereum execution + consensus client (or NEAR RPC). Hawkeye reads `finalized` and, since
  the latest-block watcher (05/H-2), **one extra `eth_getLogs` per tick** over the unfinalized
  range (`(finalized, latest]`, at most about 70 blocks on Ethereum, re-reading 64 below the last
  scan) with two topics (`MintProposed`, `MintChallenged`). Negligible on a self-hosted node;
  within the free tier of hosted providers at one tick per second, but count it if you share a key.

## 4. Key ceremony

Do this once per member key, on an **offline** machine, with two people.

1. Generate 32 random bytes: `openssl rand -hex 32` (or `cast wallet new`).
2. Print what the key is: `hawkeye keys derive --secret <hex>` → `memberkey` (33-byte compressed),
   `eth_address` (the guardian on Ethereum), `near_guardian` (64-byte key on NEAR). Record all three.
3. Encrypt it: `HAWKEYE_SECRET=<hex> HAWKEYE_KEYSTORE_PASSWORD=<pw> hawkeye keys encrypt --out
   member-key.json` (keystore v3, created 0600). Clear the shell history. Never put the password in
   the config: `[keys] password_env` names the variable that holds it at run time.
4. Do the same for a separate **gas key** (`[eth] sender_keystore`, `sender_password_env`): mainnet
   refuses to start without one, and refuses the member key as the sender. Fund it; `gas-low` fires
   below `[eth] min_sender_balance_wei` (default 0.05 ETH on mainnet).
5. Escrow: one copy of `member-key.json` plus its password, sealed, held by two custodians apart.
6. Move the keystore to the host. Use `[keys] ycash_signing = "self"` (mainnet example): Hawkeye
   computes and places every set and act signature itself, and the node wallet holds only fee coins.
   In `"wallet"` mode, `hawkeye enroll` imports the member key into `wallet.dat`, **in clear**:
   from that moment anyone who reads the wallet or the RPC credentials has it. An attestor moving
   from `"wallet"` to `"self"` should rotate (section 7): the old secret has been in `wallet.dat`.
7. Join the Ycash set with your bond (`set_join`, plan §2.4) and fund the node wallet's fee coins
   (`hawkeye split-coins --count 16`). In `"wallet"` mode, once the `SET_JOIN` is mined the node
   wallet carries a **restore marker** (it imported a member key, 07/F-5) and signs nothing
   (`set-sign-restored`, alarm `node-sign-restored`) until you run **`hawkeye acknowledge-restore`**:
   it audits the ledger against the node, imports the ledger's sign-once records
   (`set_importsigned`) and clears the marker (`set_acknowledgerestore`). For the fresh key of
   this ceremony that is a true statement; never run it for a key another host may have used.
8. Hand `eth_address` (or `near_guardian`) to the governance round (section 7).

| Step | Done by | Signature |
|---|---|---|
| 1–3 key generated, derived, encrypted offline | | |
| 4 gas key generated and funded | | |
| 5 escrow sealed (two custodians) | | |
| 6 keystore on the host, `ycash_signing` set | | |
| 7 `set_join` mined, fee coins split (`"wallet"` mode: `acknowledge-restore`) | | |
| 8 guardian address handed over | | |

## 5. Backups and `audit-ledger`

**What, always together:** `wallet.dat` (fee keys; in `"wallet"` mode the member key and the node's
sign-once records), `hawkeye.db` with its `-wal` and `-shm`, the keystores, and `hawkeye.toml`.

**When:** with **both** daemons stopped (`systemctl stop hawkeye ycashd`), never while running: the
two files would be from different instants. Take one before every upgrade (section 11).

**How:** `tar` the set, encrypt it (`age`, `gpg`), keep two generations off-host.

**Restore** only onto a host where the original is **destroyed or powered off for good**
(section 2). Then, before `hawkeye run`:

1. start `ycashd` and let it sync;
2. `hawkeye status` (read-only);
3. **`hawkeye audit-ledger`**. It opens the ledger read-only (never migrating or writing it) and
   compares it with the node: every Ycash sign-once record of the set with whether its outpoint is
   still unspent, and every unlock **this member signed** that the node still shows — behind the
   set's unspent intents and in the mempool — with no record here. One missing record means
   *ledger is behind the chain: records for vault X missing*, and the command exits non-zero;
4. if anything is missing, or you are in any doubt, **do not sign from this ledger**: leave with
   the key (section 7) and rejoin with a fresh one.
5. in `"wallet"` mode the node keeps its own sign-once records in `wallet.dat` (07/F-5): a wallet
   restored from its seed, or one that imported the member key, carries a **restore marker** and
   refuses to sign (`set-sign-restored`, which Hawkeye logs and retries, signing nothing) until the
   old wallet's history is imported and acknowledged: `set_listsigned` on the old wallet (or the
   `vaultsetsig=` lines of its `dumpwallet`), `set_importsigned` on the new one, check with
   `set_listsigned`, then `set_acknowledgerestore` — only when no other copy of the key can have
   signed since (`hawkeye acknowledge-restore` does all three from this ledger, after its audit).
   A `wallet.dat` restored by copying the file has no marker: the single-instance
   rule (section 2) is the only defence. In `"self"` mode the node holds no member key and
   `hawkeye.db` is the record.

`hawkeye run` performs the same audit at start and **refuses to start** when a record is missing;
`--i-accept-equivocation-risk` overrides it, for the case where you know the original copy can never
sign again (and accept that the vaults named may be ones you signed). Sign-once records are never
deleted; a restored ledger older than your last signature is exactly the equivocation risk.

## 6. Moving hosts

1. `systemctl stop hawkeye ycashd` on the old host.
2. Back up (section 5).
3. Wipe `wallet.dat`, the keystores and `hawkeye.db` on the old host, or power it off for good.
4. Restore on the new host; start `ycashd`; wait for sync.
5. `hawkeye audit-ledger`, then `hawkeye status`.
6. `hawkeye run`. Update the other attestors' `[peers] urls` if the API address changed.

Never two hosts alive with the key, not even for a minute.

## 7. Rotation order (join / leave)

A rotation has two halves: the Ycash set (`set_join`, `hawkeye leave`) and the bridge contract's
guardians (`setGuardians` on Ethereum, `set_guardians` on NEAR, signed by the **current**
guardians' threshold). Between them the set's current members and the contract's guardians
differ, and every attestor raises **`guardian-drift`**. On mainnet drift **pauses every
attestor's mint-side acts and rolls** (Mint signatures, proposals, executions, threshold mints,
rolls); releases, cancels, challenges, heartbeats and slash votes go on. Keep the gap short.

Hawkeye compares the two at start, on every finalized `GuardiansChanged`, and every 60 ticks (about
a minute): drift raised by a Ycash-side change can take up to that long to appear or clear.

| Step | Who | What |
|---|---|---|
| 1 | new attestor | key ceremony (section 4), `set_join` with the bond |
| 2 | everyone | wait until `set_getinfo` shows the new member `current` |
| 3 | governance round | sign `SetGuardians(new set: with the joiner, without the leaver, threshold)` with the current threshold and submit; drift is raised now |
| 4 | leaving attestor | **immediately**: stop its daemon, `hawkeye leave` |
| 5 | everyone | `guardian-drift` clears (within a minute of the leave being mined) |
| 6 | leaving attestor | `hawkeye withdraw-bond` after the set's `maturity` (≥ 16,128 blocks, 14 days, on mainnet) |

- Admin acts share one `adminNonce` (HK-11): run one admin round at a time and agree who submits.
- Leaving first (step 4 before step 3) also raises drift, until the governance round lands: the
  same pause, for as long as the round takes. `hawkeye-devnet scenario rotation` runs both orders
  and checks the alarm.
- **Emergency rotation** (a key is compromised): pause the bridge first (`setPaused(true)` by the
  threshold), then the same order; the compromised member is removed by `SET_REMOVE burn=1` (a slash
  vote), not by leaving.
- **A successor bridge** (wyec-contract-design.md §4.6) is a different migration: (1) deploy the
  successor over the old token with `PREDECESSOR` set (the deployment file records `predecessor`);
  (2) every attestor re-reads it before switching: guardians, threshold, `challengeWindow`,
  `mintCap`, `predecessor` and `token()` (`cast call`; `hawkeye status --params` with the new file
  shows the contract's values against their floors); (3) the guardians sign `SetBridge(newBridge, adminNonce)` on the
  **old** bridge, after which it can neither mint nor burn and its pending proposals are void;
  (4) every attestor switches `[eth] deployment` to the new file in one maintenance window. Hawkeye's
  `Mint` sign-once records are per deployment, so it re-proposes the old bridge's pending locks on
  the successor; burn nonces restart at 0 under the new `(chainId, bridge)` key.

## 8. Parameters that must agree

`hawkeye status --params` prints every value next to its mainnet floor (`OK` / `BELOW FLOOR`), the
set's live parameters and the contract's. Mainnet refuses to start below a floor
(`crates/hawkeye/src/floors.rs`, `hawkeye-eth::mode`); testnet warns at a quarter of them. Start from
[`config/ethereum-mainnet.example.toml`](../config/ethereum-mainnet.example.toml); the P8 values come
from `yb-calibration`.

| Parameter | Must agree with | Floor / rule |
|---|---|---|
| `[bridge] delay` | every bridge vault's `delay` (`params-drift` otherwise) | ≥ 288 and ≥ 4 × `confirmations` |
| `[bridge] confirmations` (`C_Y`) | | ≥ 20 |
| `[bridge] min_owner_age` | | ≥ 105,120 |
| `[bridge] takeover_blocks` | | ≥ `C_Y`, ≤ `delay / 4` |
| `[bridge] roll_margin` | | ≥ `delay + takeover + 2 × C_Y` |
| `[bridge] heartbeat_blocks` | the set's `livenesswindow` (`heartbeat-too-slow`) | ≤ `livenesswindow / 4` |
| `[bridge] max_lock` | one rate-limit window's cap | ≤ 21,000,000 YEC |
| contract `threshold` | | ≥ 2 in every mode |
| contract `challengeWindow` | Ethereum finality + `C_Y` + submission | ≥ 2 h |
| contract `mintCap` | | > 0 (`mint-cap-unbounded`) |
| `[bridge] fallback_to_threshold` | | always on on mainnet |
| `[peers] require_auth` | every attestor's binary (section 11) | true on mainnet |

## 9. Monitoring

Scrape `/metrics` (Prometheus text) and alert on `hawkeye_alarm`. Every alarm the daemon can raise
is in this table (a unit test keeps it in step with the code). *Page* = someone acts now; *ticket* =
within a working day.

| Alarm | Severity | Meaning | Action |
|---|---|---|---|
| `supply` | page | wYEC `totalSupply` exceeds the value of the set's live bridge vaults | pause mints by quorum; reconcile (section 10c) |
| `exposure` | page | a lock this attestor signed left the active chain (a Ycash reorg deeper than `C_Y`), minted or not; off regtest, own mint-side acts pause | have the set pause or lower the cap, reconcile the supply, then `hawkeye exposure list` / `hawkeye exposure ack <lockId> --note …` |
| `fraudulent-mint` | page | a `Minted` or a proposal with no policy-OK lock behind it; challenged, and a slash case opened | check the case (section 10a); vote |
| `matured-unmatched` | page | an unmatched intent passed its cancel window: a release without a burn happened | page the set; slash case; reconcile |
| `guardian-drift` | ticket (page if unplanned) | the set's current members and the contract's guardians differ; on mainnet mint-side acts and rolls pause | finish the rotation (section 7) |
| `not-a-member` | page | this member key is not a current member of the set | check `set_getinfo`; if removed, find out why |
| `eth-finality-stall` | ticket | Ethereum `finalized` has not moved for 1,152 s while the head advanced; on mainnet own proposals, executions and Mint signatures pause, challenges continue | nothing but watch; it clears when finality moves |
| `mint-cap-unbounded` | page | the bridge's `mintCap` was set to 0; on mainnet own mint-side acts pause | a quorum sets a cap again |
| `matching-proposal-challenged` | ticket | someone challenged a proposal that matched a policy-OK lock (griefing, HK-15); the lock is re-proposed, a `GRIEFING` case is open against the challenger, and once every live proposer is barred the threshold fallback mints it (`mint_threshold_fallback` in the log; `[bridge] fallback_to_threshold`) | review the `GRIEFING` case and vote (`SET_REMOVE burn=0`); a second strike by the same challenger is grounds for removal |
| `slash-case-<id>` | page | a slash case waits for this operator (`auto_slash = false`, the mainnet default) | verify the evidence (section 10a) and vote |
| `burn-over-cap` | ticket | a burn larger than the set's whole per-window unlock cap is parked out of the FIFO; later burns are served | governance: a `SET_PARAMS` raising `ratelimitbps`, or a decision to leave it parked |
| `node-sign-restored` | page | `"wallet"` mode: the node wallet refuses every set signature (`set-sign-restored`, 07/F-5): it imported the member key (enrolment) or was restored from a seed, and its restore marker is set; no unlock or cancel is signed | if no other copy of the key can have signed: `hawkeye acknowledge-restore` (section 4 step 7, section 5 step 5); otherwise do not acknowledge, leave with the key |
| `unlock-held` | ticket | this attestor's signed unlock for a burn cannot be sent yet: its vault is spent in the mempool, or by another transaction not yet `C_Y` deep, or it is a drill's (takeover moves the burn on) | check the node's mempool |
| `unlock-dead` | ticket | a signed unlock can no longer confirm: its **vault** was spent by another transaction at least `C_Y` deep (a fee-input spend never makes it dead: it can be re-funded, 01/V-2); one more vault may now be signed for the burn | check the log line `unlock_dead`; nothing to do if a later unlock confirms |
| `roll-overdue` | ticket | vaults past half their `ROLL_MARGIN` without a roll (HK-6) | check the roll leader and the rate limit |
| `roll-waiting-cap` | ticket | rolls wait for rate-limit room | expected under load; governance if it persists |
| `fee-coins-low` | ticket | fewer than 8 confirmed fee coins in the node wallet: a flood of intents can outrun the cancels | fund the wallet; `hawkeye split-coins --count 16` |
| `fee-coins-exhausted` | page | no confirmed coin can fund a cancel | fund the wallet now; `hawkeye split-coins` |
| `gas-low` | ticket | the gas account holds less than `[eth] min_sender_balance_wei` | fund the gas key |
| `heartbeat-too-slow` | page | `heartbeat_blocks` exceeds the set's `livenesswindow / 4`: members would go DORMANT | lower `heartbeat_blocks`, restart |
| `params-drift` | ticket | bridge vaults carry a `delay` other than `[bridge] delay` | fix the config or find who locks with another delay |

Peer trouble is not an alarm: watch `unlock_signature_refused`, `slash_vote_refused` and
`peer_unreachable` log events.

Gauges worth a graph: `hawkeye_ycash_lag_blocks`, `hawkeye_eth_lag_blocks` /
`hawkeye_foreign_lag_blocks`, `hawkeye_eth_finalized_age_seconds`, `hawkeye_eth_finality_stalled`,
`hawkeye_fee_coins`, `hawkeye_sender_balance`, `hawkeye_exposure_unacked`, `hawkeye_burn_over_cap`,
`hawkeye_live_members`, `hawkeye_burns{state}`, `hawkeye_supply_ok`, `hawkeye_alarm{name}`.

Liveness: the set goes DORMANT when no member heartbeats within `livenesswindow`, and then every
bridge vault's owner branch opens (plan §1.4): a dormant set protects nobody. Alert long before.

```yaml
# Prometheus alert rules (examples)
- alert: HawkeyePage
  expr: hawkeye_alarm{name=~"supply|exposure|fraudulent-mint|matured-unmatched|not-a-member|mint-cap-unbounded|fee-coins-exhausted|heartbeat-too-slow|slash-case-.*"} == 1
- alert: HawkeyeTicket
  expr: hawkeye_alarm == 1
  for: 30m
- alert: HawkeyeYcashLag
  expr: hawkeye_ycash_lag_blocks > 10
  for: 10m
- alert: HawkeyeDown
  expr: up{job="hawkeye"} == 0 or increase(hawkeye_ticks_total[5m]) == 0
- alert: HawkeyeFeeCoins
  expr: hawkeye_fee_coins < 8
```

**A signed spend whose fee input is gone** (audit 01/V-2). Set signatures cover the template input
and every output (`SIGHASH_ALL|SIGHASH_ANYONECANPAY`), not the fee inputs, so a signed UNLOCK,
CANCEL or roll stays valid when its fee coin is spent elsewhere. Hawkeye re-funds it by itself:
when `vault_send` answers `bad-txns-inputs-spent`, `Missing inputs` or `txn-mempool-conflict`, it
calls `vault_refee`, checks that only the fee inputs changed (log `refee`; a refusal is
`refee_refused` / `refee_failed`) and sends the re-funded spend, with no new signature. A leader's
unlock whose fee input is gone is therefore re-sent, never declared dead: anyone holding its bytes
could re-fund it, so signing another vault for the burn could pay it twice.

**One revivable unlock per burn (01/V-2 on 05/N-1).** The rule every attestor follows: it never
signs a second unlock for a burn while an unlock it signed for that burn could still confirm, and
an unlock stops being revivable only when its **vault** is spent by another transaction at least
`C_Y` deep (log `unlock_dead`) or the burn is paid. In practice:

- an unlock this attestor co-signed (`unlockThreshold > 1`) and now leads after a takeover is
  re-sent re-funded (`vault_refee` replaces every fee input: they are the old leader's), with no
  new signature — log `unlock_resend` with `refund=true`;
- a takeover leader that holds nothing for the burn first asks every peer's `GET /burns/<nonce>`
  (field `unlock`: the signed unlock that peer holds for it) and adopts a valid one — log
  `unlock_prior_found` / `unlock_adopted`, then `refee` — instead of building a new unlock; only
  when no peer has one does it sign a fresh vault (the silent old leader's bytes, should they ever
  be revived, are a second intent for a consumed burn: the watchers cancel it as a benign race);
- a co-signer asked again for the same unlock re-funded adds the signature it already made (log
  `unlock_cosign_merged`), and still refuses any other unlock of the vault.

Keep the peer API reachable to the other attestors: a takeover depends on reading the old
leader's `/burns/<nonce>`. By hand: `ycash-cli
vault_refee <signed hex>`, then `vault_send` of the result. Re-funding needs a coin of exactly the
missing value (within 1,000 zatoshi) or makes one with a self-send the spend chains on; keep fee
coins confirmed (`fee-coins-low`). The node also remembers one build per vault and intent
(`vault_buildunlock` / `vault_buildcancel` return it again, `build` `reused`); Hawkeye rebuilds
(`rebuild`) only a build it holds no signature of (log `unlock_rebuild`).

## 10. Incident response

Talk on the set's out-of-band channel first. On mainnet the slash vote is manual (`auto_slash =
false`): verify, then vote.

a. **Suspected key compromise** (yours or another member's): have the threshold pause the bridge
   (`setPaused(true)`), rotate the key out (section 7, emergency), and slash it (`SET_REMOVE
   burn=1`) on evidence.
b. **An equivocation against you**: stop `hawkeye` and `ycashd` at once; preserve logs, the
   ledger and the wallet; find the second instance (section 2). Expect ejection and a frozen bond.
c. **`supply` or `exposure`**: pause mints by quorum (or lower `mintCap`); reconcile wYEC supply
   against the locked vaults; then `hawkeye exposure ack` each lock with a note of what was done.
d. **Ethereum finality stall**: nothing to do; challenges continue at `latest`, own proposals
   resume when `finalized` moves.
e. **Over-cap burn**: a governance decision (raise `ratelimitbps` by `SET_PARAMS`, or leave it).
f. **Peer channel down** (storms of `unlock_signature_refused`): check TLS, `[peers] urls`,
   `require_auth` and the clocks (requests are valid for 60 s).
g. **Ledger corruption**: stop; `sqlite3 hawkeye.db 'PRAGMA integrity_check'`; restore (section 5)
   only with `audit-ledger` clean, otherwise leave and rejoin with a fresh key.
h. **A Ycash reorg deeper than `C_Y`**: the daemon rewinds itself; check `exposure`.
i. **A griefer** (`matching-proposal-challenged`): the fallback mints the lock; vote on the
   `GRIEFING` case.

## 11. Upgrades and migrations

1. Stop `hawkeye` (and `ycashd` if it is upgraded too); back up (section 5).
2. Install the new binary; `hawkeye status --params`; `hawkeye audit-ledger`.
3. Start. Ledger migrations run on the first read-write open (`run`, `status`), are automatic and
   forward-only (schema v9 at this writing). Never run an older binary on a migrated ledger (it
   refuses: `SchemaTooNew`); `audit-ledger` never migrates.

**Peer authentication rollout** (`[peers] require_auth`, HK-13). An old peer cannot sign requests
and an old server ignores the headers: new → old works, old → new fails 401. Upgrade **every
attestor's binary first** with `require_auth = false` (off mainnet), then flip all of them to `true`
in one maintenance window. Mainnet refuses `false`, so a mainnet set deploys straight to `true` and
accepts that slash and cancel gathering is unavailable until the last attestor has restarted.

## 12. Quick reference

| Command | What |
|---|---|
| `hawkeye run [--i-accept-blind-start] [--i-accept-equivocation-risk]` | the daemon; the first override only off mainnet (a start height above the set's oldest bridge vault) |
| `hawkeye status [--json] [--params]` | read-only summary; `--params`: values against floors |
| `hawkeye audit-ledger [--json]` | read-only ledger vs node (section 5); non-zero exit when behind |
| `hawkeye exposure list` / `exposure ack <lockId> --note …` | unacknowledged exposures |
| `hawkeye enroll` | `"wallet"` mode: import the member key (nothing in `"self"` mode) |
| `hawkeye keys derive --secret <hex>` / `keys encrypt --out <file>` | key ceremony (section 4) |
| `hawkeye split-coins [--count N] [--amount YEC]` | fresh fee coins |
| `hawkeye acknowledge-restore` | `"wallet"` mode: import the ledger's sign-once records into the node wallet and clear its restore marker (07/F-5) |
| `hawkeye leave` / `hawkeye withdraw-bond [--to <addr>]` | leave the set; bond after `maturity` |

| File | Mode | Backed up |
|---|---|---|
| `hawkeye.toml` | 0600 if it holds a secret | yes |
| member and gas keystores | 0600 | yes (and escrow) |
| `hawkeye.db`, `-wal`, `-shm` | 0600 | yes, with the daemon stopped |
| `wallet.dat`, `.cookie` | 0600 | `wallet.dat` yes |

Ports: `[api] listen` (default 7801, loopback behind TLS); `ycashd` RPC on loopback; your Ethereum
node's RPC.
