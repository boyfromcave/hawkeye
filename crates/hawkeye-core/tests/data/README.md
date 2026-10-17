# Test fixtures

## `vault_vectors.json`

The vault primitive's golden vector, copied verbatim from the node:

- source: `boyfromcave/ycash-dd` `src/test/data/vault_vectors.json` at commit **`cc8c90764`**
  (`upgrade/vault`; the file is unchanged since **`8af82551b`**, including `ed828e7b2`,
  `7cc440fe9` and this head), byte-identical to `boyfromcave/ycash6` `upgrade/vault`
  **`23515263c`** (checked by sha256: the vector is the same on both node
  lines). New since the copy at ycash-dd `d41026209` (sha256 `4ba21283…80d03`): set
  signatures are over `SIGHASH_ALL|SIGHASH_ANYONECANPAY` (`0x81`, audit 01/V-2), so `spends[0]`
  (`unlock`) and `spends[1]` (`cancel`) have new `sighash`, `setSigMsg`, `sigs`, `scriptSig` and
  `tx`; nothing else changed (`ownerSpends` is untouched: the post-quantum owner signs with the
  hash type its signature carries).
- sha256 `2f7a3ab2fc909bca4772957f15696e8ed5f6feec6914f957e016adf5d0fd7dc8`
- schema and conventions: ycash-dd `qa/rpc-tests/test_framework/VAULT_VECTORS.md`; generator
  `qa/rpc-tests/test_framework/gen_vault_vectors.py` (both at the same commit)

Do not edit it. To update, copy the node's file again (from either line, after checking the two
are identical), record the new commit and hash here, and re-run `cargo test -p hawkeye-core`.

`tests/vault_vectors.rs` replays `pqOwner`, `falconOwner` (the id of the public key), `vaults`,
`vaultsInvalid`, `intents`, `intentsInvalid`, `bonds`, `selectors`, `selectorsInvalid`,
`setSigMsgs`, `signatures`, `signaturesInvalid`, the act messages and signatures of `acts`, the
set signatures inside `spends`, and in every `ownerSpends` case the selector, the chunked
scriptSig shape, the reassembled public key against the template's owner and the ZIP-243
sighash. The SLH-DSA and Falcon signatures themselves are **not** verified: Hawkeye has no
post-quantum signature code (the node signs owner spends), and `verify` (`script` /
`signature`) needs the node's interpreter and set state.

`tests/attribution.rs` runs every `spends` case through `attribution::attribute_template_input`
(it must name exactly the recorded signers, with the recorded sighash — `0x81`, and not the plain
`SIGHASH_ALL` one — and `setSigMsg`) and the negative cases built from them.

## `sighash.json`

The node's transparent signature-hash vector, copied verbatim:

- source: `boyfromcave/ycash-dd` `src/test/data/sighash.json` at commit **`cc8c90764`**
  (branch `upgrade/vault`; unchanged since `dbc1ab0`, including `ed828e7b2` and `7cc440fe9`, and
  unchanged from Ycash v4.5.0's Zcash lineage)
- sha256 `6e10f3e5649c876a8968a3ba13885aeb8dcee8040fd89e7e39651b041d07f30c`
- rows `[raw_tx, scriptCode, nIn, hashType, branchId, sighash]`, amount 0, `sighash` printed by
  `uint256::GetHex()` (display order: reverse it for the internal bytes);
  harness ycash-dd `src/test/sighash_tests.cpp` `sighash_from_data`
- `ycash6`'s copy differs (the Zcash 6.x lineage regenerated it); the v4.5.0 line's is the one
  for ZIP-143/243 and is what this crate checks. The v3/v4 sighash itself is the same on both
  lines.

Do not edit it. `tests/sighash.rs` checks all 269 overwintered rows (139 Overwinter v3 via ZIP-143,
130 Sapling v4 via ZIP-243, covering ALL / NONE / SINGLE with and without ANYONECANPAY, shielded
spends and outputs, and JoinSplits) and round-trips each transaction through `tx::Transaction`;
the 231 Sprout (v1/v2) rows are counted and skipped.

## `eip712_vectors.json` (optional)

Foundry-generated `Mint` digests (phase H3, `eth/`). When the file exists, `tests/eip712.rs`
checks every case; it may also be pointed at with `HAWKEYE_EIP712_VECTORS=<path>`. Shape: a
JSON array (or an object with the array under `"mint"` or `"cases"`) of

```json
{
  "domain": {"chainId": 31337, "verifyingContract": "0x…", "name": "WyecBridge", "version": "1"},
  "lockId": "0x…32 bytes",
  "amount": "250000000",
  "to": "0x…",
  "digest": "0x…32 bytes"
}
```

`amount` and `chainId` may be JSON numbers or decimal strings; `name`/`version` are optional
and, when present, must be the contract's.

## `recipient_vectors.json`

Hawkeye's own golden vectors for the `ycashRecipient` encoding (`docs/hawkeye-bridge-plan.md`
§4.2 revision 2, HK-5; phase R4). They were **derived independently in Python** from the plan
text alone (`gen_recipient_vectors.py` beside this file: a hand-rolled base58, `hashlib` SHA-256,
the opcode bytes of the three scripts written out; no `hawkeye-core` code), so
`tests/recipient_vectors.rs` is a cross-check of the Rust codec, not a replay of it. The
`TX_PQPKH` script bytes (`20 <keyHash> 51|52 c2`) were cross-checked against the node's
`GetScriptForPQKey` (ycash-dd `upgrade/vault` `ed828e7b2` `src/script/standard.cpp:338`:
`CScript() << ToByteVector(id.hash) << CScript::EncodeOP_N(id.scheme) << OP_CHECKPQSIG`) and the
`sq…`/`tq…`/`rq…` versions against `src/key_io.cpp:23-27` and `src/test/pq_address_tests.cpp`
(`sq_roundtrip_per_network`: the leading characters and the 53-character length; the node's
tests use random hashes, so there is no address literal to compare). The P2PKH/P2SH addresses
and the PQ owner addresses reproduce the known strings `address.rs` already pins.

- sha256 `b736d9760cd9c6575d80f417a1acdae8793eb6ab35d230fd83bcf524ef6acbe5`

Conventions: hex is lowercase without `0x`; `kind` and `scheme` are small JSON numbers. Top-level
keys:

| Key | Contents |
|---|---|
| `version` | `2` (the encoding revision) |
| `valid[]` | `{note, kind, kindName, scheme?, hash, bytes, script, recipientHash, addresses}`: P2PKH and P2SH over `20 × 5a` and `20 × ab`, PQPKH scheme 1 over the node vector's `pqOwner` hash, scheme 2 over `32 × ff`, both schemes over the node's D-Q-21 known-answer hash `32 × 5a`, scheme 1 over `32 × 00`; `bytes` is the 22- or 35-byte field, `script` the recipient scriptPubKey, `recipientHash = SHA256(script)`, `addresses` the `mainnet` / `testnet` / `regtest` strings |
| `invalid[]` | `{note, bytes, reason}`: fields `YcashRecipient::from_bytes` must refuse — revision 1's 32 bytes, versions 0/1/3, kinds 3/0xff, a kind at the other kind's length, schemes 0/3/0xff, lengths 0/1/2/21/23/32/34/36, a left-padded Ethereum address; `reason` is `wrong length` (checked first), `unknown version`, `unknown kind` or `unknown scheme` |
| `scriptsInvalid[]` | `{note, script}`: scripts `from_script` / `parse_pqpkh` must refuse — the scheme as the data push `01 01` (quantum spec F-1), `OP_0`/`OP_3`/`OP_16` schemes, 31- and 33-byte hashes, a wrong final opcode, a trailing byte, truncations, `OP_RETURN` |
| `ownerAddressesNotRecipients` | the PQ *owner* address (`yb…`/`yt…`/`yr…`) of the scheme-1 key: decodes as an owner, refused by `decode_address` on every network |

To regenerate after a deliberate encoding change (which changes the plan first):

```sh
python3 -I crates/hawkeye-core/tests/data/gen_recipient_vectors.py crates/hawkeye-core/tests/data/recipient_vectors.json
```

then record the new hash here; the file is never written from `hawkeye-core`.

## `near_vectors.json`

Hawkeye's own golden vectors for the NEAR bridge's encodings (`docs/hawkeye-near-plan.md` §2),
generated by `hawkeye-core`; the `wyec-near` contract's tests (phase NH2) check their digests,
Borsh bytes and signatures against this file. To regenerate after a deliberate encoding change
(which changes the plan first):

```sh
HAWKEYE_WRITE_NEAR_VECTORS=1 cargo test -p hawkeye-core --test near_vectors
```

`tests/near_vectors.rs` rebuilds the file from fixed inputs and requires it unchanged, then
re-derives every entry **without** `hawkeye-core`'s encoders: Borsh with the `borsh` crate's
derive (the serialiser `near-sdk` uses), account ids with NEAR's `near-account-id` 3.0.0, and
signatures with raw `k256` verification and recovery.

Conventions: hex is lowercase **without** `0x`; every `u64` / `u128` is a **decimal string**
(`threshold`, `tag`, `kind` and `key` are small JSON numbers); Ycash hashes are internal byte
order. Top-level keys:

| Key | Contents |
|---|---|
| `version` | `1` |
| `digestDomain` | `"HawkeyeNear-v1"` (raw bytes, no length prefix, at the head of every preimage) |
| `keys[]` | `{secret, compressed, guardian}`: the fixed test keys (secrets `0x01…01`, `0x02…02`, `0x03…03`), the 33-byte Ycash member key and the 64-byte guardian id `x ‖ y` |
| `accountIds.valid[]` | `{id, kind}`; `kind` is `named`, `near-implicit` (64 lowercase hex) or `eth-implicit` (`0x` + 40 lowercase hex); includes NEAR's own valid list |
| `accountIds.invalid[]` | `{id, reason}`; includes NEAR's own invalid list; `reason` is `hawkeye-core`'s (informative) |
| `destinations[]` | `{accountId, script}`: the lock destination `OP_RETURN <"NR1" ‖ id>` (§2.1) |
| `destinationsInvalid[]` | `{script, reason}`: scripts the lock policy refuses (wrong prefix, bad id, 65-byte id, a 32-byte Ethereum destination, `OP_PUSHDATA1`, a second push, no `OP_RETURN`) |
| `deployments[]` | `{networkId, contractId, chainId, chainIdLe, bridge}`: `chainId` = `SHA256("near:" ‖ networkId)[0..8]` as u64 LE (`chainIdLe` the 8 bytes), `bridge` = `SHA256(contractId)[0..20]` (§2.2) |
| `memos[]` | `{bridgeKind, kind, chainId, bridge, ref, data, payload, script}`: `HKN1` burn releases (`data` = a `burns[].sha256`) and a roll, and `HKB1` burn release and roll for contrast; `payload` is the 73 bytes, `script` is `6a 49 ‖ payload` |
| `messages[]` | `{domain: {networkId, contractId}, message, tag, borsh, preimage, digest, signatures[]}` for every `BridgeMessage` variant (§2.3); `preimage` = `"HawkeyeNear-v1" ‖ borsh(networkId) ‖ borsh(contractId) ‖ borsh`, `digest` = `SHA256(preimage)`; `signatures[]` = `{key, signature, guardian}`, one per `keys[]` entry: 65 bytes `r ‖ s ‖ v`, RFC 6979, low S, `v ∈ {0, 1}`, and the guardian id it recovers to under `env::ecrecover(digest, r‖s, v, true)` |
| `burns[]` | `{record, borsh, sha256}`: a **BurnRecord v2** (§2.4; `ycashRecipient` the raw main-plan §4.2 revision-2 bytes, 22 — P2PKH, P2SH — or 35 — PQPKH scheme 1, PQPKH scheme 2 —, Borsh-encoded as a `Vec<u8>`: `u32` LE length then the bytes), its Borsh bytes and `SHA256`; the four records cover every shape the contract accepts, the last two at the field extremes |

`message` objects by `type` (field names are the JSON spellings of the contract's):

```json
{"type": "Mint",         "lockId": "…32 bytes", "amount": "250000000", "receiverId": "alice.near"}
{"type": "Challenge",    "lockId": "…32 bytes", "proposalId": "1"}
{"type": "SetGuardians", "guardians": ["…64 bytes", …], "threshold": 2, "adminNonce": "0"}
{"type": "SetPaused",    "paused": true, "adminNonce": "1"}
{"type": "SetMintLimit", "mintCap": "100000000000", "capWindowSec": "86400", "adminNonce": "3"}
```
