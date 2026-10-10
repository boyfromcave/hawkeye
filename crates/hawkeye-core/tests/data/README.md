# Test fixtures

## `vault_vectors.json`

The vault primitive's golden vector, copied verbatim from the node:

- source: `boyfromcave/ycash-dd` `src/test/data/vault_vectors.json` at commit **`a8572900f`**
  (branch `q/tmpl`, the post-quantum line `upgrade/quantum-vaults`; the file last changed in
  `926268c3b`; the same blob `b7d164f` on `q/wallet` `e37a8c3b4`). Every V and I owner is a
  post-quantum key id (quantum spec §1): `pqOwner`, the scheme-2 case, the owner-slot invalid
  cases and the SLH-DSA owner spend `ownerSpends` are new. The `upgrade/vault` copy was ycash-dd
  `dbc1ab0`, sha256 `b9681ac0…6f97`.
- sha256 `29633de74cc8c67dfa0f78327a33fdb03700532297d3d90c95349e674d47b131`; it must be
  byte-identical in `ycash6` once the port lands there (the vector is the same on both node lines)
- schema and conventions: ycash-dd `qa/rpc-tests/test_framework/VAULT_VECTORS.md`

Do not edit it. To update, copy the node's file again, record the new commit and hash here, and
re-run `cargo test -p hawkeye-core`.

`tests/vault_vectors.rs` replays `pqOwner`, `vaults`, `vaultsInvalid`, `intents`,
`intentsInvalid`, `bonds`, `selectors`, `selectorsInvalid`, `setSigMsgs`, `signatures`,
`signaturesInvalid`, the act messages and signatures of `acts`, the set signatures inside
`spends`, and the owner spend's selector, chunks and ZIP-243 sighash in `ownerSpends`.

`tests/attribution.rs` runs every `spends` case through `attribution::attribute_template_input`
(it must name exactly the recorded signers, with the recorded sighash and `setSigMsg`) and the
negative cases built from them.

## `sighash.json`

The node's transparent signature-hash vector, copied verbatim:

- source: `boyfromcave/ycash-dd` `src/test/data/sighash.json` at commit **`dbc1ab0`**
  (branch `upgrade/vault`; unchanged from Ycash v4.5.0's Zcash lineage)
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
