# Test fixtures

## `vault_vectors.json`

The vault primitive's golden vector, copied verbatim from the node:

- source: `boyfromcave/ycash-dd` `src/test/data/vault_vectors.json` at commit **`dbc1ab0`**
  (branch `upgrade/vault`; the file last changed in `82d8b47`)
- sha256 `b9681ac0b3b984b10f6cba0d906d4b4d77c19f2420bec22e42a2922e6b336f97`, byte-identical in
  `ycash6` (the vector is the same on both node lines)
- schema and conventions: ycash-dd `qa/rpc-tests/test_framework/VAULT_VECTORS.md`

Do not edit it. To update, copy the node's file again, record the new commit and hash here, and
re-run `cargo test -p hawkeye-core`.

`tests/vault_vectors.rs` replays `vaults`, `vaultsInvalid`, `intents`, `intentsInvalid`, `bonds`,
`selectors`, `selectorsInvalid`, `setSigMsgs`, `signatures`, `signaturesInvalid`, the act
messages and signatures of `acts`, and the set signatures inside `spends`.

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
