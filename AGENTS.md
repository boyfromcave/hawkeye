# hawkeye — agent instructions

Read `docs/hawkeye-bridge-plan.md` first; it is normative (encodings in §4, engine in §5, layout in
§6, phases in §9). This repository is a component of the yellowback workspace
(`boyfromcave/yellowback`, `CLAUDE.md` there); the workspace rules that apply here:

1. **Interfaces only.** Hawkeye reaches `ycashd` only through stock RPCs and the vault primitive's
   `set_*` / `vault_*` RPCs (`ycash-dd/doc/vault-rpc.md`, `doc/vault-rpc-contract.json`), never a
   `yed_*` call, and Ethereum only through standard JSON-RPC. It never needs a node change; a
   needed one is a change request in plan §10, not a patch.
2. **Commit only here.** `ycash-dd`, `ycash6`, `wyec` and the workspace are read, never written,
   from this repository's work. The wyec contracts are fetched at a pinned commit
   (`eth/tools/fetch-wyec.sh`), never copied in as source.
3. **Byte-exactness.** Every encoding has golden vectors: the node's
   `src/test/data/vault_vectors.json` (identical on both node lines), Foundry-generated EIP-712
   vectors, and Hawkeye's own. A change to an encoding changes the plan first.
4. **Naming.** Yellowback is the system, YED the unit, YEC the coin, wYEC the ERC-20; Hawkeye is
   this software; an attestor is a member of the bridge signer set. No DigiDollar naming.
5. **Both node lines.** Anything tested against `ycash-dd` is tested against `ycash6` too before a
   phase closes (same branch ID, same RPCs, same vectors).
6. **Dependencies** are exact-pinned, `Cargo.lock` is committed, builds are `--locked`.
7. **Sign once.** Code that signs (set signatures, EIP-712, acts) must go through the sign-once
   records; a retry reuses the bytes it signed, never re-builds and re-signs.
