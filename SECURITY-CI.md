# Security CI

Hawkeye holds attestor keys and signs set signatures, EIP-712 and NEAR attestations and acts, so every
push and pull request runs these security checks besides the build and test CI (`ci.yml`, `devnet-e2e.yml`).
They scan Hawkeye's own code only: the wyec contracts fetched at the pin (`eth/tools/fetch-wyec.sh`,
`eth/vendor/`, gitignored) are wyec's, and are analysed in the wyec repository.

| Leg | Workflow / job | Gate | Results |
|---|---|---|---|
| Semgrep: rule packs at pinned commits + Hawkeye's rules | `semgrep.yml` | PR fails on a new **critical** finding (diff-aware) | step summary, code scanning (`semgrep`), at most four rolling PRs `semgrep/<bucket>` |
| Semgrep rule tests | `secops.yml` / semgrep rule tests | fails when a Hawkeye rule stops matching its test cases | job log |
| CodeQL `security-extended` (rust, actions, python, javascript) | `codeql.yml` | report only | code scanning (`codeql-<language>`) |
| Workflow security: zizmor + actionlint | `ci.yml` / lint workflows | fails on any finding | job log |
| Rust dependencies: cargo-deny (advisories, bans, licences, sources) | `ci.yml` / cargo-deny | fails on any finding (`deny.toml`) | job log |
| Secrets: gitleaks | `secops.yml` / gitleaks | PR: fails on a leak in the PR's commits; nightly: full history | step summary, code scanning (`gitleaks`) |
| Known vulnerabilities in every lockfile: OSV-Scanner | `secops.yml` / osv-scanner | fails on any vulnerability not accepted in `osv-scanner.toml` | step summary, code scanning (`osv-scanner`) |
| npm production dependencies (`eth/`) | `secops.yml` / npm audit | fails on high or critical | job log |
| Dependabot | `.github/dependabot.yml` | security updates only, one grouped PR per ecosystem | PRs |
| Code-scanning triage | `code-scanning.yml` / triage | none: applies `contrib/secops/code-scanning-dismissals.json` (on a change to it on `upgrade/vault`, nightly, by hand) | job log, dismissed alerts |

Not run, and why: Slither (Hawkeye owns no deployed Solidity; `eth/` is forge tests and a deploy script),
pip-audit (no Python dependencies; the devnet script is standard library only), Checkov (no Docker,
Kubernetes or Terraform).

## Hawkeye's Semgrep rules

`contrib/semgrep/rules/hawkeye.yaml` (tests: `hawkeye.rs` beside it) encodes the repository's invariants:

- `hawkeye.interface.yed-rpc` (critical): no `yed_*` RPC method name anywhere (AGENTS.md rule 1).
- `hawkeye.signing.primitive-outside-signing-modules` (high): raw k256 / alloy / ed25519 signing calls only in
  the per-scheme wrapper modules (hawkeye-core `setsig`/`eth`/`near`/`peerauth`, hawkeye-eth `eip712`,
  hawkeye-near `tx`).
- `hawkeye.signing.outside-sign-once` (high): in the daemon, set signatures, attestations and acts are made
  only inside a `sign_once_*` closure of the ledger (AGENTS.md rule 7).
- `hawkeye.crypto.non-crypto-rng` (high): no non-cryptographic or fixed-seed RNG outside tests.
- `hawkeye.secrets.logged-key-material` (high): no secret key, seed or key bytes passed to a log, format or
  panic macro.

## Accepting a finding

Fix it if you can. Otherwise accept it with a reason a reviewer can check:

- Semgrep: `contrib/semgrep/accepted.json`, by fingerprint or by rule over paths (`contrib/semgrep/README.md`).
- gitleaks: `.gitleaks.toml` allowlists, only for public values (test vectors, public keys, well-known dev
  keys). A real secret is rotated first, never allowlisted.
- OSV-Scanner: an `[[IgnoredVulns]]` entry in `osv-scanner.toml` with `reason` and an `ignoreUntil` at most
  90 days out.
- cargo-deny: `deny.toml` `[advisories] ignore`, with a reason and a revisit date. An advisory on `Cargo.lock`
  is reported by both cargo-deny and OSV-Scanner, so it is accepted in both files with the same reason.
- Any code-scanning alert (CodeQL, Semgrep, zizmor, gitleaks, OSV-Scanner, ...): an entry in
  `contrib/secops/code-scanning-dismissals.json` (tool, rule, path glob, reason, comment);
  `code-scanning.yml` dismisses the matching open alerts. A real finding is fixed, never listed.

## Repository settings

- Code scanning results need GitHub code scanning (free for public repositories).
- The Semgrep bucket PRs need *Settings → Actions → General → Allow GitHub Actions to create and approve
  pull requests*; to have CI run on them, add the secret `SEMGREP_PR_TOKEN` (fine-grained; this repository;
  contents and pull requests: write).
- Dependabot security updates: *Settings → Code security → Dependabot security updates* on.
