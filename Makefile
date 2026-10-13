# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying file LICENSE or
# https://www.opensource.org/licenses/mit-license.php.
#
# Developer shortcuts. The Ethereum-backed suites (crates/hawkeye/tests/engine.rs,
# crates/hawkeye-eth/tests/anvil.rs) return early and pass when `anvil` is not on PATH (Rust has
# no "skipped"); they print SKIPPED to stderr. `make test` sets HAWKEYE_REQUIRE_ANVIL=1 whenever
# anvil is on PATH, so a broken anvil setup fails instead of passing vacuously (audit 05/T-3).
# CI sets HAWKEYE_REQUIRE_ANVIL=1 unconditionally.

ANVIL := $(shell command -v anvil 2>/dev/null)

.PHONY: test
test:
ifneq ($(ANVIL),)
	HAWKEYE_REQUIRE_ANVIL=1 cargo test --workspace --all-features --locked
else
	@echo "anvil is not on PATH: the Ethereum-backed suites will be SKIPPED (pass vacuously)" >&2
	cargo test --workspace --all-features --locked
endif
