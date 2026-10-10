#!/bin/sh
# Fetch the NEAR sandbox node (nearcore's `neard` built with the `sandbox` feature) at the pinned
# version into near/vendor/sandbox (gitignored) and print the binary's path on stdout.
#
# The version is near-sandbox-utils' DEFAULT_NEAR_SANDBOX_VERSION for the near-workspaces in
# near/Cargo.lock (near-sandbox 0.3.16 -> 2.13.4), so the devnet, the adapter's sandbox test and
# the contract's near-workspaces tests all run the same node; the archive's SHA-256 is checked.
#
#   ./tools/fetch-sandbox.sh                       # download from nearcore's build bucket
#   SANDBOX_TARBALL=/path/near-sandbox.tar.gz ./tools/fetch-sandbox.sh
#                                                  # use an archive fetched elsewhere (offline)
#
# Re-pinning is deliberate: change SANDBOX_VERSION and SANDBOX_SHA256 together.
set -eu

SANDBOX_VERSION=2.13.4
SANDBOX_SHA256=5690a4635172263cf026683f75965cac09dd916912584f12709974fed620163f
SANDBOX_URL=${SANDBOX_URL:-https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Linux-x86_64/$SANDBOX_VERSION/near-sandbox.tar.gz}

here=$(cd "$(dirname "$0")/.." && pwd)
dest="$here/vendor/sandbox/$SANDBOX_VERSION"
bin="$dest/near-sandbox"
if [ -x "$bin" ] && [ -f "$dest/.sha256" ] && [ "$(cat "$dest/.sha256")" = "$SANDBOX_SHA256" ]; then
    echo "$bin"
    exit 0
fi

[ "$(uname -sm)" = "Linux x86_64" ] || { echo "the pinned sandbox is Linux-x86_64 only" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "${SANDBOX_TARBALL:-}" ]; then
    cp "$SANDBOX_TARBALL" "$tmp/s.tar.gz"
else
    curl --fail --silent --show-error --location --retry 4 --retry-delay 2 -o "$tmp/s.tar.gz" "$SANDBOX_URL"
fi
got=$(sha256sum "$tmp/s.tar.gz" | cut -d' ' -f1)
if [ "$got" != "$SANDBOX_SHA256" ]; then
    echo "near-sandbox $SANDBOX_VERSION: SHA-256 $got, expected $SANDBOX_SHA256" >&2
    exit 1
fi
mkdir -p "$tmp/x"
tar -xzf "$tmp/s.tar.gz" -C "$tmp/x"
found=$(find "$tmp/x" -type f -name near-sandbox | head -1)
[ -n "$found" ] || { echo "no near-sandbox in the archive" >&2; exit 1; }
rm -rf "$dest"
mkdir -p "$dest"
mv "$found" "$bin"
chmod 0755 "$bin"
echo "$SANDBOX_SHA256" >"$dest/.sha256"
echo "near-sandbox $SANDBOX_VERSION -> $bin" >&2
echo "$bin"
