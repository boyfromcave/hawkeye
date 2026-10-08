#!/bin/sh
# Fetch the wYEC contracts at the pinned commit into eth/vendor/wyec (gitignored).
#
# The contracts are never copied into this repository as source (AGENTS.md rule 2): every build
# fetches them at WYEC_COMMIT and checks the commit before using it.
#
#   ./tools/fetch-wyec.sh                 # clone from WYEC_URL (default: GitHub) at the pin
#   WYEC_SRC=/path/to/wyec ./tools/fetch-wyec.sh
#                                         # export the pinned commit from a local clone instead
#                                         # (offline machines, or where GitHub is unreachable)
#
# Re-pinning is deliberate: change WYEC_COMMIT here, regenerate vectors/eip712.json and the ABI
# files under crates/hawkeye-eth/abi/, and say so in the commit message.
set -eu

# wyec main at the merge of PR #1 (CR-W1 optimistic mint + rate limit, CR-W2 Foundry project,
# CR-W3 recipient NatSpec). Was d2e382b (threshold mint only).
WYEC_COMMIT=cad126a415bdb5e0ae9cf7d05f6bd1b512267efb
WYEC_URL=${WYEC_URL:-https://github.com/boyfromcave/wyec.git}

here=$(cd "$(dirname "$0")/.." && pwd)
dest="$here/vendor/wyec"
stamp="$dest/.wyec-commit"
sums="$dest/.wyec-sha256"

# Idempotent: an existing fetch at the pin whose files still match the checksums recorded at
# fetch time is kept; anything else (other commit, edited or missing file) is fetched again.
if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$WYEC_COMMIT" ] && [ -f "$sums" ] &&
    (cd "$dest" && sha256sum --quiet --check .wyec-sha256 >/dev/null 2>&1); then
    echo "wyec @ $WYEC_COMMIT already in $dest (checksums verified)"
    exit 0
fi

rm -rf "$dest"
mkdir -p "$dest"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

src=${WYEC_SRC:-}
if [ -z "$src" ]; then
    if git clone --quiet --no-checkout "$WYEC_URL" "$tmp/wyec" 2>"$tmp/err"; then
        src="$tmp/wyec"
    elif [ -d "$here/../../wyec/.git" ]; then
        # Workspace layout fallback: hawkeye/ and wyec/ side by side.
        echo "clone of $WYEC_URL failed ($(head -1 "$tmp/err")); using sibling ../wyec" >&2
        src=$(cd "$here/../../wyec" && pwd)
    else
        cat "$tmp/err" >&2
        echo "cannot fetch wyec: set WYEC_SRC to a local clone" >&2
        exit 1
    fi
fi

# Verify the commit: it must resolve to exactly the pinned object (git checks the object's own
# hash, so the archived tree is the pinned tree).
got=$(git -C "$src" rev-parse --verify --quiet "$WYEC_COMMIT^{commit}" || true)
if [ "$got" != "$WYEC_COMMIT" ]; then
    echo "commit $WYEC_COMMIT not found in $src" >&2
    exit 1
fi
git -C "$src" cat-file -e "$WYEC_COMMIT:contracts/WyecBridge.sol" &&
    git -C "$src" cat-file -e "$WYEC_COMMIT:contracts/WrappedYcash.sol" || {
    echo "commit $WYEC_COMMIT lacks the contracts" >&2
    exit 1
}

git -C "$src" archive --format=tar "$WYEC_COMMIT" contracts docs | tar -x -C "$dest"
(cd "$dest" && find contracts docs -type f | LC_ALL=C sort | xargs sha256sum >.wyec-sha256)
echo "$WYEC_COMMIT" >"$stamp"
echo "wyec @ $WYEC_COMMIT -> $dest"
