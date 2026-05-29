#!/usr/bin/env bash
#
# verify-plugin-upstream-crypto.sh
#
# Guarantees that ./libplugin/... and ./plugin/... build and test cleanly
# against the unpatched upstream golang.org/x/crypto module (no fork,
# no `replace` directive). This codifies the rule that plugin authors
# should never need the sshpiper crypto fork to write or build plugins.
#
# The forked daemon code under cmd/sshpiperd/ and the crypto fork itself
# are NOT covered by this check; they continue to rely on the fork.
#
# How it works:
#   1. Copy go.mod / go.sum to a scratch dir.
#   2. Strip the `replace golang.org/x/crypto => ./crypto` directive.
#   3. Use `go build -modfile=...` to compile plugin code against the
#      vanilla golang.org/x/crypto version pinned by go.mod.
#
# If anything under libplugin/ or plugin/ starts using a symbol that
# exists only in the fork, the build will fail here.

set -euo pipefail

cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp go.mod "$WORK/go.mod"
cp go.sum "$WORK/go.sum"

# Drop the crypto-fork replace directive. Everything else (versions,
# other replaces, requires) is left intact so the rest of the dependency
# graph still resolves identically.
sed -i.bak '/^replace[[:space:]]\+golang\.org\/x\/crypto[[:space:]]\+=>[[:space:]]\+\.\/crypto$/d' "$WORK/go.mod"
rm -f "$WORK/go.mod.bak"

if grep -q 'golang.org/x/crypto.*=>.*\./crypto' "$WORK/go.mod"; then
  echo "ERROR: failed to strip crypto replace directive from temp go.mod" >&2
  exit 1
fi

export GOFLAGS="-mod=mod -modfile=$WORK/go.mod"

TARGETS=(./libplugin/... ./plugin/...)
TAGS=(""  "full")

for tag in "${TAGS[@]}"; do
  if [ -n "$tag" ]; then
    echo "==> go build -tags $tag (against upstream golang.org/x/crypto)"
    go build -tags "$tag" "${TARGETS[@]}"
    echo "==> go test  -tags $tag (against upstream golang.org/x/crypto)"
    go test  -tags "$tag" -count=1 "${TARGETS[@]}"
  else
    echo "==> go build (against upstream golang.org/x/crypto)"
    go build "${TARGETS[@]}"
    echo "==> go test (against upstream golang.org/x/crypto)"
    go test -count=1 "${TARGETS[@]}"
  fi
done

echo
echo "OK: libplugin/ and plugin/ build and test against upstream golang.org/x/crypto"
