#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo "Run this script on macOS with native Go and a running Docker daemon." >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="sshpiper-macos-$(uuidgen | tr '[:upper:]' '[:lower:]')"
compose=(docker compose --project-name "$project"
    -f "$root/e2e/docker-compose.yml"
    -f "$root/e2e/docker-compose.native.yml")

cleanup() {
    local status=$?
    trap - EXIT
    if ! "${compose[@]}" logs --no-color host-password; then
        echo "Could not collect Compose SSH server logs" >&2
    fi
    if ! "${compose[@]}" down --volumes; then
        echo "Could not remove the native E2E Compose project" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${compose[@]}" up --detach --wait --wait-timeout 120 host-password
upstream="$("${compose[@]}" port host-password 2222)"
if [[ ! "$upstream" =~ ^127\.0\.0\.1:[0-9]+$ ]]; then
    echo "Unexpected Compose SSH endpoint: $upstream" >&2
    exit 1
fi

export SSHPIPERD_E2E_UPSTREAM="$upstream"
export CGO_ENABLED=0 GOWORK=off
go -C "$root" test -v -count=1 -tags e2e -timeout 10m ./e2e/native
