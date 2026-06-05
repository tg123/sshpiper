#!/usr/bin/env bash
#
# build-snap.sh
#
# Replaces the legacy goreleaser `snapcrafts:` block with a plain snapcraft
# invocation. For each requested arch:
#
#   1. Stage the daemon + plugins (from `make docker-bins`) plus the snap
#      `launcher` binary (cross-compiled here, with the same
#      `go generate ./cmd/sshpiperd/snap/launcher` step goreleaser used to
#      run as a `pre` hook) and the `configure` hook script into a
#      per-arch prime dir under `snap/prime-<arch>/`.
#   2. Render `snap/snapcraft.yaml.in` for that arch into `snap/snapcraft.yaml`.
#   3. Run `snapcraft pack --destructive-mode --output <dist>/<name>.snap`.
#
# Optional second step:
#
#   scripts/build-snap.sh push <snap-file> <channel-list>
#
# Uses `snapcraft upload --release=<channels>` so it can be driven from CI.

set -euo pipefail

VERSION="${VERSION:-devel}"
DIST_DIR="${DIST_DIR:-dist}"
DOCKER_BINS_DIR="${DOCKER_BINS_DIR:-.docker-bins}"
SNAP_DIR="${SNAP_DIR:-snap}"
TEMPLATE="${SNAP_DIR}/snapcraft.yaml.in"
SNAPCRAFT_YAML="${SNAP_DIR}/snapcraft.yaml"

# Architectures we publish to the snap store. The legacy goreleaser config
# emitted one .snap per (amd64, arm64).
SNAP_ARCHS_DEFAULT="amd64 arm64"
SNAP_ARCHS="${SNAP_ARCHS:-$SNAP_ARCHS_DEFAULT}"

# Plugins that the launcher exposes through `snapctl` (matches the legacy
# `snapcrafts.ids` list — `workingdir`, `yaml`, `fixed`, `failtoban`,
# `username-router`, `lua`). `docker` / `kubernetes` were intentionally
# excluded from the snap because they cannot run under strict confinement.
SNAP_PLUGINS=(workingdir yaml fixed failtoban username-router lua)

# Render the snapcraft.yaml template for a given arch.
render_yaml() {
  local arch="$1"
  sed \
    -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@BUILD_ON@|${arch}|g" \
    -e "s|@BUILD_FOR@|${arch}|g" \
    "$TEMPLATE" > "$SNAPCRAFT_YAML"
}

# Build the snap `launcher` binary (lives at `cmd/sshpiperd/snap/launcher`
# and is wired up via `//go:generate sh -c "go run ../configgen/main.go > configentry.txt"`).
build_launcher() {
  local arch="$1" dst="$2"
  echo ">> generating snap launcher config entries"
  ( cd cmd/sshpiperd/snap/launcher && go generate ./... )

  echo ">> building snap launcher (GOARCH=$arch)"
  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" \
      -o "$dst/launcher" \
      ./cmd/sshpiperd/snap/launcher
}

prime_for_arch() {
  local arch="$1"
  local prime="$SNAP_DIR/prime-${arch}"
  local src="$DOCKER_BINS_DIR/linux_${arch}"

  if [ ! -d "$src" ]; then
    echo "ERROR: $src missing — run 'make docker-bins' first" >&2
    exit 1
  fi

  rm -rf "$prime"
  mkdir -p "$prime/plugins"

  # 1. sshpiperd + plugins exposed through the launcher.
  cp -f "$src/sshpiperd" "$prime/sshpiperd"
  local p
  for p in "${SNAP_PLUGINS[@]}"; do
    if [ ! -f "$src/plugins/$p" ]; then
      echo "ERROR: missing $src/plugins/$p" >&2
      exit 1
    fi
    cp -f "$src/plugins/$p" "$prime/plugins/$p"
  done

  # 2. The snap launcher (entry point declared in snapcraft.yaml as
  # `apps.sshpiperd.command: launcher`).
  build_launcher "$arch" "$prime"

  # The configure hook lives at `snap/hooks/configure` and is declared by
  # the top-level `hooks:` block in snap/snapcraft.yaml.in. snapcraft picks
  # it up automatically from that conventional location at `pack` time
  # (no extra copying into `meta/hooks/configure` is needed here).
}

cmd_pack() {
  command -v snapcraft >/dev/null || {
    echo "ERROR: snapcraft not installed" >&2
    exit 1
  }
  mkdir -p "$DIST_DIR"

  local arch
  for arch in $SNAP_ARCHS; do
    prime_for_arch "$arch"
    render_yaml "$arch"

    local out="$DIST_DIR/sshpiperd_${VERSION}_${arch}.snap"
    echo ">> packing $out"
    rm -f "$out"
    # `--destructive-mode` keeps everything on the host runner (no LXD /
    # multipass VM) — we have already produced the binaries.
    snapcraft pack --destructive-mode --output "$out"

    # Clean intermediate state so the next arch starts fresh.
    rm -f "$SNAPCRAFT_YAML"
    rm -rf "$SNAP_DIR/prime-${arch}"
  done
}

cmd_push() {
  local snap="${2:-}" channels="${3:-beta,stable}"
  if [ -z "$snap" ]; then
    echo "usage: $0 push <snap-file> [channels]" >&2
    exit 2
  fi
  if [ -z "${SNAPCRAFT_STORE_CREDENTIALS:-}" ]; then
    echo "ERROR: SNAPCRAFT_STORE_CREDENTIALS is not set" >&2
    exit 1
  fi
  echo ">> uploading $snap to channels: $channels"
  snapcraft upload --release="$channels" "$snap"
}

case "${1:-}" in
  pack) cmd_pack ;;
  push) cmd_push "$@" ;;
  *) echo "usage: $0 {pack|push <snap-file> [channels]}" >&2; exit 2 ;;
esac
