#!/usr/bin/env bash
#
# build-release.sh
#
# Replaces the old `goreleaser release` flow with a plain Make + Bash
# pipeline:
#
#   * linux binaries are extracted from the `bin-export` stage in the
#     repo Dockerfile via `make docker-bins`. They are byte-identical
#     to the binaries that ship in the published runtime image.
#   * windows / darwin binaries are cross-compiled here with the same
#     `-trimpath -ldflags "-s -w"` flags goreleaser used.
#   * everything is staged into per-platform directories under
#     `dist/staging/<os>_<arch>/` and packaged into archives whose names
#     match the legacy goreleaser layout
#     (`sshpiperd_with_plugins_<os>_<archive_arch>.{tar.gz,zip}`) so
#     existing download URLs keep working.
#
# Usage:
#   scripts/build-release.sh <step>
#
# Steps:
#   bins        cross-compile windows/darwin + ingest docker-bins into staging
#   archives    pack each staging dir into tar.gz / zip
#   checksums   write dist/checksums.txt (sha256, one line per archive)

set -euo pipefail

VERSION="${VERSION:-devel}"
DIST_DIR="${DIST_DIR:-dist}"
STAGING_DIR="${STAGING_DIR:-${DIST_DIR}/staging}"
DOCKER_BINS_DIR="${DOCKER_BINS_DIR:-.docker-bins}"
BUILDTAGS="${BUILDTAGS:-full}"

# Platforms we package release archives for. Match the legacy
# `.goreleaser.yaml` matrix (windows/darwin amd64/arm64 + linux amd64/arm64).
RELEASE_PLATFORMS_DEFAULT="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
RELEASE_PLATFORMS="${RELEASE_PLATFORMS:-$RELEASE_PLATFORMS_DEFAULT}"

# Targets cross-compiled into each cross (non-linux) staging dir. Linux
# staging is populated from $DOCKER_BINS_DIR. The matrix matches the
# `goos: [linux, windows, darwin]` builds from the legacy `.goreleaser.yaml`
# (i.e. excludes plugin_docker and plugin_kubernetes which were linux-only).
CROSS_BINS=(
  "sshpiperd:./cmd/sshpiperd:sshpiperd"
  "sshpiperd-webadmin:./cmd/sshpiperd-webadmin:sshpiperd-webadmin"
  "sshpiperd-admin:./cmd/sshpiperd-admin:sshpiperd-admin"
  "plugins/workingdir:./plugin/workingdir:plugins/workingdir"
  "plugins/yaml:./plugin/yaml:plugins/yaml"
  "plugins/fixed:./plugin/fixed:plugins/fixed"
  "plugins/failtoban:./plugin/failtoban:plugins/failtoban"
  "plugins/username-router:./plugin/username-router:plugins/username-router"
  "plugins/lua:./plugin/lua:plugins/lua"
  "plugins/metrics:./plugin/metrics:plugins/metrics"
)

# Mirror goreleaser's `uname`-compatible arch token used in archive names:
#   amd64 -> x86_64, 386 -> i386, everything else passes through.
archive_arch() {
  case "$1" in
    amd64) echo "x86_64" ;;
    386)   echo "i386" ;;
    *)     echo "$1" ;;
  esac
}

bin_ext() { [ "$1" = "windows" ] && echo ".exe" || echo ""; }

ensure_web_dist() {
  # The sshpiperd-webadmin Go package uses //go:embed all:web/dist, so the
  # frontend must exist before any `go build` of that command.
  local web_dir="cmd/sshpiperd-webadmin/internal/httpapi/web"
  if [ ! -d "$web_dir/dist" ]; then
    echo ">> building webadmin frontend ($web_dir)"
    npm --prefix "$web_dir" ci
    npm --prefix "$web_dir" run build
  fi
}

stage_linux() {
  local os="$1" arch="$2"
  local src="$DOCKER_BINS_DIR/${os}_${arch}"
  local dst="$STAGING_DIR/${os}_${arch}"

  if [ ! -d "$src" ]; then
    echo "ERROR: $src missing — run 'make docker-bins' first" >&2
    exit 1
  fi

  rm -rf "$dst"
  mkdir -p "$dst"
  # `cp -a` preserves the plugins/ subdir layout produced by bin-export.
  cp -a "$src"/. "$dst"/
}

stage_cross() {
  local os="$1" arch="$2"
  local dst="$STAGING_DIR/${os}_${arch}"
  local ext
  ext="$(bin_ext "$os")"

  rm -rf "$dst"
  mkdir -p "$dst/plugins"

  local entry
  for entry in "${CROSS_BINS[@]}"; do
    local out_rel="${entry%%:*}"
    local rest="${entry#*:}"
    local main_path="${rest%%:*}"
    local out_path="$dst/${out_rel}${ext}"

    mkdir -p "$(dirname "$out_path")"
    echo ">> building $out_path  (GOOS=$os GOARCH=$arch)"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
      go build -trimpath -tags "$BUILDTAGS" \
        -ldflags "-s -w -X main.mainver=${VERSION}" \
        -o "$out_path" \
        "$main_path"
  done
}

add_extras() {
  # Goreleaser's archive default bundles README/LICENSE alongside the
  # binaries. Keep that for parity with the historical archive contents.
  local dst="$1"
  [ -f README.md ]  && cp README.md  "$dst/"
  [ -f LICENSE ]    && cp LICENSE    "$dst/"
}

cmd_bins() {
  ensure_web_dist
  mkdir -p "$STAGING_DIR"

  local plat os arch
  for plat in $RELEASE_PLATFORMS; do
    os="${plat%%/*}"
    arch="${plat##*/}"
    if [ "$os" = "linux" ]; then
      stage_linux "$os" "$arch"
    else
      stage_cross "$os" "$arch"
    fi
    add_extras "$STAGING_DIR/${os}_${arch}"
  done
}

cmd_archives() {
  mkdir -p "$DIST_DIR"
  local plat os arch aarch name
  for plat in $RELEASE_PLATFORMS; do
    os="${plat%%/*}"
    arch="${plat##*/}"
    aarch="$(archive_arch "$arch")"
    name="sshpiperd_with_plugins_${os}_${aarch}"

    local stage="$STAGING_DIR/${os}_${arch}"
    if [ ! -d "$stage" ]; then
      echo "ERROR: staging dir $stage missing — run 'release-bins' first" >&2
      exit 1
    fi

    if [ "$os" = "windows" ]; then
      local archive="$DIST_DIR/${name}.zip"
      rm -f "$archive"
      echo ">> packing $archive"
      local abs_archive
      abs_archive="$(cd "$DIST_DIR" && pwd)/${name}.zip"
      ( cd "$stage" && zip -qr "$abs_archive" . )
    else
      local archive="$DIST_DIR/${name}.tar.gz"
      rm -f "$archive"
      echo ">> packing $archive"
      tar -C "$stage" -czf "$archive" .
    fi
  done
}

cmd_checksums() {
  local out="$DIST_DIR/checksums.txt"
  rm -f "$out"
  ( cd "$DIST_DIR" \
      && find . -maxdepth 1 -type f \
          \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.snap' \) \
          -printf '%f\n' \
        | sort \
        | xargs -r sha256sum \
        > "$(basename "$out")"
  )
  echo ">> wrote $out"
}

case "${1:-}" in
  bins)       cmd_bins ;;
  archives)   cmd_archives ;;
  checksums)  cmd_checksums ;;
  *) echo "usage: $0 {bins|archives|checksums}" >&2; exit 2 ;;
esac
