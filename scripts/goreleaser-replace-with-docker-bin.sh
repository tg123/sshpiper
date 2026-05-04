#!/usr/bin/env bash
#
# goreleaser-replace-with-docker-bin.sh
#
# Replaces a goreleaser-just-built linux binary with the matching binary
# extracted by `make docker-bins` from the Dockerfile's `bin-export` stage.
# Wired into `.goreleaser.yaml` as a per-build `hooks.post` so the bytes
# packaged into the GH release archives are byte-identical to the bytes that
# ship inside the published Docker images. No-op for non-linux builds.
#
# Usage:
#   goreleaser-replace-with-docker-bin.sh <dest> <os> <arch> <bin_relative>
#
# Where:
#   <dest>          - the goreleaser binary path ({{ .Path }} from a build)
#   <os>            - GOOS for the build ({{ .Os }})
#   <arch>          - GOARCH for the build ({{ .Arch }})
#   <bin_relative>  - path inside the docker bin-export layout, e.g.
#                     "sshpiperd", "plugins/fixed", "sshpiperd-webadmin"

set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <dest> <os> <arch> <bin_relative>" >&2
    exit 2
fi

dest="$1"
os="$2"
arch="$3"
bin_relative="$4"

if [ "$os" != "linux" ]; then
    exit 0
fi

bins_dir="${DOCKER_BINS_DIR:-.docker-bins}"
src="${bins_dir}/linux_${arch}/${bin_relative}"

if [ ! -f "$src" ]; then
    echo "ERROR: docker-bins binary missing: $src" >&2
    echo "Did 'make docker-bins' run before goreleaser?" >&2
    exit 1
fi

cp -f "$src" "$dest"
echo "replaced $dest with $src (bytes from Dockerfile bin-export)"
