# sshpiper Makefile
#
# Single source of truth for build, test, lint, and Docker image release.
# The Dockerfile is the canonical builder for the published images, and is
# driven from the `docker*` targets below.

SHELL := /bin/bash

VERSION       ?= devel
# Strip a leading "v" so VERSION always holds the bare semver and the docker
# tag templates below can prepend "v" / "full-v" without producing "vv1.2.3".
# `override` is required so the substitution applies even when VERSION is set
# on the command line (e.g. `make docker-push VERSION=v1.2.3`).
override VERSION := $(patsubst v%,%,$(VERSION))
BUILDTAGS     ?= full

WEB_DIR       := cmd/sshpiperd-webadmin/internal/httpapi/web
WEB_DIST      := $(WEB_DIR)/dist

OUT_DIR       ?= out

DOCKER        ?= docker
DOCKER_BUILDX ?= $(DOCKER) buildx

# Multi-arch platforms used by `docker-bins` and `docker-push*`. The push
# targets and the bin extraction must use the same platform list so the
# binaries embedded in the image and the binaries packaged into the GH
# release archives are identical.
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64

# Image repositories the release targets publish to. Override on the command
# line, e.g. `make docker-push IMAGE_REPOS="myrepo/sshpiperd"`.
IMAGE_REPOS   ?= farmer1992/sshpiperd ghcr.io/tg123/sshpiperd

# Set PUSH=1 to actually push the image. Without PUSH=1 the multi-arch build
# is exercised but the resulting manifest is discarded (buildx cannot --load
# a multi-arch image into the local docker daemon). Use the `docker` /
# `docker-full` targets for a loadable single-platform local build.
PUSH          ?= 0
DOCKER_OUTPUT := $(if $(filter 1,$(PUSH)),--push,)

# Where `docker-bins` deposits the per-arch linux binaries extracted from the
# `bin-export` stage in the Dockerfile. `scripts/build-release.sh` ingests
# this layout when staging the linux release archives, and
# `scripts/build-snap.sh` reuses it when building the per-arch .snap files,
# so the linux binaries shipped in archives, snaps, and runtime images are
# all the same bytes.
DOCKER_BINS_DIR ?= .docker-bins

# Output directory for release artifacts (archives, checksums, snaps).
DIST_DIR      ?= dist

GOFUMPT       ?= gofumpt
GOLANGCI_LINT ?= golangci-lint

.PHONY: all build web test test-crypto lint fmt fmt-check clean \
        docker docker-slim docker-full \
        docker-bins docker-push docker-push-slim docker-push-full \
        release release-bins release-archives release-checksums \
        snap snap-push e2e \
        demo demo-down

all: build

## --- Web frontend (sshpiperd-webadmin) ---------------------------------------

$(WEB_DIST): $(WEB_DIR)/package.json $(WEB_DIR)/package-lock.json
	npm --prefix $(WEB_DIR) ci
	npm --prefix $(WEB_DIR) run build

web: $(WEB_DIST)

## --- Go build / test / lint --------------------------------------------------

build: web
	mkdir -p $(OUT_DIR)
	go build -tags $(BUILDTAGS) -o $(OUT_DIR) -ldflags "-X main.mainver=$(VERSION)" ./...

test:
	go test -v -race -cover -tags $(BUILDTAGS) ./...

test-crypto:
	cd crypto/ssh && go test ./...

lint:
	$(GOLANGCI_LINT) run --build-tags $(BUILDTAGS) -D errcheck

fmt:
	$(GOFUMPT) -w .

fmt-check:
	@out="$$($(GOFUMPT) -l .)"; \
	if [ -n "$$out" ]; then \
	  echo "gofumpt: the following files are not formatted:"; \
	  echo "$$out"; \
	  exit 1; \
	fi

clean:
	rm -rf $(OUT_DIR) $(DIST_DIR) $(DOCKER_BINS_DIR) $(WEB_DIST) \
	  snap/prime-* snap/snapcraft.yaml snap/parts snap/stage \
	  cmd/sshpiperd/snap/launcher/configentry.txt

## --- Docker images -----------------------------------------------------------
##
## The `Dockerfile` is the single source of truth for the Linux binaries that
## ship in the published images and in the GH release tarballs:
##
##   * `docker-bins` extracts the binaries from the `bin-export` stage via
##     `docker buildx build --output type=local`. The release pipeline
##     (see `release-bins` below) packages those exact bytes into the GH
##     release tarballs, and `snap` packs them into the published .snap
##     files.
##   * `docker-push*` builds + pushes the multi-arch runtime images from the
##     same Dockerfile. Buildx caches the `builder` stage between the two
##     invocations, so the binaries copied into the runtime image are the
##     same ones extracted by `docker-bins` (and `-trimpath` makes the Go
##     compile reproducible even if the cache is cold).

# Local single-platform builds (loaded into the host docker daemon).
docker: docker-slim

docker-slim:
	$(DOCKER_BUILDX) build \
	  --build-arg VER=$(VERSION) \
	  --target sshpiperd \
	  -t sshpiperd:$(VERSION) \
	  --load .

docker-full:
	$(DOCKER_BUILDX) build \
	  --build-arg VER=$(VERSION) \
	  --build-arg BUILDTAGS=full \
	  --target sshpiperd \
	  -t sshpiperd:full-$(VERSION) \
	  --load .

# Extract the per-arch linux binaries from the Dockerfile's `bin-export`
# stage. Output layout (mirrors goreleaser's `linux_<arch>` convention so
# the release / snap scripts can address the binaries with a predictable
# path):
#
#   $(DOCKER_BINS_DIR)/linux_amd64/sshpiperd
#   $(DOCKER_BINS_DIR)/linux_amd64/sshpiperd-webadmin
#   $(DOCKER_BINS_DIR)/linux_amd64/plugins/<name>
#   $(DOCKER_BINS_DIR)/linux_arm64/...
#
# Build with BUILDTAGS=full so all plugins (the superset shipped in the
# `:full` image) are present; this is what the release archives package.
# Loop per-platform — buildx local output is flat for single-platform builds,
# so doing them one at a time gives a consistent `linux_<arch>/` layout
# regardless of whether buildx is on the docker driver or a multi-arch one.
docker-bins:
	rm -rf $(DOCKER_BINS_DIR)
	@set -e; \
	for plat in $$(echo $(DOCKER_PLATFORMS) | tr ',' ' '); do \
	  arch=$${plat##*/}; \
	  echo ">> extracting binaries for $$plat -> $(DOCKER_BINS_DIR)/linux_$$arch"; \
	  mkdir -p $(DOCKER_BINS_DIR)/linux_$$arch; \
	  $(DOCKER_BUILDX) build \
	    --platform $$plat \
	    --build-arg VER=$(VERSION) \
	    --build-arg BUILDTAGS=full \
	    --target bin-export \
	    --output type=local,dest=$(DOCKER_BINS_DIR)/linux_$$arch \
	    . ; \
	done

# Multi-arch image build / publish. Tags mirror what the previous release
# pipeline produced:
#
#   slim: <repo>:v<VERSION>, <repo>:latest
#   full: <repo>:full-v<VERSION>, <repo>:full
#
# Use `make docker-push PUSH=1 VERSION=1.2.3` from CI to publish; without
# `PUSH=1` the build is exercised but not pushed.

# Per-image tag flags for every repo in IMAGE_REPOS.
_slim_tags := $(foreach r,$(IMAGE_REPOS),-t $(r):v$(VERSION) -t $(r):latest)
_full_tags := $(foreach r,$(IMAGE_REPOS),-t $(r):full-v$(VERSION) -t $(r):full)

docker-push: docker-push-slim docker-push-full

docker-push-slim:
	$(DOCKER_BUILDX) build \
	  --platform $(DOCKER_PLATFORMS) \
	  --build-arg VER=$(VERSION) \
	  --target sshpiperd \
	  $(_slim_tags) \
	  $(DOCKER_OUTPUT) .

docker-push-full:
	$(DOCKER_BUILDX) build \
	  --platform $(DOCKER_PLATFORMS) \
	  --build-arg VER=$(VERSION) \
	  --build-arg BUILDTAGS=full \
	  --target sshpiperd \
	  $(_full_tags) \
	  $(DOCKER_OUTPUT) .

## --- Release pipeline (replaces goreleaser) ----------------------------------
##
## End-to-end release flow used by `.github/workflows/release.yaml`:
##
##   make docker-bins                  # extract linux binaries from Dockerfile
##   make release VERSION=1.2.3        # bins + archives + checksums (+ snap)
##   make docker-push PUSH=1 VERSION=1.2.3
##
## `release` orchestrates `release-bins`, `release-archives`, and
## `release-checksums`. Snap packaging is split off into its own target
## because it requires `snapcraft` on the host.

release: release-bins release-archives release-checksums

release-bins: docker-bins
	VERSION=$(VERSION) DIST_DIR=$(DIST_DIR) DOCKER_BINS_DIR=$(DOCKER_BINS_DIR) \
	  BUILDTAGS=$(BUILDTAGS) \
	  bash scripts/build-release.sh bins

release-archives:
	VERSION=$(VERSION) DIST_DIR=$(DIST_DIR) \
	  bash scripts/build-release.sh archives

release-checksums:
	VERSION=$(VERSION) DIST_DIR=$(DIST_DIR) \
	  bash scripts/build-release.sh checksums

## --- Snap --------------------------------------------------------------------
##
## Pack per-arch .snap files from the binaries extracted by `docker-bins`.
## Requires `snapcraft` to be installed and on PATH. Override SNAP_ARCHS
## (default: `amd64 arm64`) to build for a different set of architectures.

SNAP_ARCHS ?= amd64 arm64

snap: docker-bins
	VERSION=$(VERSION) DIST_DIR=$(DIST_DIR) DOCKER_BINS_DIR=$(DOCKER_BINS_DIR) \
	  SNAP_ARCHS="$(SNAP_ARCHS)" \
	  bash scripts/build-snap.sh pack

# Upload + release every .snap in $(DIST_DIR) to the snap store. CI uses
# `SNAPCRAFT_STORE_CREDENTIALS` (exported macaroon) for non-interactive auth.
SNAP_CHANNELS ?= beta,stable
snap-push:
	@set -e; \
	for s in $(DIST_DIR)/sshpiperd_*.snap; do \
	  bash scripts/build-snap.sh push "$$s" "$(SNAP_CHANNELS)"; \
	done

## --- E2E ---------------------------------------------------------------------

e2e:
	cd e2e && $(DOCKER) compose up --build --force-recreate --exit-code-from testrunner

## --- Demo --------------------------------------------------------------------
##
## One-shot quickstart demo: builds the sshpiperd image from the local
## Dockerfile and stands up sshpiperd in front of a dummy upstream sshd.
## Connect with:  ssh -p 2222 demo@127.0.0.1   (password: pass)
## See examples/quickstart/README.md for details.

demo:
	cd examples/quickstart && $(DOCKER) compose up --build

demo-down:
	cd examples/quickstart && $(DOCKER) compose down -v
