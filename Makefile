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

# Multi-arch platforms used by `docker-push*`.
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

GOFUMPT       ?= gofumpt
GOLANGCI_LINT ?= golangci-lint

.PHONY: all build web test test-crypto lint fmt fmt-check clean \
        docker docker-slim docker-full \
        docker-push docker-push-slim docker-push-full \
        goreleaser-snapshot goreleaser-check e2e \
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
	rm -rf $(OUT_DIR) dist $(WEB_DIST)

## --- Docker images -----------------------------------------------------------
##
## All Docker images are built from the same Dockerfile (single source of
## truth). The "slim" image omits the optional plugins gated behind the `full`
## build tag; the "full" image includes them all.

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

# Multi-arch image build / publish. Tags mirror what GoReleaser used to produce:
#   slim: <repo>:v<VERSION>, <repo>:latest
#   full: <repo>:full-v<VERSION>, <repo>:full
#
# Use `make docker-push PUSH=1 VERSION=1.2.3` from CI to publish; without
# `PUSH=1` the build is exercised but not pushed (and only the host platform
# image is loaded locally — buildx cannot --load a multi-arch manifest).

# Build the per-image tag flags for every repo in IMAGE_REPOS.
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

## --- GoReleaser / E2E --------------------------------------------------------

goreleaser-snapshot:
	goreleaser release --snapshot --clean

goreleaser-check:
	goreleaser check

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
