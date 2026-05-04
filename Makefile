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

GOFUMPT       ?= gofumpt
GOLANGCI_LINT ?= golangci-lint

.PHONY: all build web test test-crypto lint fmt fmt-check clean \
        docker docker-slim docker-full \
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
## Local single-platform builds for development. The published multi-arch
## images are built and pushed by GoReleaser (`dockers:` / `docker_manifests:`
## in `.goreleaser.yaml`) using the same `Dockerfile` with `EXTERNAL=1`, so
## release images contain the exact binaries that ship in the GH archives.

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
