# Copilot Instructions for sshpiper

## What is sshpiper

sshpiper is a reverse proxy for SSH. It sits between SSH clients ("downstream") and SSH servers ("upstream"), routing connections based on configurable plugins. All SSH-based protocols (ssh, scp, port forwarding) are supported.

## Build

```bash
# Clone with submodules (required — crypto/ is a submodule)
git submodule update --init --recursive

# Build all binaries (daemon + all plugins)
mkdir -p out
go build -tags full -o out ./...
```

- **`-tags full`** includes all plugins. Without it, plugins are excluded from the build.
- **CGO is not used** — all builds are pure Go (`CGO_ENABLED=0`).
- GoReleaser handles release builds, multi-arch Docker images, and Snap packages (`.goreleaser.yaml`).

## Test

### Unit tests

```bash
# Run all unit tests with race detection and coverage
go test -v -race -cover -tags full ./...

# Run crypto/ssh tests separately (forked library)
cd crypto/ssh && go test ./...

# Run a single test
go test -v -tags full -run ^TestName$ ./path/to/package/
```

### E2E tests

E2E tests require Docker Compose and run inside a `testrunner` container:

```bash
cd e2e
docker compose up --build --force-recreate -d

# Or run with exit code from testrunner:
docker compose up --build --exit-code-from testrunner
```

The E2E suite spins up multiple SSH servers (password auth, pubkey auth, old OpenSSH, CA certs, Kubernetes via Kind) and tests each plugin against them.

### Lint and formatting

```bash
# golangci-lint with build tags (errcheck is disabled)
golangci-lint run --build-tags full -D errcheck

# gofumpt formatting check (stricter than gofmt) — CI uses v0.8.0
gofumpt -l .         # list unformatted files (must be empty)
gofumpt -w .         # auto-fix
```

## ⚠️ Required PR gates — DO NOT skip

Before considering any change/PR complete, you **must** verify all of these locally and confirm green on the PR:

1. **`gofumpt -l .` produces empty output** (workflow: `.github/workflows/gofumpt.yml`). `gofmt` is not enough — this repo enforces `gofumpt`.
2. **`go test -v -race -cover -tags full ./...` passes** (workflow: `.github/workflows/test.yml`).
3. **`cd crypto/ssh && go test ./...` passes** — the forked crypto package is tested separately.
4. **`golangci-lint run --build-tags full -D errcheck` passes** — the `--build-tags full` flag is required or plugin code is skipped.
5. **`goreleaser release --snapshot --clean` succeeds** for release-affecting changes (Dockerfile, `.goreleaser.yaml`, new plugin binaries).
6. **E2E suite passes** for changes touching the daemon, plugins, or crypto fork: `cd e2e && docker compose up --build --exit-code-from testrunner`.

After pushing to a PR, **always check the GitHub Actions results** (`gh pr checks <pr>` or via the GitHub MCP). Do not declare the task done while any required check is failing or pending — push fixes until every gate is green. Common failure: forgetting to run `gofumpt -w .` after edits, or omitting `-tags full` when running tests/lint locally and missing plugin-specific issues.

## Architecture

### Crypto fork (`crypto/`)

The `crypto/` directory is a **git submodule** containing a fork of `golang.org/x/crypto`. The `go.mod` replaces the upstream module:

```
replace golang.org/x/crypto => ./crypto
```

The key addition is `crypto/ssh/sshpiper.go`, which adds `PiperConfig` and `PiperConn` — the low-level API for intercepting SSH handshakes and piping two independent SSH connections together. This is the core of how sshpiper works as a man-in-the-middle for SSH auth.

### Plugin system

Plugins are **separate binaries** that communicate with `sshpiperd` over **gRPC via stdin/stdout** (`libplugin/ioconn/`). The gRPC service is defined in `libplugin/plugin.proto`.

**Key components:**
- `cmd/sshpiperd/` — the daemon that accepts downstream SSH connections and loads plugins
- `libplugin/` — the plugin SDK (gRPC proto, base implementation, helpers)
- `plugin/` — built-in plugin implementations

**Plugin lifecycle:**
1. `sshpiperd` spawns the plugin binary as a subprocess
2. Plugin calls `libplugin.NewFromStdio()` which starts a gRPC server on stdin/stdout
3. Daemon calls `ListCallbacks()` to discover which auth methods the plugin handles
4. On each SSH connection, daemon invokes the appropriate callback (e.g., `PasswordCallback`)
5. Plugin returns an `Upstream` struct with target host, port, and auth credentials

**Plugin chaining:** Multiple plugins can be chained with `--` separators on the command line. A plugin can return `UpstreamNextPluginAuth` to delegate to the next plugin in the chain.

### Writing a new plugin

Use `plugin/fixed/` (~30 lines) or `plugin/simplemath/` as templates. A minimal plugin:

1. Import `libplugin`
2. Define a `*libplugin.PluginTemplate` like the ones in `plugin/fixed/main.go` and other plugins
3. Implement `CreateConfig` on that template so it returns `*SshPiperPluginConfig`
4. Pass the template to `libplugin.CreateAndRunPluginTemplate()`
5. Implement one or more callbacks (`PasswordCallback`, `PublicKeyCallback`, etc.)
6. Each callback returns `*libplugin.Upstream` with target and auth info

## Conventions

- **Build tag `full`** must be used when building or testing the full project. Without it, plugins are excluded.
- **Build tag `e2e`** is used for E2E test mode in the testrunner container.
- CLI flags use `urfave/cli/v2`. Every flag has an environment variable equivalent prefixed with `SSHPIPERD_` (e.g., `--target` → `SSHPIPERD_FIXED_TARGET`).
- Logging uses `logrus` (`github.com/sirupsen/logrus`).
- The terms **downstream** (client side) and **upstream** (server side) are used consistently throughout the codebase.
- **Private key remapping**: For public key auth, plugins must provide a "mapping key" for the upstream since the two SSH sessions have different `session_id` values.

## Rebasing the crypto submodule onto upstream golang/crypto

The `crypto/` submodule (`https://github.com/tg123/sshpiper.crypto`, branch `v1`) is a fork of `https://github.com/golang/crypto` carrying sshpiper-specific patches (notably `crypto/ssh/sshpiper.go`). When upstream releases a new tag, follow this procedure to rebase:

1. **Find the latest upstream tag.** List tags from `https://github.com/golang/crypto` and pick the newest `vX.Y.Z`:
   ```bash
   cd crypto
   git fetch upstream --tags
   git --no-pager tag --sort=-v:refname --list 'v*' | grep -v sshpiper | head
   ```
   If the `upstream` remote is missing, add it: `git remote add upstream https://github.com/golang/crypto.git`.

2. **Rebase the sshpiper patches onto the new tag.** Do the work on a throwaway branch first so `v1` isn't disturbed if you need to retry:
   ```bash
   git fetch origin
   git checkout -b rebase-<new-upstream-tag> v1
   git rebase <new-upstream-tag>     # e.g. v0.50.0
   ```
   Resolve conflicts — most patches live in `crypto/ssh/sshpiper.go` and small touches to `crypto/ssh/server.go` / `client_auth.go`. There are typically ~17 sshpiper patches; recent rebases (e.g. v0.48.0 → v0.50.0) have applied cleanly with no conflicts.

3. **Verify tests pass** in the submodule first, then in the main repo:
   ```bash
   cd crypto/ssh && go test ./...
   cd ../..
   # Bump golang.org/x/crypto require line in go.mod to match the new upstream tag
   #   sed -i 's|golang.org/x/crypto v[0-9.]*|golang.org/x/crypto v0.50.0|' go.mod
   go mod tidy            # required — new upstream often pulls in newer x/sys, x/term
   go build -tags full ./...
   go test -race -tags full ./...
   ```

4. **Move `v1` and tag, then push to the fork.** Tag format is **`<upstream-tag>-sshpiper-<YYYYMMDD>`** (e.g. `v0.50.0-sshpiper-20260423`). Use `--force-with-lease` because `v1` history was rewritten:
   ```bash
   cd crypto
   git branch -f v1 rebase-<new-upstream-tag>
   git checkout v1
   TAG="<new-upstream-tag>-sshpiper-$(date -u +%Y%m%d)"
   git tag "$TAG"
   git push origin v1 --force-with-lease
   git push origin "$TAG"
   ```

5. **Open the sshpiper PR.** Branch off the latest `origin/master` (not local `master`, which may be stale):
   ```bash
   cd ..   # back to sshpiper repo root
   git fetch origin
   git checkout -b chore/rebase-crypto-<new-upstream-tag> origin/master
   git add crypto go.mod go.sum
   git commit -m "chore: rebase crypto onto <new-upstream-tag>"
   git push -u origin HEAD
   gh pr create --fill
   ```
   Confirm `git ls-tree HEAD crypto` shows the new submodule SHA. If you instead rebased a feature branch onto a moved `origin/master` and hit `go.mod`/`go.sum` conflicts, note that **`--ours`/`--theirs` are reversed during rebase** (`--ours` = `origin/master`, `--theirs` = your branch). Easiest resolution: `git checkout --ours go.mod go.sum`, re-bump `golang.org/x/crypto` to the new version, then `go mod tidy && git add go.mod go.sum && git rebase --continue`. After pushing, verify all CI gates pass (see "Required PR gates" above).
