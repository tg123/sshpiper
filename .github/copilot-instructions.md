# Copilot Instructions for sshpiper

## What is sshpiper

sshpiper is a reverse proxy for SSH. It sits between SSH clients ("downstream") and SSH servers ("upstream"), routing connections based on configurable plugins. All SSH-based protocols (ssh, scp, port forwarding) are supported.

## Build

```bash
# Build root module (plugins, admin/webadmin CLI, libs)
mkdir -p out
go build -tags full -o out ./...

# Build the sshpiperd daemon (separate module so the forked crypto stays scoped to it)
(cd cmd/sshpiperd && go build -o ../../out/ .)
```

- **`-tags full`** includes all plugins. Without it, plugins are excluded from the build.
- **CGO is not used** — all builds are pure Go (`CGO_ENABLED=0`).
- **Two Go modules:** the root `github.com/tg123/sshpiper` module uses upstream `golang.org/x/crypto`; the nested `cmd/sshpiperd/go.mod` module contains the daemon and has `replace golang.org/x/crypto => github.com/tg123/sshpiper.crypto <tag>` so only the daemon links against the fork. **No git submodule** — the fork is pulled in as a regular Go module dependency.
- GoReleaser handles release builds, multi-arch Docker images, and Snap packages (`.goreleaser.yaml`).

## Test

### Unit tests

```bash
# Root module: plugins, libs, admin/webadmin
go test -v -race -cover -tags full ./...

# Daemon module
(cd cmd/sshpiperd && go test -v -race -cover ./...)

# Run a single test (specify the module/package)
go test -v -tags full -run ^TestName$ ./path/to/package/
```

> The forked `crypto/ssh` library is **not** tested from this repo — its tests live in the
> [`tg123/sshpiper.crypto`](https://github.com/tg123/sshpiper.crypto) repository and run in that repo's own CI.

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
# golangci-lint with build tags (errcheck is disabled). Must be run per module.
golangci-lint run --build-tags full -D errcheck
(cd cmd/sshpiperd && golangci-lint run -D errcheck)

# gofumpt formatting check (stricter than gofmt) — CI uses v0.8.0
gofumpt -l .         # list unformatted files (must be empty)
gofumpt -w .         # auto-fix
```

## ⚠️ Required PR gates — DO NOT skip

Before considering any change/PR complete, you **must** verify all of these locally and confirm green on the PR:

1. **`gofumpt -l .` produces empty output** (workflow: `.github/workflows/gofumpt.yml`). `gofmt` is not enough — this repo enforces `gofumpt`.
2. **`go test -v -race -cover -tags full ./...` passes** in the root module, AND `cd cmd/sshpiperd && go test -v -race -cover ./...` passes in the daemon module (workflow: `.github/workflows/test.yml`).
3. **`golangci-lint run --build-tags full -D errcheck` passes for the root module AND `cd cmd/sshpiperd && golangci-lint run -D errcheck` passes for the daemon module** — both modules are linted independently.
4. **`goreleaser release --snapshot --clean` succeeds** for release-affecting changes (Dockerfile, `.goreleaser.yaml`, new plugin binaries).
5. **E2E suite passes** for changes touching the daemon or plugins: `cd e2e && docker compose up --build --exit-code-from testrunner`.

After pushing to a PR, **always check the GitHub Actions results** (`gh pr checks <pr>` or via the GitHub MCP). Do not declare the task done while any required check is failing or pending — push fixes until every gate is green. Common failure: forgetting to run `gofumpt -w .` after edits, or omitting `-tags full` when running tests/lint locally and missing plugin-specific issues.

## Architecture

### Crypto fork

The forked `golang.org/x/crypto` lives in a **separate repository**,
[`tg123/sshpiper.crypto`](https://github.com/tg123/sshpiper.crypto) (branch `v1`, tagged
`vX.Y.Z-sshpiper-YYYYMMDD`). It is pulled in as a regular Go module dependency — there is **no git submodule**.
The fork is scoped to a single Go module so it does not leak into plugins:

- `cmd/sshpiperd/go.mod` (the daemon module) has `replace golang.org/x/crypto => github.com/tg123/sshpiper.crypto <tag>`. Everything compiled into the `sshpiperd` binary uses the forked `ssh` package.
- The root `go.mod` does **not** replace `golang.org/x/crypto`. Every plugin under `plugin/*`, the libs under `libplugin/` / `libadmin/`, and the `sshpiperd-admin` / `sshpiperd-webadmin` CLIs build against upstream `golang.org/x/crypto` and therefore cannot import fork-only symbols.

The key addition in the fork is `ssh/sshpiper.go`, which adds `PiperConfig` and `PiperConn` — the low-level API for intercepting SSH handshakes and piping two independent SSH connections together. Only the daemon module can reach those symbols.

> Do not commit a `go.work` at the repo root: in workspace mode the daemon's `replace` would leak into root-module builds and destroy the isolation. If you want IDE/workspace support — or to develop against a local checkout of `sshpiper.crypto` — create a local `go.work` (it is gitignored). Example:
>
> ```
> go 1.26
> use ./
> use ./cmd/sshpiperd
> use ../sshpiper.crypto
> ```

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

## Rebasing the crypto fork onto upstream golang/crypto

The fork (`https://github.com/tg123/sshpiper.crypto`, branch `v1`) is a fork of `https://github.com/golang/crypto` carrying sshpiper-specific patches (notably `ssh/sshpiper.go`). It lives in its own repo and is consumed by `cmd/sshpiperd` as a regular Go module dependency (`replace golang.org/x/crypto => github.com/tg123/sshpiper.crypto <tag>`). When upstream releases a new tag, follow this procedure to rebase:

1. **Clone the fork repo locally** (alongside your sshpiper checkout):
   ```bash
   git clone https://github.com/tg123/sshpiper.crypto ../sshpiper.crypto
   cd ../sshpiper.crypto
   git remote add upstream https://github.com/golang/crypto.git   # one-time
   git fetch upstream --tags
   git --no-pager tag --sort=-v:refname --list 'v*' | grep -v sshpiper | head
   ```

2. **Rebase the sshpiper patches onto the new tag.** Do the work on a throwaway branch first so `v1` isn't disturbed if you need to retry:
   ```bash
   git fetch origin
   git checkout -b rebase-<new-upstream-tag> v1
   git rebase <new-upstream-tag>     # e.g. v0.50.0
   ```
   Resolve conflicts — most patches live in `ssh/sshpiper.go` and small touches to `ssh/server.go` / `client_auth.go`. There are typically ~17 sshpiper patches; recent rebases have applied cleanly with no conflicts.

3. **Verify tests pass** in the fork repo:
   ```bash
   cd ssh && go test ./...
   ```

4. **Move `v1` and tag, then push to the fork.** Tag format is **`<upstream-tag>-sshpiper-<YYYYMMDD>`** (e.g. `v0.50.0-sshpiper-20260423`). Use `--force-with-lease` because `v1` history was rewritten:
   ```bash
   git branch -f v1 rebase-<new-upstream-tag>
   git checkout v1
   TAG="<new-upstream-tag>-sshpiper-$(date -u +%Y%m%d)"
   git tag "$TAG"
   git push origin v1 --force-with-lease
   git push origin "$TAG"
   ```

5. **Open the sshpiper PR.** Branch off the latest `origin/master` (not local `master`, which may be stale), bump both the `require` and `replace` lines in `cmd/sshpiperd/go.mod`, and tidy:
   ```bash
   cd <sshpiper-repo>
   git fetch origin
   git checkout -b chore/rebase-crypto-<new-upstream-tag> origin/master
   # In cmd/sshpiperd/go.mod, bump:
   #   - the golang.org/x/crypto require line to the new upstream version
   #   - the replace target to github.com/tg123/sshpiper.crypto <new-tag>
   (cd cmd/sshpiperd && go mod tidy)
   # Root module may also need its golang.org/x/crypto require bumped:
   go mod tidy
   git add go.mod go.sum cmd/sshpiperd/go.mod cmd/sshpiperd/go.sum
   git commit -m "chore: rebase crypto onto <new-upstream-tag>"
   git push -u origin HEAD
   gh pr create --fill
   ```
   If you rebased a feature branch onto a moved `origin/master` and hit `go.mod`/`go.sum` conflicts, note that **`--ours`/`--theirs` are reversed during rebase** (`--ours` = `origin/master`, `--theirs` = your branch). Easiest resolution: `git checkout --ours go.mod go.sum`, re-bump `golang.org/x/crypto`, then `go mod tidy && git add go.mod go.sum && git rebase --continue`. After pushing, verify all CI gates pass (see "Required PR gates" above).
