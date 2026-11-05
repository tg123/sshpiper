# Copilot Instructions for sshpiper

## What is sshpiper

sshpiper is a reverse proxy for SSH. It routes downstream clients to upstream
servers through configurable plugins and supports SSH-based protocols, including
scp and port forwarding.

## Build

```bash
# Unchanged Go plugins, SDK, admin CLI, and webadmin
mkdir -p out
go build -tags full -o out ./...

# Rust-native daemon
cargo build --locked --release --manifest-path rust/Cargo.toml --bin sshpiperd
```

- `-tags full` includes every Go plugin.
- Go production builds use `CGO_ENABLED=0`. Go race tests require CGO.
- The root Go module uses upstream `golang.org/x/crypto`. There is no nested
  daemon Go module, crypto fork, or git submodule.
- The Cargo workspace contains `rust/daemon` and `rust/transport`.
- Native release binaries are built by `.github/workflows/rust-build.yml` on
  Linux, Windows, and macOS, for amd64 and arm64. Linux uses static musl and
  Windows uses the static CRT.
- GoReleaser builds the Go components and packages native Rust binaries supplied
  under `native/<os>_<arch>/sshpiperd[.exe]`. Download those workflow artifacts
  before running a local release snapshot.

## Tests and lint

```bash
go test -v -race -cover -tags full ./...
golangci-lint run --build-tags full -D errcheck
gofumpt -l . # must produce no output; CI uses v0.8.0

cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path rust/Cargo.toml --workspace
cargo test --locked --manifest-path rust/Cargo.toml --test openssh -- --ignored
```

The explicit OpenSSH test needs `ssh` on PATH. Independent Go SSH interoperability
tests live in `rust/daemon/tests/interop` and use the `rustdaemon` build tag.
Set `SSHPIPERD_RUST_DAEMON` and `SSHPIPERD_RUST_FIXED_PLUGIN` to built binaries,
then run `go test -race -tags rustdaemon ./rust/daemon/tests/interop`.

## Required PR gates

Before considering a change complete, verify the applicable gates locally and
confirm green on the PR:

1. `gofumpt -l .` is empty. `gofmt` alone is insufficient.
2. The full root Go unit/race suite and golangci-lint pass with `full` tags.
3. Rust formatting, clippy with warnings denied, unit/integration/documentation
   tests, and independent Go/OpenSSH interoperability pass.
4. All six native release builds and `goreleaser release --snapshot --clean`
   pass for release-affecting changes.
5. Full Docker/Kubernetes E2E and native Windows/macOS E2E pass for daemon or
   plugin changes. Do not remove assertions or exclude shipped plugins.
6. Preserve the 90% benchmark gate relative to direct SSH. A historical Go
   revision is pinned only for benchmark comparison, not production builds.

Always check `gh pr checks` after pushing. Do not declare completion with failing
or pending required checks.

## E2E

```bash
cd e2e
docker compose up --build --exit-code-from testrunner
```

The suite exercises password/public-key auth, old OpenSSH, certificates, gRPC
plugins, and Kubernetes. Both the test proxy and Kubernetes image use Rust.
Native E2E runs through `e2e/windows/run.ps1` or `e2e/macos/run.sh`, using a native
Rust toolchain and Go plus Docker Compose. `SSHPIPERD_E2E_DAEMON` optionally
selects a prebuilt daemon. The suite derives its plugin matrix from
`.goreleaser.yaml`; every shipped plugin needs a scenario.

## Architecture

- `rust/transport/` owns SSH framing, negotiation, key exchange, authenticated
  encryption, and independent rekeying, using unmodified cryptographic crates.
  Connection-layer packets stay opaque, including channel IDs and extensions.
- `rust/daemon/` owns authentication, plugin chaining, host verification,
  forwarding policies, recordings, PROXY headers, and the admin API.
- `libplugin/` is the unchanged Go plugin SDK; `libadmin/` is the Go admin SDK.
- `plugin/` contains separate Go plugin binaries.
- `packaging/snap/` contains the Snap launcher and configure hook. The launcher
  execs Rust; no persistent Go wrapper runs.

Direct transport operations are serialized and cancellation poisons the
transport. Split-driver receives are cancellation-safe. Always impose handshake
deadlines and finish authentication before relaying connection packets.
The README lists supported algorithms; unsupported configured algorithms must
fail explicitly, not silently broaden the negotiated policy.

## Plugin system

Plugins communicate over gRPC on stdin/stdout through `libplugin/ioconn/`, or
over network gRPC. Keep `libplugin/plugin.proto` and existing Go plugins unchanged
when working on the Rust implementation.

The daemon spawns plugins, calls `ListCallbacks`, invokes authentication
callbacks, and receives an `Upstream` describing the target and credentials.
Command-line `--` separates chained plugins; `UpstreamNextPluginAuth` delegates
to the next plugin.

Use `plugin/fixed/` or `plugin/simplemath/` as a new-plugin template. Implement
`CreateConfig` on `libplugin.PluginTemplate`, return a `SshPiperPluginConfig`,
and pass the template to `libplugin.CreateAndRunPluginTemplate`.

## Conventions

- Go plugin flags use `urfave/cli/v2`; Rust daemon flags use Clap. Preserve
  existing CLI names and `SSHPIPERD_` environment variables.
- Go logging uses logrus; Rust logging uses tracing on stderr.
- Use downstream for the client side and upstream for the server side.
- Public-key remapping requires an upstream signing key: the two SSH sessions
  have different session IDs.
- The `full` build tag selects Go plugins; `e2e` selects container test plugins.
