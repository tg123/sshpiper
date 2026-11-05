# sshpiper 🖇

[![E2E](https://github.com/tg123/sshpiper/actions/workflows/e2e.yml/badge.svg)](https://github.com/tg123/sshpiper/actions/workflows/e2e.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/tg123/sshpiper)](https://goreportcard.com/report/github.com/tg123/sshpiper)
[![Docker Image](https://img.shields.io/docker/pulls/farmer1992/sshpiperd.svg)](https://hub.docker.com/r/farmer1992/sshpiperd)

`sshpiper` is the reverse proxy for sshd. all protocols, including ssh, scp, port forwarding, running on top of ssh are supported. 

*Note:* this is `v1` version, checkout legacy `v0` [here](https://github.com/tg123/sshpiper/tree/v0)

### Overview and Terminology

 * `downstream`: the client side, typically an ssh client.
 * `upstream`: the server side, typically an ssh server.
 * `plugin`: handles the routing from `downstream` to `upstream`. The `plugin` is also responsible for mapping authentication methods to the upstream server. For example, the downstream may use password authentication, but the upstream server may receive public key authentication mapped by `sshpiper`.
 * `additional challenge`: some `plugins` will not only perform routing but also add additional challenges to SSH authentication for the `upstream` server. For example, the `downstream` may be asked for two-factor authentication provided by the `plugin`.


```
+---------+                      +------------------+          +-----------------+
|         |                      |                  |          |                 |
|   Bob   +----ssh -l bob----+   |   sshpiper    +------------->   Bob' machine  |
|         |                  |   |               |  |          |                 |
+---------+                  |   |               |  |          +-----------------+
                             +---> pipe-by-name--+  |                             
+---------+                  |   |               |  |          +-----------------+
|         |                  |   |               |  |          |                 |
|  Alice  +----ssh -l alice--+   |               +------------->  Alice' machine |
|         |                      |                  |          |                 |
+---------+                      +------------------+          +-----------------+


 downstream                         sshpiper                        upstream                     

```

## Quick start

### Build

```
git clone https://github.com/tg123/sshpiper
cd sshpiper

mkdir out
go build -tags full -o out ./...
cargo build --locked --release --manifest-path rust/Cargo.toml --bin sshpiperd
# The daemon is rust/target/release/sshpiperd (.exe on Windows).
```

### Rust daemon

`rust/daemon` implements a Rust-native `sshpiperd` using `rust/transport` and
unmodified cryptographic crates, rather than an SSH-library fork. It communicates
with the existing, unchanged Go plugins using their stdio or network gRPC APIs.
The daemon, Docker images, release archives, and Snap packages use Rust.
There is no Go daemon, Go runtime linked into the daemon, or SSH-library fork.
Go remains the implementation language of the existing plugins, SDK, admin CLI,
and webadmin.

The Docker image runs the daemon under Tini as PID 1 to reap orphaned plugin
descendants, forward signals, and preserve the daemon's exit status. Tini does not
wait for the daemon's direct plugin children; those remain managed by Tokio.
Keep the image's default entrypoint, or provide an equivalent init when overriding
it or running the native daemon as a container's PID 1.

The component provides client/server key exchange, explicitly trusted host-key
verification, encrypted opaque packet relay, bounded full-duplex queues, and
independent rekeying on each side. Channel IDs and unknown connection payloads are
not rewritten. The transport prefers `mlkem768x25519-sha256` (using unmodified
libcrux ML-KEM) and also supports `curve25519-sha256`, Ed25519,
RSA-SHA2 and ECDSA P-256/P-384/P-521 host keys (including host certificates),
AES-128/256-GCM, and no compression.
The direct transport API serializes operations and becomes unusable if an
operation is cancelled; its split driver provides cancellation-safe receives and
concurrent sending/receiving.

From the `rust` directory:

```text
cargo test --locked --all-targets
cargo test --locked --test openssh -- --ignored
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --bin sshpiperd
cargo run --locked --release -p sshpiper-transport --example throughput
```

The daemon implements password, public-key and keyboard-interactive authentication,
plugin chaining, upstream host verification, RSA/ECDSA remote signing, custom gRPC
connections, forwarding policies, env injection, recording, and the admin API.

Downstream channel opens and global requests can be restricted with
`--allowed-channel-types` / `--denied-channel-types` and
`--allowed-global-requests` / `--denied-global-requests`. Each allow/deny pair is
mutually exclusive; values are repeatable or comma-separated and match
case-sensitively after trimming whitespace. An explicitly empty allowlist denies
all types. The corresponding `SSHPIPERD_ALLOWED_CHANNEL_TYPES`,
`SSHPIPERD_DENIED_CHANNEL_TYPES`, `SSHPIPERD_ALLOWED_GLOBAL_REQUESTS`, and
`SSHPIPERD_DENIED_GLOBAL_REQUESTS` environment variables are also supported.
`--disable-local-forwarding` and `--disable-remote-forwarding` add mandatory
denials even when the corresponding types appear in an allowlist.
Private keys may use OpenSSH, PKCS#8 (Ed25519, RSA, or NIST EC), PKCS#1 RSA,
or named-curve SEC1 EC PEM encoding, including keys produced by Go plugins.
Downstream algorithm lists can restrict and reorder the supported algorithms,
including the legacy `curve25519-sha256@libssh.org` name. AES-GCM authenticates
packets internally, so separate MAC algorithms are not used. Unsupported algorithms
are rejected at startup rather than silently ignored. Certificates retain the
OpenSSH no-expiry timestamp without modifying their CA-signed wire data.
`--allowed-downstream-pubkey-algos` accepts signature algorithm names:
`ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp521`. These restrictions also apply
to the corresponding certificate authentication algorithms; use the signature
name, not a certificate key type or the SHA-1 `ssh-rsa` algorithm.
Compared with the former Go daemon, the supported transport algorithm set is
deliberately limited to the algorithms listed above: AES-CTR/CBC, standalone
HMAC modes, NIST ECDH and finite-field DH key exchange, SHA-1 signatures, and
compression are not implemented.

From `e2e`, run `docker compose up --build --exit-code-from testrunner`.
The suite uses Rust for both the proxy and the image loaded into Kubernetes.
The native Windows/macOS suites build Rust automatically, or accept
`SSHPIPERD_E2E_DAEMON` pointing to a prebuilt binary. They still build and exercise
every shipped Go plugin, including their process-lifetime and paths-with-spaces
assertions.

The OpenSSH test requires `ssh` on PATH. The throughput example measures a
64 MiB in-memory encrypted relay after warmup, verifies every payload, and prints
JSON. It includes endpoint encryption/decryption and is a microbenchmark, **not
evidence of a performance improvement over the Go daemon**.

CI retains the existing 90% end-to-end throughput gate relative to direct SSH.
The benchmark workflow also builds a pinned historical Go revision for comparison;
separate-runner results do not by themselves demonstrate a Rust speedup.
The same-runner comparison builds only the historical Go daemon and runs it
beside Rust with the same current plugins, OpenSSH endpoints, cipher, and 64 MiB
workloads. Six trials rotate Go/Rust/direct order; the summary reports median
throughput, paired ratios and their range, and enforces the 90% direct-SSH gate.
Raw samples are uploaded as `same-runner-benchmarks`. This comparison includes
connection setup and does not measure CPU usage, memory, or concurrent capacity.
`SSHPIPERD_BENCH_DAEMON` selects an alternative daemon for the existing E2E
benchmark without changing its payload or client.
For a native, disk-free upload/download comparison, set
`SSHPIPERD_BENCH_DAEMON` and `SSHPIPERD_RUST_FIXED_PLUGIN` to built binaries, then
run `go test -tags rustdaemon -run '^$' -bench BenchmarkDaemonTransfer -benchtime=10s ./rust/daemon/tests/interop`.
Use release builds and alternate the daemon binary on the same machine.
This independent Go SSH harness isolates transport costs; it does not replace
the OpenSSH/SCP end-to-end gate.

The relay batches only packets already queued, without adding a batching delay.
Each batch is limited to eight packets and 256 KiB of payload, keeping the
transport command queue's existing byte bound. Small interactive writes still
flush immediately; batched writes preserve ordering, rekeying, and final-packet
draining.
Callers of the transport must impose deadlines and complete user authentication
before relaying connection packets.

Release workflows build native Rust binaries for Linux (static musl), Windows
(static CRT), and macOS, on amd64 and arm64. Before running
`goreleaser release --snapshot --clean` locally, place those binaries under
`native/<os>_<arch>/sshpiperd[.exe]`, using the artifacts from the `rust-build.yml`
workflow. GoReleaser builds the unchanged Go components and includes the native
daemon in archives, Docker images, and [Snap packages](packaging/snap/README.md).

### Native Windows and macOS E2E tests

On Windows, run from the repository root in PowerShell with native Go, Rust, and Docker Compose
installed in the default WSL2 distribution (with its Docker daemon running):

```powershell
.\e2e\windows\run.ps1
```

On macOS, use native Go and Rust and a running Docker daemon with Compose (for example,
Docker Desktop or Colima), then run from the repository root:

```bash
bash e2e/macos/run.sh
```

Both runners use the shared `e2e/native` suite. It reads `.goreleaser.yaml` to
build every plugin shipped for the current OS and fails if any release plugin
lacks a native E2E scenario. The daemon and plugins run from paths containing
spaces. Windows and macOS currently ship the same eight plugins:

| Plugin | Native E2E behavior |
| --- | --- |
| `fixed` | Password rejection, binary stdin/stdout, stderr, exit status, reconnects |
| `workingdir` | Directory-based username remapping and rejection of missing users |
| `yaml` | Regex username remapping and rejection of unmatched users |
| `username-router` | Target/port and upstream user parsed from the downstream username; malformed username rejection |
| `lua` | Script-based routing, username remapping, and rejection |
| `failtoban` | Chaining with `fixed`, banning after failed authentication, and loopback allowlisting |
| `metrics` | Chaining with `fixed`, HTTP connection gauge lifecycle, authentication and pipe-creation error counters |
| `revtunnel` | Public-key registration, password-authenticated reverse forwarding, native file session store, and revocation |

On Windows, the suite also checks plugin termination when the daemon is forcibly
killed, using a helper that deliberately survives stdio closure. File-based
routing tests use `--no-check-perm` only on Windows, whose mode bits cannot express
Unix owner-only permissions; macOS keeps permission checks enabled. Docker and
Kubernetes plugins are Linux-only in the release config; `simplemath` is not shipped.
On macOS, a pipe-watching supervisor terminates each daemon's process group,
including its plugins, even if the parent test process times out or is interrupted.

The upstream is the real OpenSSH `host-password`
service from `e2e/docker-compose.yml`, with `e2e/docker-compose.native.yml`
publishing an ephemeral loopback port. Each runner starts an isolated Compose
project (through WSL2 on Windows), runs native `go test`, and collects logs and
removes the containers and volumes even on failure. Only the upstream SSH server
runs in Docker; the Go runner, daemon, and plugins stay native to the host OS.

The E2E workflow provisions WSL2 and Docker on `windows-latest` and Colima on
`macos-15-intel`, alongside the existing Linux Docker Compose suite. The macOS
job uses Intel because hosted Apple Silicon runners do not support the nested
virtualization Colima needs; native macOS arm64 is not exercised in CI.
To run Go tests directly against an already-started Compose `host-password` service, set
`SSHPIPERD_E2E_UPSTREAM` to its published `host:port`, then run
`go test -v -count=1 -tags e2e -timeout 10m ./e2e/native`.

## Run simple demo

### start dummy sshd server

```
docker run -d -e USER_NAME=user -e USER_PASSWORD=pass -e PASSWORD_ACCESS=true -p 127.0.0.1:5522:2222 lscr.io/linuxserver/openssh-server
```

### start `sshpiperd` with `fixed` plugin targeting the dummy sshd server

```
./out/sshpiperd -i /tmp/sshpiperkey --server-key-generate-mode notexist --log-level=trace ./out/fixed --target 127.0.0.1:5522
```

### test ssh connection (password: `pass`)

```
ssh 127.0.0.1 -l user -p 2222
```

### ➕ math before login? 

Here illustrates the example of `additional challenge` before the `fixed` plugin.

```
./out/sshpiperd -i /tmp/sshpiperkey --server-key-generate-mode notexist --log-level=trace ./out/simplemath -- ./out/fixed --target 127.0.0.1:5522
```

## More examples

For Docker Compose demos (including username routing and Lua publickey git routing), see [examples/](examples/).

## Admin UI (`sshpiperd-webadmin`)

`sshpiperd` can optionally expose a small **admin gRPC API** that lets external
tools list live SSH sessions, view their terminal output in real time, and
kill them. This API is **off by default** and is enabled by passing a non-zero
`--admin-grpc-port`. By default the API requires TLS, so a server cert/key
must be supplied:

```
./out/sshpiperd --admin-grpc-port 8222 \
  --admin-grpc-tls-cert server.crt \
  --admin-grpc-tls-key server.key \
  ... <plugin> ...
```

For mutual TLS (recommended for production), also pass
`--admin-grpc-tls-cacert ca.crt` so clients must present a certificate
signed by `ca.crt`. To opt out of TLS entirely on a trusted network, pass
`--admin-grpc-insecure`.

A separate binary, `sshpiperd-webadmin`, aggregates one or more sshpiperd admin
endpoints and serves a browser dashboard plus a JSON HTTP API:

```
./out/sshpiperd-webadmin \
  --sshpiperd 127.0.0.1:8222 \
  --sshpiperd piper-2.internal:8222 \
  --tls-cacert ca.crt --tls-cert client.crt --tls-key client.key \
  -l 127.0.0.1 -p 8080
```

Then open <http://127.0.0.1:8080>. Endpoints can also be supplied via the
`SSHPIPERD_WEBADMIN_ENDPOINTS` env var (comma-separated). Pass
`--insecure` on the webadmin side when sshpiperd is started with
`--admin-grpc-insecure`. The same client library (`libadmin/`) is structured
so a future CLI tool (`sshpiperd-admin`) can reuse the discovery +
aggregator code.

## Plugins

### icons

 * 🔀: routing plugin
 * 🔒: additional challenge plugin
 * 📈: metrics plugin

Plugin list

 * [workingdir](plugin/workingdir/) 🔀: `/home`-like directory to managed upstreams routing by sshpiperd.
 * [yaml](plugin/yaml/) 🔀: config routing with a single yaml file.
 * [lua](plugin/lua/) 🔀🔒: scriptable plugin for custom routing and auth challenges.
 * [docker](plugin/docker/) 🔀: pipe into docker containers.
 * [kubernetes](plugin/kubernetes/) 🔀: manage pipes via Kubernetes CRD.
 * [azdevicecode](https://github.com/tg123/sshpiper-plugins/tree/main/azdevicecode) 🔒: ask user to enter [azure device code](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) before login
 * [fixed](plugin/fixed/) 🔀: fixed targeting the dummy sshd server
 * [username-router](plugin/username-router/) 🔀: route based on username, the username format is `target+username`, where `target` is the target host and `username` is the username to use for that target.
 * [simplemath](plugin/simplemath/) 🔒: ask for very simple math question before login, demo purpose
 * [githubapp](https://github.com/tg123/sshpiper-gh) 🔀: login ssh with your github account
 * [restful](https://github.com/11notes/docker-sshpiper) by [@11notes](https://github.com/11notes) 🔀🔒: The rest plugin for sshpiperd is a simple plugin that allows you to use a restful backend for authentication and challenge.
 * [failtoban](plugin/failtoban/) 🔒: ban ip after failed login attempts
 * [openpubkey](https://github.com/tg123/sshpiper-openpubkey)🔀🔒: integrate with [openpubkey](https://github.com/openpubkey/openpubkey)
 * [metrics](plugin/metrics/) 📈: serve prometheus metrics on open connections and auth errors

## Screen recording

### asciicast

recording the screen in `asciicast` format <https://docs.asciinema.org/manual/asciicast/v2/>

To use it, start sshpiperd with `--screen-recording-format asciicast` and `--screen-recording-dir /path/to/recordingdir`

    Example:

    ```
    ssh user_name@
    ... do some commands
    exit

    asciinema play /path/to/recordingdir/<conn_guid>/shell-channel-0.cast

    ```

### typescript

recording the screen in `typescript` format (not the lang). The format is compatible with [scriptreplay(1)](https://linux.die.net/man/1/scriptreplay)


To use it, start sshpiperd with `--screen-recording-format typescript` and `--screen-recording-dir /path/to/recordingdir`

    Example:

    ```
    ssh user_name@127.0.0.1 -p 2222
    ... do some commands
    exit


    $ cd /path/to/recordingdir/<conn_guid>
    $ ls *.timing *.typescript
    1472847798.timing 1472847798.typescript

    $ scriptreplay -t 1472847798.timing 1472847798.typescript # will replay the ssh session
    ```


## Public key authentication when using sshpiper (Private key remapping)

During SSH publickey auth, [RFC 4252 Section 7](http://tools.ietf.org/html/rfc4252#section-7),
ssh client sign `session_id` and some other data using private key into a signature `sig`.
This is for server to verify that the connection is from the client not `the man in the middle`.

However, sshpiper actually holds two ssh connection, and it is doing what `the man in the middle` does.
the two ssh connections' `session_id` will never be the same, because they are hash of the shared secret. [RFC 4253 Section 7.2](http://tools.ietf.org/html/rfc4253#section-7).


To support publickey auth, `sshpiper` routing plugin must provide a new private key for the `upstream` to sign the `session_id`. This new private key is called `mapping key`.

How this work

```
+------------+        +------------------------+                       
|            |        |                        |                       
|   client   |        |   sshpiper             |                       
|   PK_X     +-------->      |                 |                       
|            |        |      v                 |                       
|            |        |   Check Permission     |                       
+------------+        |      |                 |                       
                      |      |                 |                       
                      |      |                 |     +----------------+
                      |      v                 |     |                |
                      |   sign again           |     |   server       |
                      |   using PK_Y  +-------------->   check PK_Y   |
                      |                        |     |                |
                      |                        |     |                |
                      +------------------------+     +----------------+
```

## Ports to other platforms

 * [sshpiper on OpenWrt](https://github.com/ihidchaos/sshpiper-openwrt) by [@ihidchaos](https://github.com/ihidchaos)

## Migrating from `v0`

### What's the major change in `v1`
 
 * low level sshpiper api is fully redesigned to support more routing protocols.
 * plugins system totally redesigned to be more flexible and extensible.
   * plugins are now separated from main process and no longer a single big binary, this allow user to write their own plugins without touching `sshpiperd` code.
 * `grpc` is first class now, the plugins are built on top of it

For plugins already in `v1`, you need change params to new params. However, not all plugins are migrated to `v1` yet, they are being migrated gradually. you can still use the old plugins in [`v0` branch](https://github.com/tg123/sshpiper/tree/v0)


## Contributing

see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
MIT
