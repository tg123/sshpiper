# Contributing

Thank you for your interest in contributing to sshpiper.
Make sure you have read [README.md](README.md) before starting.

## Getting Started

### Software Requirements
 * Go <https://go.dev/>
 * Rust <https://rustup.rs/> (stable toolchain)
 * Docker <https://www.docker.com/>
 * Docker Compose <https://docs.docker.com/compose/install/>
 * Git <https://git-scm.com/>

### Get the code

```
git clone https://github.com/tg123/sshpiper
cd sshpiper
```

The daemon is the Cargo workspace under `rust/`. The root Go module contains
the unchanged plugins, SDK, and administration tools and uses upstream
`golang.org/x/crypto`. No crypto fork, nested daemon Go module, or submodule is needed.

Build the daemon with `cargo build --locked --release --manifest-path rust/Cargo.toml`.
Build the Go components with `go build -tags full -o out ./...`.
Run `cargo test --locked --manifest-path rust/Cargo.toml --workspace`,
`cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings`,
`go test -race -cover -tags full ./...`, and `gofumpt -l .` before submitting changes.

### Start Develop Environment

 _Note_: in vscode, you can use Reopen in dev container to start the develop environment.

```
# in e2e folder, run:
SSHPIPERD_DEBUG=1 docker-compose up --force-recreate --build -d
```

you will have two sshd:

 * `host-password:2222`: a password only sshd server (user: `user`, password: `pass`)
 * `host-publickey:2222`: a public key only sshd server (put your public key in `/publickey_authorized_keys/authorized_keys`)

more settings: <https://github.com/linuxserver/docker-openssh-server>

### Make some direct changes to source code

after you have done, attach to testrunner container:

```
docker exec -ti e2e-testrunner-1 bash
```

then run test in `/src/e2e`

```
go test
```

### Send PR with Github

<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request>

## Understanding how sshpiper works

### SSH transport

[`rust/transport`](rust/transport/) owns the SSH packet framing, negotiation,
key exchange, encryption, and rekeying boundary, using unmodified cryptographic
crates. It relays authenticated opaque connection packets rather than translating
channel IDs or terminating application protocols. See the README for supported
algorithms and interoperability commands.

### sshpiperd

[sshpiperd](./rust/daemon/) implements authentication, plugin RPCs, and SSH connection management in Rust.
It accepts ssh connections from `downstream` and routes them to `upstream`.
The plugins are responsible to figure out how to authenticate `downstream` and map it to `upstream`

### plugin

The plugin is typically a grpc server that accepts requests from `sshpiperd`.
The unchanged wire protocol is defined in [plugin.proto](./libplugin/plugin.proto).

In most of the cases, the plugin connects with `sshpiperd` via `stdin/stdout`. The [ioconn](./libplugin/ioconn/) wraps stdin/stdout to net.Conn for grpc use.
`sshpiperd` also supports to create remote grpc connections to a plugin deploy in a different machine.

## Your first plugin

[fixed](./plugin/fixed/) and [simplematch](./plugin/simplematch/) are two good examples of plugins.
They are very simple and just less than 50 lines of code.

Take `fixed` as an example:

```
&libplugin.SshPiperPluginConfig{
    PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
        return &libplugin.Upstream{
            Host:          host,
            Port:          int32(port),
            IgnoreHostKey: true,
            Auth:          libplugin.CreatePasswordAuth(password),
        }, nil
    },
}
```

Here means the `downstream` is sending password to `sshpiperd`. Then `sshpiperd` will call plugin's `PasswordCallback` to get the `upstream` to connect to.
The `upstream` object contains host port and auth info about how to connect to the `upstream`. you can also return an error to deny the connection.

### build and run the plugin

simple build it with:

```
go build -tags full
```

you will get the executable in the current directory. say `myplugin`. start it with:

```
sshpiperd /path/to/myplugin
```
