# Contributing

Thank you for your interest in contributing to sshpiper.
Make sure you have read [README.md](README.md) before starting.

## Getting Started

### Software Requirements
 * Go <https://go.dev/>
 * Docker <https://www.docker.com/>
 * Docker Compose <https://docs.docker.com/compose/install/>
 * Git <https://git-scm.com/>

### Get the code

```
git clone https://github.com/tg123/sshpiper
cd sshpiper
```

> The forked `golang.org/x/crypto` (carrying sshpiper's `PiperConfig`/`PiperConn` API) lives in a separate repo,
> [`tg123/sshpiper.crypto`](https://github.com/tg123/sshpiper.crypto), and is pulled in as a regular Go module
> dependency of `cmd/sshpiperd` via `replace` — no `git submodule` step is needed.
>
> If you want to hack on the fork against your local sshpiper checkout, create a (gitignored) `go.work` at the
> repo root that `use`s both `./cmd/sshpiperd` and your local clone of `sshpiper.crypto`. Do **not** commit
> `go.work`: workspace mode would apply the daemon's `replace golang.org/x/crypto` graph-wide and leak the
> fork into root/plugin module builds.

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

### sshpiper seasoned crypto ssh lib

The forked `crypto/ssh` library (with sshpiper-specific extensions like `PiperConfig`/`PiperConn`) lives in a
separate repository: [`tg123/sshpiper.crypto`](https://github.com/tg123/sshpiper.crypto). It is based on
[crypto/ssh](https://golang.org/pkg/crypto/ssh/) with a drop-in `sshpiper.go` exposing the low-level APIs
sshpiper needs. It is consumed only by the `cmd/sshpiperd` Go module (via a `replace` directive pinned to a
versioned tag of the fork), so plugins and libs in this repo always build against upstream
`golang.org/x/crypto`.

### sshpiperd

[sshpiperd](./cmd/sshpiperd/) is the daemon wraps the `crypto/ssh` library to provide ssh connections management.
It accepts ssh connections from `downstream` and routes them to `upstream`.
The plugins are responsible to figure out how to authenticate `downstream` and map it to `upstream`

### plugin

The plugin is typically a grpc server that accepts requests from `sshpiperd`.
The proto defines in [sshpiper.proto](./proto/sshpiper.proto).

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
