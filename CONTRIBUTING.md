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

rememeber to clone the submodules

```
git clone https://github.com/tg123/sshpiper
cd sshpiper
git submodule update --init --recursive
```

### Start Develop Environment

```
# in e2e folder, run:
SSHPIPERD_DEBUG=1 docker-compose up --force-recreate
```

you will have two sshd:

 * `host-password`: a password only sshd server (user: `user`, password: `pass`)
 * `host-publickey`: a public key only sshd server (put your public key in `/sshconfig_publickey/.config/authorized_keys`)

more settings: <https://github.com/linuxserver/docker-openssh-server>

### Make some direct changes to source code

after you have done, in e2e folder run:

```
go test
```

### Send PR with Github

<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request>

## Understanding how sshpiper works

### sshpiper seasoned cryto ssh lib

The `crypto` folder contains the source code of the [sshpiper seasoned cryto ssh lib](./crypto/).
It based on [crypto/ssh](https://golang.org/pkg/crypto/ssh/) and with a drop-in [sshpiper.go](./crypto/ssh/sshpiper.go) to expose all low level sshpiper required APIs.

### sshpiperd

[sshpiperd](./cmd/sshpiperd/) is the daemon wraps the `crypto/ssh` library to provide ssh connections management.
It accepts ssh connections from `downstream` and routes them to `upstream`.
The plugins are responsible to figure out how to authenticate `downstream` and map it to `upstream`

### plugin

The plugin is typically a grpc server that accepts requrests from `sshpiperd`. 
The proto defines in [sshpiper.proto](./proto/sshpiper.proto).

In most of the cases, the plugin connects with `sshpiperd` via `stdin/stdout`. The [ioconnn](./libplugin/ioconn/) wraps stdin/stdout to net.Conn for grpc use.
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
The `upstream` object contains host port and auth info about how to connect to the `upstream`. you can aslo return an error to deny the connection.

### build and run the plugin

simple build it with:

```
go build
```

you will get the executable in the current directory. say `myplugin`. start it with:

```
sshpiperd /path/to/myplugin
```

