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
git submodule update --init --recursive

mkdir out
go build -tags full -o out ./...
```

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

Here illustrates the example of `addional challenge` before the `fixed` plugin.

```
./out/sshpiperd -i /tmp/sshpiperkey --server-key-generate-mode notexist --log-level=trace ./out/simplemath -- ./out/fixed --target 127.0.0.1:5522
```

## Plugins

### icons

 * 🔀: routing plugin
 * 🔒: addtional challenge plugin

Plugin list

 * [workingdir](plugin/workingdir/) 🔀: `/home`-like directory to managed upstreams routing by sshpiped.
 * [yaml](plugin/yaml/) 🔀: config routing with a single yaml file.
 * [docker](plugin/docker/) 🔀: pipe into docker containers.
 * [kubernetes](plugin/kubernetes/) 🔀: manage pipes via Kubernetes CRD.
 * [azdevicecode](https://github.com/tg123/sshpiper-plugins/tree/main/azdevicecode) 🔒: ask user to enter [azure device code](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) before login
 * [fixed](plugin/fixed/) 🔀: fixed targeting the dummy sshd server
 * [simplemath](plugin/simplemath/) 🔒: ask for very simple math question before login, demo purpose
 * [githubapp](https://github.com/tg123/sshpiper-gh) 🔀: login ssh with your github account
 * [restful](https://github.com/11notes/docker-sshpiper) by [@11notes](https://github.com/11notes) 🔀🔒: The rest plugin for sshpiperd is a simple plugin that allows you to use a restful backend for authentication and challenge.
 * [failtoban](plugin/failtoban/) 🔒: ban ip after failed login attempts
 * [openpubkey](https://github.com/tg123/sshpiper-openpubkey)🔀🔒: integrate with [openpubkey](https://github.com/openpubkey/openpubkey)

## Screening recording

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
   * plugins are now sperated from main process and no longer a single big binary, this allow user to write their own plugins without touching `sshpiperd` code.
 * `grpc` is first class now, the plugins are built on top of it

For plugins already in `v1`, you need change params to new params. However, not all plugins are migrated to `v1` yet, they are being migrated gradually. you can still use the old plugins in [`v0` branch](https://github.com/tg123/sshpiper/tree/v0)


## Contributing

see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
MIT
