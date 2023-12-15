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
sudo ./out/sshpiperd ./out/fixed --target 127.0.0.1:5522
```

### test ssh connection (password: `pass`)

```
ssh 127.0.0.1 -l user -p 2222
```

### ➕ math before login? 

Here illustrates the example of `addional challenge` before the `fixed` plugin.

```
sudo ./out/sshpiperd --log-level=trace ./out/simplemath -- ./out/fixed --target 127.0.0.1:5522
```

### Pubkey auth for upstream

Add the ssh_host_ed25519_key.pub into authorized_keys. Test it with:

    ssh -i ./ssh_host_ed25519_key -o IdentitiesOnly=yes root@192.168.1.1 -p 2222

Now the sshpiperd will be able to connect without asking for a password.


## Plugins

### Routing plugins

* [Fixed](plugin/fixed/): fixed targeting the sshd server
* [Working Dir](plugin/workingdir/): `/home`-like directory to managed upstreams routing by sshpiped.
* [Working Dir By Key](plugin/workingdirbykey/): same as `workingdir` but uses public key to route.
* [YAML](plugin/yaml/): config routing with a single yaml file.
* [RESTful](https://github.com/11notes/docker-sshpiper): Call the RESTful backend for authentication, challenge and routing.
* [Docker](plugin/docker/): pipe into docker containers.
* [Kubernetes](plugin/kubernetes/): manage pipes via Kubernetes CRD.
* [GitHub App](https://github.com/tg123/sshpiper-gh): login ssh with your GitHub account

### Additional challenge plugins

* [Simple Math](plugin/simplemath/): ask for very simple math question before login, demo purpose
* [TOTP](plugin/totp/): TOTP 2FA plugin. compatible with all [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238) authenticator e.g. Google Authenticator, Microsoft Authenticator.
* [RESTful](https://github.com/11notes/docker-sshpiper): Call the RESTful backend for authentication, challenge and routing.
* [Fail To Ban](plugin/failtoban/): ban ip after failed login attempts
* [Azure Device Code](plugin/azdevicecode/): ask user to enter [azure device code](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) before login


## Screening recording

`sshpiperd` support recording the screen in `typescript` format (not the lang). The format is compatible with [scriptreplay(1)](https://linux.die.net/man/1/scriptreplay)

To use it, start sshpiperd with `--typescript-log-dir loggingdir` e.g.:

    ssh user_name@127.0.0.1 -p 2222
    ... do some commands
    exit

The ssh session was saved to `.typescript` files:

    $ cd loggingdir/user_name
    $ ls *.timing *.typescript
    1472847798.timing 1472847798.typescript

Then to replay use:

    $ scriptreplay -t 1472847798.timing 1472847798.typescript # will replay the ssh session


## Public key authentication when using sshpiper (Private key remapping)

During SSH public key auth, [RFC 4252 Section 7](http://tools.ietf.org/html/rfc4252#section-7),
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
                      |   sign agian           |     |   server       |
                      |   using PK_Y  +-------------->   check PK_Y   |
                      |                        |     |                |
                      |                        |     |                |
                      +------------------------+     +----------------+
```                      

## Migrating from `v0`

### What's the major change in `v1`
 
 * low level sshpiper api is fully redesigned to support more routing protocols.
 * plugins system totally redesigned to be more flexible and extensible.
   * plugins are now separated from main process and no longer a single big binary, this allows user to write their own plugins without touching `sshpiperd` code.
 * `grpc` is first class now, the plugins are built on top of it

For plugins already in `v1`, you need change params to new params. However, not all plugins are migrated to `v1` yet, they are being migrated gradually. you can still use the old plugins in [`v0` branch](https://github.com/tg123/sshpiper/tree/v0)


## Contributing

see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
MIT
