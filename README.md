# SSH Piper

[![Build Status](https://travis-ci.org/tg123/sshpiper.svg?branch=master)](https://travis-ci.org/tg123/sshpiper)
[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/tg123/sshpiper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

SSh Piper works as a proxy-like ware, and route connections by `username`, `src ip` , etc.

```
+---------+                      +------------------+          +-----------------+
|         |                      |                  |          |                 |
|   Bob   +----ssh -l bob----+   |   SSH Piper   +------------->   Bob' machine  |
|         |                  |   |               |  |          |                 |
+---------+                  |   |               |  |          +-----------------+
                             +---> pipe-by-name--+  |                             
+---------+                  |   |               |  |          +-----------------+
|         |                  |   |               |  |          |                 |
|  Alice  +----ssh -l alice--+   |               +------------->  Alice' machine |
|         |                      |                  |          |                 |
+---------+                      +------------------+          +-----------------+


 Downstream                         SSH Piper                       Upstream                     

```

## Install 

```
go get github.com/tg123/sshpiper/sshpiperd
go install github.com/tg123/sshpiper/sshpiperd
```

with pam module support

```
go get -tags pam github.com/tg123/sshpiper/sshpiperd
go install -tags pam github.com/tg123/sshpiper/sshpiperd
```

## [Docker image](https://registry.hub.docker.com/u/farmer1992/sshpiperd/)

Pull

```
docker pull farmer1992/sshpiperd
```

Run  [:question: what is WORKING_DIR](#files-inside-working-dir) 

```
docker run -d -p 2222:2222 \
  -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key \
  -v /YOUR_WORKING_DIR:/var/sshpiper \
  farmer1992/sshpiperd
```

Run with [Additional Challenge](#additional-challenge)

use env `CHALLENGER` to specify which challenger to use

```
docker run -d -p 2222:2222 \
  -e CHALLENGER=pam \
  -v /YOUR_PAM_CONFIG:/etc/pam.d/sshpiperd \
  -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key \
  -v /YOUR_WORKING_DIR:/var/sshpiper \
  farmer1992/sshpiperd
```

## Quick start

Just run `showme.sh` in [sshpiperd exmaple directory](sshpiperd/example)
```
$GOPATH/src/github.com/tg123/sshpiper/sshpiperd/example/showme.sh
```

the example script will setup a sshpiper server using
```
ssh 127.0.0.1 -p 2222 -l github # connect to github.com:22
ssh 127.0.0.1 -p 2222 -l linode # connect to lish-atlanta.linode.com:22
```

connect to linode 

```
$ ssh 127.0.0.1 -p 2222 -l linode.com:22
linode@127.0.0.1's password:
```


connect to github.com:22

```
$ ssh 127.0.0.1 -p 2222 -l github
Permission denied (publickey).
```


## Configuration 

```
$ sshpiperd -h
  -c="": Additional challenger name, e.g. pam, emtpy for no additional challenge
  -h=false: Print help and exit
  -i="/etc/ssh/ssh_host_rsa_key": Key file for SSH Piper
  -l="0.0.0.0": Listening Address
  -p=2222: Listening Port
  -w="/var/sshpiper": Working Dir
```

### Files inside `Working Dir`

`Working Dir` is a `/home`-like directory. 
SSHPiperd read files from `workingdir/[username]/` to know upstream's configuration.

e.g.

```
workingdir tree

.
├── github
│   └── sshpiper_upstream
└── linode
    └── sshpiper_upstream
```

when `ssh sshpiper_host -l github`, 
sshpiper reads `workingdir/github/sshpiper_upstream` and the connect to the upstream. 

#### User files

*These file MUST NOT be accessible to group or other. (chmod og-rwx filename)*

 * sshpiper_upstream
 
   one line file `upstream_host:port` e.g. `github.com:22`

 * authorized_keys
  
   OpenSSH format `authorized_keys` (see `~/.ssh/authorized_keys`). Used for `publickey sign again(see below)`.

 * id_rsa
 
   RSA key for `publickey sign again(see below)`.


#### Publickey sign again

During SSH publickey auth, [RFC 4252 Section 7](http://tools.ietf.org/html/rfc4252#section-7),
ssh client sign `session_id` and some other data using private key into a signature `sig`.
This is for server to verify that the connection is from the client not `the man in the middle`.

However, sshpiper actually holds two ssh connection, and it is doing what `the man in the middle` does.
the two ssh connections' `session_id` will never be the same, because they are hash of the shared secret. [RFC 4253 Section 7.2](http://tools.ietf.org/html/rfc4253#section-7).


To support publickey auth, sshpiper will modify the `sig` using a private key (`id_rsa`) in the `workingdir/[username]/`.

How this work

```
+------------+        +------------------------+                       
|            |        |                        |                       
|   client   |        |   SSH Piper            |                       
|   PK_X     +-------->      |                 |                       
|            |        |      v                 |                       
|            |        |   Check PK_X           |                       
+------------+        |   in authorized_keys   |                       
                      |      |                 |                       
                      |      |                 |     +----------------+
                      |      v                 |     |                |
                      |   sign agian           |     |   server       |
                      |   using PK_Y  +-------------->   check PK_Y   |
                      |                        |     |                |
                      |                        |     |                |
                      +------------------------+     +----------------+
```

e.g.

on client 

```
ssh-copy-id -i PK_X test@sshpiper
```

on ssh piper server

```
ln -s ~test/.ssh/authorized_keys workingdir/test/authorized_keys
ssh-keygen -N '' -f workingdir/test/id_rsa  # this is PK_Y
ssh-copy-id -i workingdir/test/id_rsa test@server
```

now `ssh test@sshpiper -i -i PK_X`, sshpiper will send `PK_Y` to server instead of `PK_X`.


### Additional Challenge

ssh piper allows you run your own challenge before dialing to the upstream.
if a client failed in this challenge, connection will be closed.
however, the client has to pass the upstream server's auth in order to establish the whole connection.
`Additional Challenge` is required, but not enough.


This is useful when you want use publickey and something like [google-authenticator](https://github.com/google/google-authenticator) together. OpenSSH do not support use publickey and other auth together.


#### Available Challengers

 * pam
   
   [Linux-PAM](http://www.linux-pam.org/) challenger
   
   this module use the pam service called `sshpiperd`

   you can configure the rule at `/etc/pam.d/sshpiperd`


## API @ [![GoDoc](https://godoc.org/github.com/tg123/sshpiper?status.svg)](https://godoc.org/github.com/tg123/sshpiper/ssh#SSHPiperConfig)

Package ssh in sshpiper is compatible with[golang.org/x/crypto/ssh](http://golang.org/x/crypto/ssh). 
All func and datatype left unchanged. You can use it like [golang.org/x/crypto/ssh](http://golang.org/x/crypto/ssh).

SSHPiper additional API

 * [NewSSHPiperConn](https://godoc.org/github.com/tg123/sshpiper/ssh#NewSSHPiperConn)
 * [SSHPiperConfig](https://godoc.org/github.com/tg123/sshpiper/ssh#SSHPiperConfig)


## TODO List
 
 * deb package
 * live upgrade
 * more unit test for sshpiperd
 * man page
 * hostbased auth support
 * ssh-copy-id support or tools
 * challenger: menu challenger
 * sshpiperd: user@subhost@host support
