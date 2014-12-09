# SSH Piper

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

## Run with Docker

```
docker run -d -p 2222:2222 -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key -v /YOUR_WORKING_DIR:/var/sshpiper farmer1992/sshpiperd
```

[what is WORKING_DIR](#files-inside-working-dir)

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
$ ssh 0 -p 2222 -l linode.com:22
linode@0's password:
```


connect to github.com:22

```
$ ssh 0 -p 2222 -l github
Permission denied (publickey).
```


## Configuration 

```
$ sshpiperd -h
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

*These file MUST be in mode 400*

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


## API

sshpiper use a [modified version](ssh) of [golang.org/x/crypto/ssh](http://golang.org/x/crypto/ssh).
[sshpiperd](sshpiperd) now is the font-end of the modified ssh.


## TODO List
 
 * additional challenge (like google authenticator support) before send auth to upstream
 * deb package
 * live upgrade
 * unit test
 * API doc

