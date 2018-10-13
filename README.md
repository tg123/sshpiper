# SSH Piper

[![Build Status](https://travis-ci.org/tg123/sshpiper.svg?branch=master)](https://travis-ci.org/tg123/sshpiper)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/tg123/sshpiper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/tg123/sshpiper)](https://goreportcard.com/report/github.com/tg123/sshpiper)
[![GoDoc](https://godoc.org/github.com/tg123/sshpiper/ssh?status.svg)](https://godoc.org/github.com/tg123/sshpiper/ssh)


sshpiper:  [![Coverage Status](https://coveralls.io/repos/github/tg123/sshpiper.crypto/badge.svg)](https://coveralls.io/github/tg123/sshpiper.crypto)

sshpiperd: [![Coverage Status](https://coveralls.io/repos/github/tg123/sshpiper/badge.svg)](https://coveralls.io/github/tg123/sshpiper)

SSH Piper works as a proxy-like ware, and route connections by `username`, `src ip` , etc.

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

### with Go

```
go get -u github.com/tg123/sshpiper/sshpiperd
```

with pam module support

```
go get -u -tags pam github.com/tg123/sshpiper/sshpiperd
```

### with [Docker image](https://registry.hub.docker.com/u/farmer1992/sshpiperd/)

```
docker run farmer1992/sshpiperd
```

Run  [:question: what is WORKING_DIR](#files-inside-working-dir) 

```
docker run -d -p 2222:2222 \
  -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key \
  -v /YOUR_WORKING_DIR:/var/sshpiper \
  farmer1992/sshpiperd
```
Run with [Additional Challenge](#additional-challenge)

use env `SSHPIPERD_CHALLENGER` to specify which challenger to use

```
docker run -d -p 2222:2222 \
  -e SSHPIPERD_CHALLENGER=pam \
  -v /YOUR_PAM_CONFIG:/etc/pam.d/sshpiperd \
  -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key \
  -v /YOUR_WORKING_DIR:/var/sshpiper \
  farmer1992/sshpiperd
```

### with [Snap](https://snapcraft.io/sshpiperd)
  
```
sudo snap install sshpiperd
```

configure with snap

```
sudo snap set sshpiperd 'port=3333'

sudo snap restart sshpiperd
```

_NOTE:_ Default working dir for snap verion is `/var/snap/sshpiperd/common`


## Quick start

Just run `showme.sh` in [sshpiperd example directory](sshpiperd/example)
```
$GOPATH/src/github.com/tg123/sshpiper/sshpiperd/example/showme.sh
```

the example script will setup a sshpiper server using
```
github@127.0.0.1:2222 -> pipe to github.com:22
linode@127.0.0.1:2222 -> pipe to lish-atlanta.linode.com:22
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

 * sshpiperd manpage | man -l /dev/stdin

```
$ ./sshpiperd -h
Usage:
  sshpiperd [OPTIONS] [command]

SSH Piper works as a proxy-like ware, and route connections by username, src ip , etc. Please see <https://github.com/tg123/sshpiper> for more information

sshpiperd:
  -l, --listen=                             Listening Address (default: 0.0.0.0) [$SSHPIPERD_LISTENADDR]
  -p, --port=                               Listening Port (default: 2222) [$SSHPIPERD_PORT]
  -i, --server-key=                         Server key file for SSH Piper (default: /etc/ssh/ssh_host_rsa_key) [$SSHPIPERD_SERVER_KEY]
  -u, --upstream-driver=                    Upstream provider driver (default: workingdir) [$SSHPIPERD_UPSTREAM_DRIVER]
  -c, --challenger-driver=                  Additional challenger name, e.g. pam, empty for no additional challenge [$SSHPIPERD_CHALLENGER]
      --auditor-driver=                     Auditor for ssh connections piped by SSH Piper  [$SSHPIPERD_AUDITOR]
      --log=                                Logfile path. Leave empty or any error occurs will fall back to stdout [$SSHPIPERD_LOG_PATH]
      --config=                             Config file path. Will be overwriten by arg options and environment variables (default: /etc/sshpiperd.ini) [$SSHPIPERD_CONFIG_FILE]

upstream.mysql:
      --upstream-mysql-host=                mysql host for driver (default: 127.0.0.1) [$SSHPIPERD_UPSTREAM_MYSQL_HOST]
      --upstream-mysql-user=                mysql user for driver (default: root) [$SSHPIPERD_UPSTREAM_MYSQL_USER]
      --upstream-mysql-password=            mysql password for driver [$SSHPIPERD_UPSTREAM_MYSQL_PASSWORD]
      --upstream-mysql-port=                mysql port for driver (default: 3306) [$SSHPIPERD_UPSTREAM_MYSQL_PORT]
      --upstream-mysql-dbname=              mysql dbname for driver (default: sshpiper) [$SSHPIPERD_UPSTREAM_MYSQL_DBNAME]

upstream.workingdir:
      --workingdir=                         Path to workingdir (default: /var/sshpiper) [$SSHPIPERD_WORKINGDIR]
      --workingdir-allowbadusername         Disable username check while search the working dir [$SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME]
      --workingdir-nocheckperm              Disable 0400 checking when using files in the working dir [$SSHPIPERD_WORKINGDIR_NOCHECKPERM]

challenger.welcometext:
      --challenger-welcometext=             Show a welcome text when connect to sshpiper server [$SSHPIPERD_CHALLENGER_WELCOMETEXT]

auditor.typescript-logger:
      --auditor-typescriptlogger-outputdir= Place where logged typescript files were saved (default: /var/sshpiper) [$SSHPIPERD_AUDITOR_TYPESCRIPTLOGGER_OUTPUTDIR]

Help Options:
  -h, --help                                Show this help message

Available commands:
  dumpconfig  dump current config ini to stdout
  genkey      generate a 2048 rsa key to stdout
  manpage     write man page to stdout
  options     list all options
  plugins     list support plugins, e.g. sshpiperd plugis upstream
  version     show version
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

    * line starts with `#` are treated as comment
    * only the first not comment line will be parsed
    * if no port was given, 22 will be used as default
    * if `user@` was defined, username to upstream will be the mapped one

```
# comment
[user@]upstream[:22]
```
    
```
e.g. 

git@github.com

google.com:12345

```

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


### Additional Challenge (`--challenger-driver=`)

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

 * welcometext
 
   Do nothing, but print a welcome text

### SSH Session logging (`--auditor-driver=typescript-logger`)

  When `record_typescript` is allowed, each piped connection would be recorded into [typescript](https://en.wikipedia.org/wiki/Script_(Unix)) in working_dir.
  
  The file format is compatible with scriptreplay(1)
  
  Example:
  
  ```
  $ ./sshpiperd  --auditor-driver=typescript-logger
  
  ssh user_name@127.0.0.1 -p 2222
  ... do some commands
  exit
  
  
  $ cd workingdir/user_name
  $ ls *.timing *.typescript
  1472847798.timing 1472847798.typescript
  
  $ scriptreplay -t 1472847798.timing 1472847798.typescript # will replay the ssh session
  ```

## TODO List
 
 * live upgrade
 * hostbased auth support
 * ssh-copy-id support or tools
 * challenger: menu challenger
 * sshpiperd: user@subhost@host support
