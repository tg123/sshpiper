# SSH Piper

[![Build Status](https://travis-ci.org/tg123/sshpiper.svg?branch=master)](https://travis-ci.org/tg123/sshpiper)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/tg123/sshpiper?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/tg123/sshpiper)](https://goreportcard.com/report/github.com/tg123/sshpiper)
[![GoDoc](https://godoc.org/github.com/tg123/sshpiper/ssh?status.svg)](https://godoc.org/github.com/tg123/sshpiper/ssh)
![cover.run go](https://cover.run/go/github.com/tg123/sshpiper/sshpiperd.svg)

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

```
go get -u github.com/tg123/sshpiper/sshpiperd
```

with pam module support

```
go get -u -tags pam github.com/tg123/sshpiper/sshpiperd
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

use env `SSHPIPERD_CHALLENGER` to specify which challenger to use

```
docker run -d -p 2222:2222 \
  -e SSHPIPERD_CHALLENGER=pam \
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
OPTIONS
   sshpiperd
       -l, --listen <default: "0.0.0.0">
              Listening Address

       -p, --port <default: "2222">
              Listening Port

       -i, --server-key <default: "/etc/ssh/ssh_host_rsa_key">
              Server key file for SSH Piper

       -u, --upstream-driver <default: "workingdir">
              Upstream provider driver

       -c, --challenger-driver <default: $SSHPIPERD_CHALLENGER>
              Additional challenger name, e.g. pam, empty for no additional challenge

       --auditor-driver <default: $SSHPIPERD_AUDITOR>
              Auditor for ssh connections piped by SSH Piper

       --log <default: $SSHPIPERD_LOG_PATH>
              Logfile path. Leave empty or any error occurs will fall back to stdout

       --config <default: "/etc/sshpiperd.ini">
              Config file path. Higher priority than arg options and environment variables

   upstream.workingdir
       --workingdir <default: "/var/sshpiper">
              Path to workingdir

       --workingdir-allowbadusername <default: $SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME>
              Disable username check while search the working dir

       --workingdir-nocheckperm <default: $SSHPIPERD_WORKINGDIR_NOCHECKPERM>
              Disable 0400 checking when using files in the working dir

   challenger.welcometext
       --challenger-welcometext <default: $SSHPIPERD_CHALLENGER_WELCOMETEXT>
              Show a welcome text when connect to sshpiper server

   auditor.typescript-logger
       --auditor-typescriptlogger-outputdir <default: "/var/sshpiper">
              Place where logged typescript files were saved
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
