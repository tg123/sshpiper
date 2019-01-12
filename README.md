# SSH Piper

[![Build Status](https://farmer1992.visualstudio.com/opensources/_apis/build/status/sshpiper?branchName=master)](https://farmer1992.visualstudio.com/opensources/_build/latest?definitionId=15?branchName=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/tg123/sshpiper)](https://goreportcard.com/report/github.com/tg123/sshpiper)


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

Run with [Workding Dir upstream driver](sshpiperd/upstream/workingdir/README.md)

```
docker run -d -p 2222:2222 \
  -v /etc/ssh/ssh_host_rsa_key:/etc/ssh/ssh_host_rsa_key \
  -v /YOUR_WORKING_DIR:/var/sshpiper \
  farmer1992/sshpiperd
```

Run with [Additional Challenge](#additional-challenge---challenger-driver)

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

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/sshpiperd)

```
sudo snap install sshpiperd
```

configure with snap

```
sudo snap set sshpiperd 'port=3333'

sudo snap restart sshpiperd
```

_NOTE:_ 
 * Default working dir for snap verion is `/var/snap/sshpiperd/common`
 * use classic mode if PAM is not working: `sudo snap install --classic sshpiperd`


## Quick start

Just run `showme.sh` in [sshpiperd example directory](sshpiperd/example)
or 
Copy paste command below to run

```
go get github.com/tg123/sshpiper/sshpiperd && `go env GOPATH`/src/github.com/tg123/sshpiper/sshpiperd/example/showme.sh
```

the example script will setup a sshpiper server using
```
bitbucket -> bitbucket@bitbucket.org:22 # ssh 127.0.0.1 -p 2222 -l bitbucket
github -> github@github.com:22 # ssh 127.0.0.1 -p 2222 -l github
gitlab -> gitlab@gitlab.com:22 # ssh 127.0.0.1 -p 2222 -l gitlab
```

connect to gitlab 

```
$ ssh 127.0.0.1 -p 2222 -l gitlab
Permission denied (publickey).
```


connect to github.com

```
$ ssh 127.0.0.1 -p 2222 -l github
Permission denied (publickey).
```


## Configuration 

sshpiper provides 3 pluginable components to highly customize your piper
 
 * [Upstream Driver](#upstream-Driver---upstream-driver=))
 * [Additional Challenge](#additional-challenge---challenger-driver)
 * [Auditor](#auditor-for-pipes---auditor-driver)

### Upstream Driver (`--upstream-driver=`)

Upstream driver helps sshpiper to find which upstream host to connect and how to connect.

For example, you can change the username when connecting to upstream sshd by config upstream driver

#### [Workding Directory](sshpiperd/upstream/workingdir/README.md)

#### [Database Driver](sshpiperd/upstream/database/README.md)

#### How to do public key authentication when using sshpiper

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

sshpiper allows you to add your own challenge before dialing to the upstream.
if a client failed in this challenge, connection will be closed.
however, the client has to pass the upstream server's auth in order to establish the whole connection.
`Additional Challenge` is required, but not enough.

This is useful when you want use publickey and something like [google-authenticator](https://github.com/google/google-authenticator) together. OpenSSH do not support use publickey and other auth together.


#### Available Challengers

 * pam
   
   [Linux-PAM](http://www.linux-pam.org/) challenger
   
   this module use the pam service called `sshpiperd`

   you can configure the rule at `/etc/pam.d/sshpiperd`

 * azdevcode
 
   support azure ad device grant, more info
   <https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code>
   
   sshpier will ask user to login using webpage
   
   ```
   To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ****** to authenticate.
   ```
   

### Auditor for pipes (`--auditor-driver=`)


#### SSH Session logging (`--auditor-driver=typescript-logger`)

  When `record_typescript` is allowed, each piped connection would be recorded into [typescript](https://en.wikipedia.org/wiki/Script_(Unix)) in working_dir.
  
  The file format is compatible with scriptreplay(1)
  
  Example:
  
  ```
  $ ./sshpiperd daemon --auditor-driver=typescript-logger
  
  ssh user_name@127.0.0.1 -p 2222
  ... do some commands
  exit
  
  
  $ cd workingdir/user_name
  $ ls *.timing *.typescript
  1472847798.timing 1472847798.typescript
  
  $ scriptreplay -t 1472847798.timing 1472847798.typescript # will replay the ssh session
  ```
