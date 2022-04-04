# SSH Piper

![Go](https://github.com/tg123/sshpiper/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/tg123/sshpiper)](https://goreportcard.com/report/github.com/tg123/sshpiper)
[![Docker Image](https://img.shields.io/docker/pulls/farmer1992/sshpiperd.svg)](https://hub.docker.com/r/farmer1992/sshpiperd)

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

## Demo

[![asciicast](https://asciinema.org/a/222825.svg)](https://asciinema.org/a/222825)

## Quick start

Just run `showme.sh` in [sshpiperd example directory](sshpiperd/example)
or 
Copy paste command below to run

```
git clone https://github.com/tg123/sshpiper
cd sshpiper/sshpiperd/example/
./showme.sh
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

## Install 

### Build yourself [Go 1.18]

```
git clone 
cd sshpiper/sshpiperd/
go build
```

### with [Docker image](https://registry.hub.docker.com/r/farmer1992/sshpiperd/)

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



## Configuration 

sshpiper provides 3 pluginable components to highly customize your piper
 
 * [Upstream Driver](#upstream-Driver---upstream-driver)
 * [Additional Challenge](#additional-challenge---challenger-driver)
 * [Auditor](#auditor-for-pipes---auditor-driver)

 `sshpiperd daemon -h` to learn more

### Upstream Driver (`--upstream-driver=`)

Upstream driver helps sshpiper to find which upstream host to connect and how to connect.

For example, you can change the username when connecting to upstream sshd by config upstream driver

Available Upstream Drivers

 * [Workding Directory](sshpiperd/upstream/workingdir/README.md)

    Working Dir is a /home-like directory. SSHPiperd read files from workingdir/[username]/ to know upstream's configuration.

 * [Database Driver](sshpiperd/upstream/database/README.md)

   Database upstream driver connected to popular databases, such as mysql, pg or sqlite etc to provide upstream's information.

 * [Kubernetes Driver](sshpiperd/upstream/kubernetes/README.md)

   Kubernetes drive can configure pipe with CRD.

#### How to do public key authentication when using sshpiper

During SSH publickey auth, [RFC 4252 Section 7](http://tools.ietf.org/html/rfc4252#section-7),
ssh client sign `session_id` and some other data using private key into a signature `sig`.
This is for server to verify that the connection is from the client not `the man in the middle`.

However, sshpiper actually holds two ssh connection, and it is doing what `the man in the middle` does.
the two ssh connections' `session_id` will never be the same, because they are hash of the shared secret. [RFC 4253 Section 7.2](http://tools.ietf.org/html/rfc4253#section-7).


To support publickey auth, sshpiper will modify the `sig` using a private key provided by upstream driver.
e.g. (`id_rsa`) in the `workingdir/[username]/`.

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

This is useful when you want use publickey and something like [google-authenticator](https://github.com/google/google-authenticator) together.


#### Available Challengers
 * azdevcode
 
   Support Azure AD device code grant, [More info](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
   
   sshpier will ask user to login using webpage
   
   ```
   To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ****** to authenticate.
   ```
  
  * authy 
  
    Support token and onetouch from <https://authy.com/>
  
#### OpenSSH Native way to do 2FA (No SSHPiper)

in `sshd_config`
```
AuthenticationMethods publickey,keyboard-interactive:pam
```

Enable 2FA PAM, for example, `pam_yubico` or `pam_google_authenticator`.   

### Auditor for pipes (`--auditor-driver=`)

Auditor provides hook for messages transfered by SSH Piper which cloud log messages onto disks or filter some specific message on the fly. 

#### Available Auditor

 * SSH Session logging (`--auditor-driver=typescript-logger`)

    When `record_typescript` is allowed, each piped connection would be recorded into [typescript](https://en.wikipedia.org/wiki/Script_(Unix)) in `--auditor-typescriptlogger-outputdir`.

    The file format is compatible with [scriptreplay(1)](https://linux.die.net/man/1/scriptreplay)

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

## Manage pipes with sshpiper command

SSH Piper comes with tools to list/add/remove pipes.

`sshpiperd pipe -h` to learn more.

## License
MIT
