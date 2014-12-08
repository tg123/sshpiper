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

```

## Install 

```
go get github.com/tg123/sshpiper/sshpiperd
go install github.com/tg123/sshpiper/sshpiperd
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
$ ssh 0 -p 2222 -l linode.com:22
linode@0's password:
```


connect to github.com:22

```
$ ssh 0 -p 2222 -l github
Permission denied (publickey).
```
