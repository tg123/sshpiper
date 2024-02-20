# Working Directory plugin for sshpiperd

`Working Dir` is a `/home`-like directory. 
sshpiperd read files from `workingdir/[username]/` to know upstream's configuration.

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
sshpiper reads `workingdir/github/sshpiper_upstream` and then connects to the upstream. 

## Usage

```
sshpiperd workingdir --root /var/sshpiper
```

### options (allow supported read from environments)

```
--allow-baduser-name  allow bad username (default: false) [$SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME]
--no-check-perm       disable 0400 checking (default: false) [$SSHPIPERD_WORKINGDIR_NOCHECKPERM]
--no-password-auth    disable password authentication and only use public key authentication (default: false) [$SSHPIPERD_WORKINGDIR_NOPASSWORD_AUTH]
--root value          path to root working directory (default: "/var/sshpiper") [$SSHPIPERD_WORKINGDIR_ROOT]
--strict-hostkey      upstream host public key must be in known_hosts file, otherwise drop the connection (default: false) [$SSHPIPERD_WORKINGDIR_STRICTHOSTKEY]
```

## User files

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
  
   OpenSSH format `authorized_keys` (see `~/.ssh/authorized_keys`). `downstream`'s public key must be in this file to get verified in order to use `id_rsa` to login to `upstream`. 

 * id_rsa
 
   RSA key for upstream.
   
 * known_hosts
 
   when `--strict-hostkey` is set, upstream server's public key must present in known_hosts
   
## FAQ
 * Q: why sshpiperd still asks for password even I disabled password auth in upstream (different behavior from `v0`)
   
   A: you may want `--no-password-auth`, see <https://github.com/tg123/sshpiper/issues/97>

