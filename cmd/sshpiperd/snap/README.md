# Snap for sshpiperd

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/sshpiperd)

## Install

```
sudo snap install sshpiperd
```

## Config

```
sudo snap set sshpiperd <config>=<value>
sudo snap restart sshpiperd
```

### sshpiperd 

 * `sshpiperd.plugins` space separated list of plugins, allowed values: `workingdir`, `fixed`, `yaml` `failtoban`,
 * `sshpiperd.address` listening address
 * `sshpiperd.port` listening port
 * `sshpiperd.server-key` server key files, support wildcard
 * `sshpiperd.server-key-data` server key in base64 format, server-key, server-key-generate-mode will be ignored if set
 * `sshpiperd.server-key-generate-mode` server key generate mode, one of: disable, notexist, always. generated key will be written to `server-key` if  * no`texist or always
 * `sshpiperd.login-grace-time` sshpiperd forcely close the connection after this time if the pipe has not successfully established
 * `sshpiperd.log-level` log level, one of: trace, debug, info, warn, error, fatal, panic
 * `sshpiperd.typescript-log-dir` create typescript format screen recording and save into the directory see https://linux.die.net/man/1/script
 * `sshpiperd.banner-text` display a banner before authentication, would be ignored if banner file was set
 * `sshpiperd.banner-file` display a banner from file before authentication
 * `sshpiperd.drop-hostkeys-message` filter out hostkeys-00@openssh.com which cause client side warnings

### workingdir plugin

 * `workingdir.root path` to root working directory
 * `workingdir.allow-baduser-name` allow bad username
 * `workingdir.no-check-perm` disable 0400 checking
 * `workingdir.strict-hostkey` upstream host public key must be in known_hosts file, otherwise drop the connection
 * `workingdir.no-password-auth` disable password authentication and only use public key authentication

### yaml plugin

 * `yaml.config` path to yaml config file
 * `yaml.no-check-perm` disable 0400 checking

### fixed plugin

 * `fixed.target` target ssh endpoint address

### failtoban plugin

 * `failtoban.max-failures` max failures
 * `failtoban.ban-duration` ban duration

