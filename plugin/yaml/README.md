# yaml plugin for sshpiperd

The yaml plugin for sshpiperd is a simple plugin that allows you to use single yaml file to configure your sshpiperd.

some basic idea of yaml config file:

 * first matched `pipe` will be used.
 * any `from` in `pipe` fits `downstream` authentication will be considered as the `pipe` matched.
 * `username_regex_match` can be used to match with regex

   * to.Username can be template of regex match groups, example: `from.username: "^password_(.*?)_regex$"` and `to.username: $1"`, will match `password_user_regex` to `user`, more sytax see <https://pkg.go.dev/regexp#Regexp.Expand>

 * `authorized_keys`, `known_hosts` are array `path/to/target/file` or single string, but there are also `authorized_keys_data`, `known_hosts_data` accepting base64 inline data, file and data will be merged if both are set
 * `private_key` is `path/to/target/file`, but there are also `private_key_data` accepting base64 inline data, file wins if both are set
 * magic placeholders in path, example usage: `/path/to/$UPSTREAM_USER/file`
    * `DOWNSTREAM_USER`: supported in `private_key`, `known_hosts`
    * `UPSTREAM_USER`: supported in `authorized_keys`, `private_key`, `known_hosts`
    * environment variables: supported in `authorized_keys`, `private_key`, `known_hosts`

## Usage

```
sshpiperd yaml --config /path/to/sshpiperd.yaml
```

### options

```
   --config value   path to yaml config file [$SSHPIPERD_YAML_CONFIG]
   --no-check-perm  disable 0400 checking (default: false) [$SSHPIPERD_YAML_NOCHECKPERM]
```

## Config example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/yaml/schema.json
version: "1.0"
pipes:
- from:
    - username: "password_simple"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
- from:
    - username: "^password_(.*?)_regex$"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "$1"
    ignore_hostkey: true
- from:
    - username: "publickey_simple"
      authorized_keys: 
      - /path/to/publickey_simple/authorized_keys
      - /path/to/publickey_simple/authorized_keys2
  to:
    host: host-publickey:2222
    username: "user"
    private_key: /path/to/host-publickey/id_rsa
    known_hosts_data: 
    - "base64_known_hosts_data"
    - "base64_known_hosts_data2"
- from:
    - username: ".*" # catch all    
      username_regex_match: true
      authorized_keys: /path/to/catch_all/authorized_keys
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: /path/to/host-publickey/id_rsa
```