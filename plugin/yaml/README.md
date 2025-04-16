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

### Plugin Options

```
--config value   path to yaml config file [$SSHPIPERD_YAML_CONFIG]
--no-check-perm  disable 0400 checking (default: false) [$SSHPIPERD_YAML_NOCHECKPERM]
```

**NOTE:** If you use this plugin with Docker Compose and a data volume where the ownership is root, you'll need to correct that ownership UID to `1000` to match the container user. Alternatively [run the container user as `root`](https://github.com/tg123/sshpiper/issues/562).

## Config examples

These examples use `ignore_hostkey: true` to skip verifying trust with the upstream server.
- This is insecure, and you are advised to configure `known_hosts` with a filepath listing trusted host keys.
- `known_hosts` may also configure a entry for an upstream offering an _SSH Host Certificate_, but sshpiper itself does not support offering an _SSH Host Certificate_ for downstream clients.
- A valid `known_hosts` config that would work with other SSH clients may not work with sshpiper when the upstream server has multiple host keys offered and your [`known_hosts` file is missing the key type sshpiper attempts to verify with](https://github.com/tg123/sshpiper/issues/554), resulting in the ambiguous failure with error: `Permission denied (publickey)`.

### Password authentication

When no alternative authentication methods are provided (_`from.authorized_keys` or `from.trusted_ca_user_keys`_), `sshpiperd` will prompt the downstream client for a password to authenticate.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/yaml/schema.json
version: "1.0"
pipes:
- from:
    - username: "hello"
  to:
    host: example.com:22
    username: "world"
    ignore_hostkey: true
```

**NOTE:** You cannot set a custom password for `from.username`, nor can you configure a hard-coded password for `sshpiperd` to implicitly provide to the upstream server (_**reference:** Unimplemented [`to.password`](https://github.com/tg123/sshpiper/issues/555)_).

### Regex for dynamic usernames

With `from.username_regex_match: true` you can provide a regex pattern for the `from.username` attribute. The capture group value will be available for `to.username` via `$1`.

For example when the downstream client connects to the sshpiper service for the user `password_world_regex`, this would match the pattern and connect to the upstream `world@example.com`:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/yaml/schema.json
version: "1.0"
pipes:
- from:
    - username: "^password_(.*?)_regex$"
      username_regex_match: true
  to:
    host: example.com:22
    username: "$1"
    ignore_hostkey: true
```

**Tip:** You can use `username: ".*"` to allow any username via a catch-all. Without a capture group this would always connect to the same upstream hard-coded user.

### SSH keys

- **`from.authorized_keys`:** A single file path or a list of file paths in the standard `authorized_keys` format for downstream clients to trust by their public keys.
- **`to.private_key`:** The private key for connecting to your upstream server.

**Caveats:**
- When the upstream server has multiple host keys configured (_typically RSA + ECDSA + Ed25519_), this will affect the host key algorithms offered. sshpiper [will not negotiate a compatible algorithm between the upstream and it's configured `known_hosts`](https://github.com/tg123/sshpiper/issues/554#issuecomment-2765360963), either ensure `known_hosts` has an entry for the first key type offered by the upstream server, or [configure the upstream server to offer your preferred key type](https://github.com/tg123/sshpiper/issues/554#issuecomment-2765446110).
- SSH keys encrypted with a passphrase will have a [degraded UX with multiple prompts for the downstream secret](https://github.com/tg123/sshpiper/issues/559#issuecomment-2798373009). Do not use a passphrase with `to.private_key`.
- SSH user certificates for connecting to upstreams is not supported. Your upstream must trust the public key associated to `to.private_key` (_as with any SSH client lacking user certificate support_).

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/yaml/schema.json
version: "1.0"
pipes:
- from:
    - username: "hello"
      authorized_keys:
      - /path/to/authorized_keys
      - /path/to/authorized_keys2
  to:
    host: example.com:22
    username: "world"
    ignore_hostkey: true
    private_key: /path/to/id_rsa
```

### SSH User Certificates for downstream client auth

Instead of `from.authorized_keys`, if your clients support connecting with provisioned SSH user certificates, sshpiper can verify trust via the CA public key.

- You can still include `from.authorized_keys` to trust other downstream clients connecting only with their SSH keypair.
- The `from.username` must match one of the principals registered for the certificate.
- The connection to the upstream server cannot be via an SSH user certificate however, nor is password auth valid as one will not be prompted for an upstream when `from.trusted_user_ca_keys` is configured.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/yaml/schema.json
version: "1.0"
pipes:
- from:
    - username: "hello"
      trusted_user_ca_keys: /path/to/ca-key-user_ed25519.pub
  to:
    host: example.com:22
    username: "world"
    ignore_hostkey: true
    private_key: /path/to/id_rsa
```

**TIP:** Two full Docker Compose examples demonstrating this feature can be found [here](https://github.com/tg123/sshpiper/issues/559#issuecomment-2798373009).
         
