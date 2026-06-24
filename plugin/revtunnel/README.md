# revtunnel plugin for sshpiperd

Register an SSH reverse tunnel with `ssh -R` and let others connect
through sshpiperd using the assigned GUID + a generated connector key.
A fresh ed25519 keypair is issued per tunnel registration: the registrar
receives the private key and can share it with whoever should be allowed
to connect.

## How it works

1. **Register.** The registrar runs:
   ```
   ssh -R 0:<host>:<port> <username>@sshpiper
   ```
   `<host>:<port>` is reachable from the registrar (typically the
   registrar's own sshd, e.g. `localhost:22`). `<username>` becomes the
   SSH user for upstream auth on the target host.

   The plugin authenticates the registrar with their SSH public key,
   accepts the `tcpip-forward` global request, generates a fresh GUID,
   a connector ed25519 keypair (for connect-side auth), and an internal
   upstream ed25519 keypair (for upstream auth to the target), and prints:

   ```
   <guid>

   # connector private key (save to a file, e.g. id_connector, chmod 400):
   -----BEGIN OPENSSH PRIVATE KEY-----
   AAAA...
   -----END OPENSSH PRIVATE KEY-----

   # add to target's authorized_keys:
   echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys

   # connect with:
   ssh -i id_connector <guid>@sshpiper -p 2222  # -> <username>@<host>:<port>

   # press Ctrl+C to stop forwarding
   ```

   The registrar installs the printed upstream public key on the target
   host's `authorized_keys`, saves the connector private key, and keeps
   the SSH session open — closing it tears down the tunnel.

2. **Connect.** Anyone holding the connector private key runs:
   ```
   ssh -i id_connector <guid>@sshpiper
   ```
   sshpiperd verifies the offered public key matches the issued connector
   key stored for that GUID, then opens a `forwarded-tcpip` channel on the
   registrar's connection. Inside that channel the daemon performs SSH
   auth to `<host>:<port>` as `<username>` using the internal upstream key
   (whose public half was installed in step 1).

   The connector key is independent of the registrar's own SSH key — the
   registrar can safely share `id_connector` without exposing their own
   identity.

## Usage

```
sshpiperd revtunnel [--session-store <spec>] [--host-key <path>] [--piper-host <host>] [--piper-port <port>]
```

Flags:

| flag | default | description |
| ---- | ------- | ----------- |
| `--session-store` (`SSHPIPERD_REVTUNNEL_SESSION_STORE`) | `memory://` | `memory://` (default, lost on restart) or `file://<dir>` (one JSON file per GUID, atomic). |
| `--host-key` (`SSHPIPERD_REVTUNNEL_HOST_KEY`) | _auto-generated ed25519_ | Path to an OpenSSH-format ed25519 private key for the embedded register-side SSH server. Auto-generated and persisted if the path does not exist; ephemeral if not set. |
| `--piper-host` (`SSHPIPERD_REVTUNNEL_PIPER_HOST`) | `sshpiper` | Hostname shown in the connect hint after registration. |
| `--piper-port` (`SSHPIPERD_REVTUNNEL_PIPER_PORT`) | `0` | Port shown in the connect hint; 0 or 22 omits the `-p` flag. |

## Behaviour & limits

- **Register-side auth is publickey.** The registrar must have an SSH key
  to authenticate; that key is not used for connect-side verification.
- **Connect-side auth is publickey only.** The username must be the GUID
  and the key must be the connector private key issued during registration.
- **Idle timeout: 2 hours.** Records whose last byte of traffic (or
  registration handshake) is older than 2h are evicted; the registrar's
  SSH connection is dropped. Not configurable in this release.
- **Tunnel lifetime.** A tunnel disappears the moment the registrar's SSH
  session ends; the GUID may still be stored on disk (with `file://`) but
  new connect attempts are refused until the registrar re-registers.
- **Allocated bind port.** When the registrar uses `ssh -R 0:...`, the
  plugin synthesises a pseudo-port for the RFC 4254 §7.1 reply (no real
  socket is opened).
