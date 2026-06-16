# revtunnel plugin for sshpiperd

Register an ssh reverse tunnel with `ssh -R` and let anyone holding the
returned GUID + private key connect through sshpiperd back to a host that
is only reachable from the registrar.

## How it works

1. **Register.** The registrar runs:
   ```
   ssh -R 0:<host>:<port> <username>@sshpiperd
   ```
   `<host>:<port>` is reachable from the registrar (typically the
   registrar's own sshd, e.g. `localhost:22`). `<username>` is the unix
   account that connectors will land on at the target host.

   The plugin terminates an embedded ssh server, accepts the
   `tcpip-forward` global request, generates a fresh GUID and ed25519
   keypair, and prints them to the registrar's session:

   ```
   # revtunnel registration
   GUID=<uuid>
   BIND=<addr>:<port>
   TARGET_USER=<username>
   PUBLIC_KEY=ssh-ed25519 AAAA...
   -----BEGIN REVTUNNEL PRIVATE KEY-----
   -----BEGIN OPENSSH PRIVATE KEY-----
   ...
   -----END OPENSSH PRIVATE KEY-----
   -----END REVTUNNEL PRIVATE KEY-----
   ```

   The registrar copies `PUBLIC_KEY` into `~/.ssh/authorized_keys` on the
   target host (`<username>@<host>:<port>`), and keeps the ssh session
   open — closing it tears down the tunnel.

2. **Connect.** Anyone with the GUID + private key runs:
   ```
   ssh -i id_revtunnel <guid>@sshpiperd
   ```
   sshpiperd verifies the pubkey against the stored one for that GUID,
   then opens a `forwarded-tcpip` channel on the registrar's connection.
   Inside that channel the daemon performs a regular ssh handshake to
   `<host>:<port>` (the target the registrar selected) as `<username>`
   using the same ed25519 key.

## Usage

```
sshpiperd revtunnel [--session-store <spec>] [--host-key <path>]
```

Flags:

| flag | default | description |
| ---- | ------- | ----------- |
| `--session-store` (`SSHPIPERD_REVTUNNEL_SESSION_STORE`) | `memory://` | `memory://` (default, lost on restart) or `file://<dir>` (one JSON file per GUID, atomic). |
| `--host-key` (`SSHPIPERD_REVTUNNEL_HOST_KEY`) | _auto-generated ed25519, in memory_ | Path to an OpenSSH-format ed25519 private key used as the host key of the embedded register-side ssh server. Auto-generated and persisted if the path does not exist. |

## Behaviour & limits

- **Register-side auth is `none`.** Any username works; access control is
  enforced on the connect side via the issued ed25519 key.
- **Connect-side auth is publickey only.** The username must be the GUID.
- **Idle timeout: 2 hours.** Records whose last byte of traffic (or
  registration handshake) is older than 2h are evicted; the registrar's
  ssh connection is dropped. Not configurable in this release.
- **Tunnel lifetime.** A tunnel disappears the moment the registrar's ssh
  session ends; the GUID + keys may still be stored on disk (with
  `file://`) but new connect attempts are refused until the same registrar
  re-registers. v1 does not support re-binding to an existing GUID — each
  registration produces a fresh GUID.
- **Allocated bind port.** When the registrar uses `ssh -R 0:...`, the
  plugin synthesises a pseudo-port for the RFC 4254 §7.1 reply (no real
  socket is opened). The `BIND=` line in the registration output reflects
  that allocated port.
