# revtunnel plugin for sshpiperd

Register an SSH reverse tunnel with `ssh -R` and let others connect
through sshpiperd using the assigned GUID.

By default the **same SSH key the registrar used to authenticate** is
also the connector key — no extra key management is needed.  Optionally,
the registrar can supply a different connector public key via the
`CONNECTOR_PUBKEY` environment variable (sent with `SendEnv`).

## How it works

1. **Register.** The registrar runs:
   ```
   ssh -R 0:<host>:<port> <username>@sshpiper
   ```
   `<host>:<port>` is reachable from the registrar (typically the
   registrar's own sshd, e.g. `localhost:22`). `<username>` becomes the
   SSH user for upstream auth on the target host.

   The plugin authenticates the registrar with their SSH public key,
   accepts the `tcpip-forward` global request, generates a fresh GUID and
   an internal upstream ed25519 keypair (for upstream auth to the target),
   and prints:

   ```
   <guid>

   # add to target's authorized_keys:
   echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys

   # connect as <username> (use the same key you registered with):
   ssh <guid>@sshpiper

   # press Ctrl+C to stop forwarding
   ```

   The registrar installs the printed upstream public key on the target
   host's `authorized_keys` and keeps the SSH session open — closing it
   tears down the tunnel.

2. **Connect.** The registrar (or anyone they share their key with) runs:
   ```
   ssh <guid>@sshpiper
   ```
   sshpiperd verifies the offered public key matches the connector key
   stored for that GUID (the registrar's own key by default), then opens
   a `forwarded-tcpip` channel on the registrar's connection. Inside that
   channel the daemon performs SSH auth to `<host>:<port>` as `<username>`
   using the internal upstream key (whose public half was installed in
   step 1).

### Supplying a different connector key

If the registrar wants a different public key accepted for the connect
step (e.g. to give a third party access without sharing the registrar's
own key), they can send it via the `CONNECTOR_PUBKEY` environment
variable:

```
CONNECTOR_PUBKEY="ssh-ed25519 AAAA..." \
  ssh -o SendEnv=CONNECTOR_PUBKEY \
      -R 0:<host>:<port> <username>@sshpiper
```

The value must be an `authorized_keys`-format public key
(`ssh-ed25519 AAAA...` etc.).  The connector key takes effect for this
registration only; re-registering resets it to the registrar's own key
unless `CONNECTOR_PUBKEY` is sent again.

### Allowing password auth

By default the connect side is publickey-only. A registrar can instead let
connectors authenticate with the **target's own password** — forwarded
straight through to the upstream, so no key needs to be installed on the
target — by sending `ALLOWPASSWORD` during registration:

```
ALLOWPASSWORD=1 ssh -o SendEnv=ALLOWPASSWORD \
  -R 0:<host>:<port> <username>@sshpiper
# then:
ssh <guid>@sshpiper   # prompts for the target password
```

The value is truthy when empty or one of `1`/`true`/`yes`/`on`. Like
`CONNECTOR_PUBKEY`, it applies to this registration only. Publickey auth
(registrar key or `CONNECTOR_PUBKEY`) continues to work alongside it.

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
  to authenticate.
- **Connect-side auth is publickey by default.** The username must be the
  GUID and the offered key must match the connector key stored for that GUID
  (the registrar's own key by default, or the value of `CONNECTOR_PUBKEY`
  if provided during registration). If the registrar sent `ALLOWPASSWORD`,
  connectors may instead authenticate with the target's password, which is
  forwarded upstream unchanged.
- **Idle timeout: 2 hours.** Records whose last byte of traffic (or
  registration handshake) is older than 2h are evicted; the registrar's
  SSH connection is dropped. Not configurable in this release.
- **Tunnel lifetime.** A tunnel disappears the moment the registrar's SSH
  session ends. On a clean disconnect the persisted record is deleted too
  (even with `file://`), so the GUID is gone; a stale on-disk record only
  lingers after an unclean process kill or a failed delete. Connect attempts
  to a known-but-not-live GUID are refused with an "offline" error until the
  registrar re-registers.
- **Allocated bind port.** When the registrar uses `ssh -R 0:...`, the
  plugin synthesises a pseudo-port for the RFC 4254 §7.1 reply (no real
  socket is opened).
