# Revtunnel Plugin — Local Demo

This compose file starts sshpiperd with the revtunnel plugin and a target
OpenSSH server (user: `user`, password: `pass`).

## Start

```bash
cd examples/revtunnel
docker compose up
```

Wait until you see `sshpiperd is listening on [::]:2222`.

## Step 1 — Register a tunnel

In a **new terminal**, register using your existing SSH key.
The SSH username you connect with becomes the **target username** for the upstream:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -R 0:target:2222 \
    -p 2222 user@127.0.0.1
```

You'll see output like:

```
a1b2c3d4-e5f6-7890-abcd-ef1234567890

# add to target's authorized_keys:
echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys

# connect with (use the same key you registered with, or the CONNECTOR_PUBKEY key):
ssh -i <your-key> a1b2c3d4-e5f6-7890-abcd-ef1234567890@localhost -p 2222  # -> user@target:2222

# press Ctrl+C to stop forwarding
```

By default the connector key is the **same SSH key you registered with**, so no
extra key file is produced. Keep this terminal open — the tunnel stays alive as
long as the connection is active.

## Step 2 — Install the upstream key on the target

Copy the `echo '...' >> ~/.ssh/authorized_keys` line and run it on the target.
In this demo the target uses the `linuxserver/openssh-server` image, whose
`user` home is `/config`, so its authorized_keys lives at
`/config/.ssh/authorized_keys`:

```bash
docker compose exec target sh -c 'mkdir -p /config/.ssh && echo "ssh-ed25519 AAAA..." >> /config/.ssh/authorized_keys'
```

## Step 3 — Connect through the tunnel

Use the same SSH key you registered with in Step 1:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -i ~/.ssh/id_ed25519 \
    -p 2222 <GUID>@127.0.0.1
```

You're now connected to the target container via the reverse tunnel! 🎉

To grant access without sharing your own key, re-register with
`CONNECTOR_PUBKEY` set (see `plugin/revtunnel/README.md`) and connect with the
matching private key instead.

## Password auth (no key install needed)

The `target-password` service is reached with the target's **password** instead
of a key. Enable it per tunnel by sending `ALLOWPASSWORD=1` during registration:

```bash
ALLOWPASSWORD=1 ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o SendEnv=ALLOWPASSWORD \
    -R 0:target-password:2222 \
    -p 2222 user@127.0.0.1
```

The printed block now includes a password-connect hint. Connect with the
GUID and enter the target password (`pass`) when prompted — no
`authorized_keys` entry is required on `target-password`:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 2222 <GUID>@127.0.0.1
# password: pass
```

sshpiperd forwards the password straight through to the upstream target.

## Teardown

```bash
docker compose down -v
```
