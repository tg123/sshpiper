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

# connector private key (save to a file, e.g. id_connector, chmod 400):
-----BEGIN OPENSSH PRIVATE KEY-----
AAAA...
-----END OPENSSH PRIVATE KEY-----

# add to target's authorized_keys:
echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys

# connect with:
ssh -i id_connector a1b2c3d4-e5f6-7890-abcd-ef1234567890@localhost -p 2222  # -> user@target:2222

# press Ctrl+C to stop forwarding
```

Save the connector private key block to a file (e.g. `id_connector`) with `chmod 400`.
Keep this terminal open — the tunnel stays alive as long as the connection is active.

## Step 2 — Install the upstream key on the target

Copy the `echo '...' >> ~/.ssh/authorized_keys` line and run it on the target.
In this demo the target container uses `/publickey_authorized_keys/authorized_keys`:

```bash
docker compose exec target sh -c 'echo "ssh-ed25519 AAAA..." >> /etc/ssh/authorized_keys'
```

## Step 3 — Connect through the tunnel

Use the connector private key printed in Step 1:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -i id_connector \
    -p 2222 <GUID>@127.0.0.1
```

You're now connected to the target container via the reverse tunnel! 🎉

The connector key is independent of your own SSH key — you can safely share
`id_connector` with anyone who should be allowed to connect through this tunnel.

## Teardown

```bash
docker compose down -v
```
