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
GUID=abc123-...
UPSTREAM_KEY=ssh-ed25519 AAAA...
```

Keep this terminal open — the tunnel stays alive as long as the connection is active.

## Step 2 — Install the upstream key on the target

Copy the `UPSTREAM_KEY` value and add it to the target's authorized_keys.
In this demo the target container uses `/publickey_authorized_keys/authorized_keys`:

```bash
docker compose exec target sh -c 'echo "ssh-ed25519 AAAA..." >> /etc/ssh/authorized_keys'
```

## Step 3 — Connect through the tunnel

Use the same SSH key you used in Step 1:

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -i ~/.ssh/id_ed25519 \
    -p 2222 <GUID>@127.0.0.1
```

You're now connected to the target container via the reverse tunnel! 🎉

## Teardown

```bash
docker compose down -v
```
