# Quickstart demo

The smallest possible `sshpiper` demo: a dummy upstream `sshd` and an
`sshpiperd` in front of it that forwards every connection to the upstream
using the [`fixed`](../../plugin/fixed/) plugin.

## Run

From the repo root:

```bash
make demo
```

…or directly with Docker Compose:

```bash
cd examples/quickstart
docker compose up --build
```

## Connect

In another terminal:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 demo@127.0.0.1
```

Password is `pass`.

`sshpiperd` listens on `127.0.0.1:2222` and forwards the session to the
`sshd` container (`fixed --target sshd:2222`). The upstream `sshd` is
[`linuxserver/openssh-server`](https://hub.docker.com/r/linuxserver/openssh-server)
with user `demo` / password `pass`.

## Tear down

```bash
make demo-down
# or
cd examples/quickstart && docker compose down
```
