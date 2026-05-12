# Web admin console demo

Spins up an upstream sshd, `sshpiperd` with its admin gRPC API enabled,
`sshpiperd-webadmin` aggregating it into a browser dashboard, and
`sshpiperd-admin serve` exposing the same admin API over SSH for shell/CLI
use.

Start the demo:

```bash
docker compose up
```

Open the admin console at <http://127.0.0.1:8080>.

In another terminal, connect a session through `sshpiper`:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 demo@127.0.0.1
```

Password is `pass`. The session will appear in the admin console's
**Live sessions** table; click **view** to watch its terminal output live, or
**kill** to terminate it.

## CLI access (`sshpiperd-admin`)

The `admin` service runs `sshpiperd-admin serve` on port `2223`. SSH into it
to run admin subcommands (`list`, `kill`, `stream`) against the same
`sshpiper:8222` admin gRPC endpoint.

For the demo it's started with `--no-auth` so any ssh client is accepted; in
production pass `--authorized-keys` instead.

```bash
# list active sessions
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2223 admin@127.0.0.1 list

# stream a live session (raw bytes, Ctrl-C to stop)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2223 admin@127.0.0.1 stream <session-id>

# kill a session
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2223 admin@127.0.0.1 kill <session-id>

# or open an interactive shell with the same commands available
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2223 admin@127.0.0.1
```

## How it works

- `sshpiper` runs the [`fixed`](../../plugin/fixed) plugin to route every
  connection to the demo `sshd`. It exposes the admin gRPC API on port `8222`
  inside the compose network via `--admin-grpc-port=8222`. For this local
  demo the admin API uses plaintext gRPC (`--admin-grpc-insecure`); production
  deployments should provide `--admin-grpc-tls-cert`/`--admin-grpc-tls-key`
  (and ideally `--admin-grpc-tls-cacert` for mTLS).
- `webadmin` runs `sshpiperd-webadmin` (built into the same image) and connects
  to `sshpiper:8222` over plaintext gRPC (`SSHPIPERD_WEBADMIN_INSECURE=true`).
  It serves an HTML/JS dashboard on port `8080`.
- `admin` runs `sshpiperd-admin serve` (built into the same image) and
  exposes the admin API over SSH on port `2223`. Each session's exec or
  shell request is dispatched to the same `list` / `kill` / `stream`
  subcommands, talking to `sshpiper:8222` (`SSHPIPERD_ADMIN_ENDPOINTS`).

For multi-instance deployments, set
`SSHPIPERD_WEBADMIN_ENDPOINTS=host1:8222,host2:8222,...` (or
`SSHPIPERD_ADMIN_ENDPOINTS=...` for the CLI).
