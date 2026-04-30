# Web admin console demo

Spins up an upstream sshd, `sshpiperd` with its admin gRPC API enabled, and
`sshpiperd-webadmin` aggregating it into a browser dashboard.

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

For multi-instance deployments, set
`SSHPIPERD_WEBADMIN_ENDPOINTS=host1:8222,host2:8222,...`.
