# Username routing demo

Start the demo:

```bash
docker compose up
```

In another terminal, connect through `sshpiper`:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 sshd:2222+demo@127.0.0.1
```

Password is `pass`.

`username-router` parses `target+username`, so this routes to host `sshd` on port `2222` and logs in as user `demo` on the upstream sshd.
