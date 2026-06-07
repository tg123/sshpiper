# Honeypot on wrong password

This demo shows how to redirect failed password logins to an SSH honeypot
([`cowrie`](https://github.com/cowrie/cowrie)) instead of letting them reach
the real sshd.

The routing logic lives in [`lua/routing.lua`](./lua/routing.lua):

- If the user logs in as `demo` with password `pass`, `sshpiper` forwards the
  connection to the real `sshd` upstream.
- For any other username or password, `sshpiper` silently routes the
  connection to the `cowrie` honeypot, which accepts the login and drops the
  attacker into a fake shell.

⚠️ Demo only: the valid password is hardcoded in `lua/routing.lua`. Do not
hardcode credentials in production.

Start the demo:

```bash
docker compose up
```

In another terminal, log in with the **correct** password and you reach the
real sshd:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 demo@127.0.0.1
# password: pass
```

Now try a **wrong** password (or any other username) and you are silently
redirected to the honeypot:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 demo@127.0.0.1
# password: anything-else
```

The session that lands in the honeypot looks like a normal Linux shell, but
cowrie records the commands and simulates shell responses rather than
executing them for real.
