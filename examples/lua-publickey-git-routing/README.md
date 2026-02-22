# Lua publickey routing for git clone

This demo routes git SSH traffic to different upstream repos in `sshpiper_on_publickey`.

Start the demo:

```bash
docker compose up
```

Then clone via `sshpiper` into two local folders:

```bash
chmod 600 ./keys/client_key
GIT_SSH_COMMAND='ssh -i ./keys/client_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222' \
  git clone ssh://repo-a@127.0.0.1:2222/home/git/repo.git ./clone-repo-a

GIT_SSH_COMMAND='ssh -i ./keys/client_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222' \
  git clone ssh://repo-b@127.0.0.1:2222/home/git/repo.git ./clone-repo-b
```

You should see different `README.md` content in `clone-repo-a` and `clone-repo-b`.
