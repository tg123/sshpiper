# Docker Compose examples

This folder contains minimal demos for new users to try `sshpiper` with Docker Compose.

- [`username-routing`](./username-routing): route by SSH username to an upstream sshd with the `username-router` plugin.
- [`lua-publickey-git-routing`](./lua-publickey-git-routing): use Lua publickey callback routing to proxy SSH git clone requests to two different upstream git SSH servers.
