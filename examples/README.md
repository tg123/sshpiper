# Docker Compose examples

This folder contains minimal demos for new users to try `sshpiper` with Docker Compose.

- [`quickstart`](./quickstart): smallest possible demo — `sshpiperd` with the `fixed` plugin in front of a dummy upstream sshd. Run `make demo` from the repo root.
- [`username-routing`](./username-routing): route by SSH username to an upstream sshd with the `username-router` plugin.
- [`lua-publickey-git-routing`](./lua-publickey-git-routing): use Lua publickey callback routing to proxy SSH git clone requests to two different upstream git SSH servers.
- [`honeypot-on-failure`](./honeypot-on-failure): route logins to a real sshd when the password is correct and silently redirect everything else to a [`cowrie`](https://github.com/cowrie/cowrie) SSH honeypot.
- [`webadmin`](./webadmin): browser dashboard (`sshpiperd-webadmin`) for live session viewing and kill, fronting an `sshpiperd` instance with the admin gRPC API enabled.
