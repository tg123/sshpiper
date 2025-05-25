# username-router plugin for sshpiper

Supports routing based on username. This plugin allows you to route connections to different targets based on the username provided during the SSH connection.
The username format is `target+username`, where `target` is the target host and `username` is the username to use for that target.
`target` can be an IP address or a hostname, and it can also include a port number in the format `target:port`.

## Usage

```
sshpiperd username-router
```