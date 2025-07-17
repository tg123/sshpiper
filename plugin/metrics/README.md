# metrics plugin for sshpiperd

The metrics plugin provides a server to report metrics on active pipes and connection failures.
By default, only the sshpiper_pipe_open_connections{remote_addr="...",user="..."} metric is collected.

## Metrics

Name                            | Type    | Labels                    | Description
------------------------------- | ------- | ------------------------- | ------------
sshpiper_pipe_open_connections  | Gauge   | remote_addr, user         | Incremented each time a pipe is successfully started, decremented on close
sshpiper_pipe_create_errors     | Counter | remote_addr               | Incremented each time a pipe fails to be created (disabled by default)
sshpiper_upstream_auth_failures | Counter | remote_addr, user, method | Incremented each time an upstream rejects the authentication method (disabled by default)

## Usage

Note: this is a metrics server plugin. 📈 you must use it with other routing/auth plugins.

```
sshpiperd other-plugin --other-option -- metrics --port <metrics-port>
```

Start the plugin with --collect-pipe-create-errors to enable sshpiper_pipe_create_errors
Start the plugin with --collect-upstream-auth-failures to enable sshpiper_upstream_auth_failures
