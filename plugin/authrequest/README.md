# authrequest plugin for sshpiperd

This plugin performs an HTTP subrequest compatible with Nginx's `auth_request` module. It calls the configured `path` (default `/auth`) on the provided base `url` using HTTP Basic Auth derived from the SSH username and password. Any 2xx status is treated as success and the connection continues to the next plugin in the chain.

## Usage

```
sshpiperd authrequest --url https://auth.example.com --path /auth
```

### Options

- `--url` (`$SSHPIPERD_AUTHREQUEST_URL`, required): Base URL of the auth server.
- `--path` (`$SSHPIPERD_AUTHREQUEST_PATH`, default `/auth`): Path appended to the base URL for the auth check.
- `--timeout` (`$SSHPIPERD_AUTHREQUEST_TIMEOUT`, default `5s`): HTTP request timeout.
