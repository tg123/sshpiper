# fail to ban for sshpiperd

put ip to jail for a while after failed to login for several times.

## Usage

put this plugin after other plugins, like:

```
sshpiperd <main plugin> -- failtoban
```


## Configuration

 * `--max-failures` (`SSHPIPERD_FAILTOBAN_MAX_FAILURES`): max failures before ban, default 5
 * `--ban-duration` (`SSHPIPERD_FAILTOBAN_BAN_DURATION`): ban duration, default 1h. The window starts with the first failure of an ip.
 * `--log-only` (`SSHPIPERD_FAILTOBAN_LOG_ONLY`): only log failures, never ban, useful for working with other tools like fail2ban
 * `--ignore-ip` (`SSHPIPERD_FAILTOBAN_IGNORE_IP`): ips or CIDRs that are never banned. Invalid entries make the plugin fail to start.
 * `--deny-ip` (`SSHPIPERD_FAILTOBAN_DENY_IP`): ips or CIDRs (IPv4 and IPv6) that are always rejected, see [Permanent deny list](#permanent-deny-list).
 * `--store` (`SSHPIPERD_FAILTOBAN_STORE`): `memory` (default, per instance) or `redis` (shared between instances, see below)

Send `SIGHUP` to reset the jail.

Only connections that reach the SSH authentication stage are counted: failed logins and failures to create the pipe afterwards. Plain TCP connections that close before (load balancer or kubelet health checks, port scans) are not counted, so the source ip of health checks does not get banned. Connections rejected by failtoban itself (already banned or permanently denied) are not counted again.

## Permanent deny list

`--deny-ip` rejects ips or CIDRs permanently, IPv4 and IPv6 can be mixed. Repeat the flag or use a comma separated env var:

```
failtoban --deny-ip 203.0.113.0/24 --deny-ip 2001:db8::/32
SSHPIPERD_FAILTOBAN_DENY_IP=203.0.113.7,2001:db8::/32
```

 * The deny list always wins: it is enforced even if the ip also matches `--ignore-ip`, and also in `--log-only` mode.
 * Denied connections are rejected before any store lookup, they are not counted and cause no redis traffic. No shared store is needed, but every instance must get the same list.
 * IPv4-mapped IPv6 entries (e.g. `::ffff:10.0.0.0/104`) are treated as their IPv4 form (`10.0.0.0/8`), the same as `--ignore-ip`.
 * Invalid entries make the plugin fail to start. `0.0.0.0/0` or `::/0` are allowed but logged as a warning, as they reject all IPv4 or IPv6 clients.
 * `SIGHUP` does not change the deny list, restart with new arguments instead.

## Shared jail for multiple instances (opt-in)

With the default `memory` store every sshpiperd instance has its own jail. When running multiple replicas (e.g. in Kubernetes) behind a load balancer, a client gets `max-failures` attempts *per replica*.

With `--store redis` all instances share their failure counters in a Redis protocol compatible server (Redis, Valkey, ...).

| flag | env | description |
|---|---|---|
| `--redis-url` | `SSHPIPERD_FAILTOBAN_REDIS_URL` | e.g. `rediss://redis:6379/0`. `rediss://` (TLS) is required unless `--redis-insecure` is set |
| `--redis-username` | `SSHPIPERD_FAILTOBAN_REDIS_USERNAME` | ACL username |
| `--redis-password-file` | `SSHPIPERD_FAILTOBAN_REDIS_PASSWORD_FILE` | file containing the password (e.g. a mounted Secret) |
| - | `SSHPIPERD_FAILTOBAN_REDIS_PASSWORD` | password, alternative to the password file. There is intentionally no cli flag, as cli args are visible in the process list |
| `--redis-key-prefix` | `SSHPIPERD_FAILTOBAN_REDIS_KEY_PREFIX` | key prefix, default `sshpiper:failtoban:`. Instances with the same prefix share a jail |
| `--redis-tls-ca-file` | `SSHPIPERD_FAILTOBAN_REDIS_TLS_CA_FILE` | CA bundle to verify the server, system roots if not set |
| `--redis-tls-cert-file`, `--redis-tls-key-file` | `SSHPIPERD_FAILTOBAN_REDIS_TLS_CERT_FILE`, `SSHPIPERD_FAILTOBAN_REDIS_TLS_KEY_FILE` | client certificate for mTLS |
| `--redis-tls-server-name` | `SSHPIPERD_FAILTOBAN_REDIS_TLS_SERVER_NAME` | override the name used to verify the server certificate |
| `--redis-insecure` | `SSHPIPERD_FAILTOBAN_REDIS_INSECURE` | allow plaintext `redis://` connections, NOT recommended |
| `--redis-timeout` | `SSHPIPERD_FAILTOBAN_REDIS_TIMEOUT` | timeout of a single redis operation, default 500ms |
| `--store-failure-mode` | `SSHPIPERD_FAILTOBAN_STORE_FAILURE_MODE` | what to do if redis is unavailable, see below |

### Redis requirements

No bootstrapping is needed apart from the ACL user (see below): keys are created on the first failure and expire after `ban-duration`, the Lua script is loaded automatically.

 * Redis 6+ or Valkey (ACL users). `EVAL`/`EVALSHA` must not be disabled or renamed (`rename-command`).
 * TLS enabled on the server (`tls-port`, `tls-cert-file`, `tls-key-file`, `tls-ca-cert-file` for mTLS), unless `--redis-insecure` is used.
 * A single endpoint: standalone or the primary of a replicated setup (e.g. via a Kubernetes Service pointing to the primary). Redis Cluster and Sentinel discovery are not supported.
 * Eviction: with `maxmemory` set, use `maxmemory-policy noeviction` or size memory generously, otherwise counters (and bans) may be evicted early. With `noeviction` a full Redis is handled like an outage (`--store-failure-mode`).
 * Persistence: without RDB/AOF a Redis restart **clears the whole shared jail**, all banned clients can connect again (apart from bans cached locally for up to 5 seconds and failures counted locally during the outage in `local` mode). Enable AOF (e.g. `appendonly yes`) or RDB snapshots if bans must survive a restart. No re-initialization is needed after a restart either way.

### Security notes

 * Server certificates are always verified (TLS 1.2+), there is no option to skip verification.
 * Use a dedicated ACL user that can only access the jail keys:

   ```
   ACL SETUSER sshpiper on >CHANGE_ME resetkeys ~sshpiper:failtoban:* resetchannels -@all +hello +ping +get +incr +pttl +pexpire +eval +evalsha +scan +unlink
   ```

 * Anyone with write access to the keys can ban or unban arbitrary ips, protect the redis instance accordingly (e.g. a Kubernetes NetworkPolicy allowing only sshpiperd pods).
 * The plugin only stores `<prefix>fail:<ip>` counters with an expiry of `ban-duration`, no usernames or other data.

### When redis is unavailable

 * `--store-failure-mode local` (default): fall back to per instance counters until redis is reachable again. Bans that were collected locally stay in effect. Logins keep working, brute force protection is reduced to the per instance level.
 * `--store-failure-mode deny`: reject all new connections while redis is unavailable, and fail to start if redis is not reachable at startup.

### SIGHUP

`SIGHUP` on any instance clears the **shared** jail for all instances. Other instances may keep a ban they have seen within the last 5 seconds.

### Kubernetes example

```yaml
env:
  - name: SSHPIPERD_FAILTOBAN_STORE
    value: redis
  - name: SSHPIPERD_FAILTOBAN_REDIS_URL
    value: rediss://redis.sshpiper.svc:6379/0
  - name: SSHPIPERD_FAILTOBAN_REDIS_USERNAME
    value: sshpiper
  - name: SSHPIPERD_FAILTOBAN_REDIS_PASSWORD_FILE
    value: /var/run/secrets/failtoban/password
  - name: SSHPIPERD_FAILTOBAN_REDIS_TLS_CA_FILE
    value: /var/run/secrets/failtoban/ca.crt
volumeMounts:
  - name: failtoban-redis
    mountPath: /var/run/secrets/failtoban
    readOnly: true
```

### Limitations

 * IPv6 clients controlling a whole prefix (e.g. a /64) can rotate addresses, every address is counted separately.
