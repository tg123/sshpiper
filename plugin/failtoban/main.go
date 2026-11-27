//go:build full || e2e

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go4.org/netipx"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

const (
	storeMemory = "memory"
	storeRedis  = "redis"

	redisPasswordEnv = "SSHPIPERD_FAILTOBAN_REDIS_PASSWORD"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "failtoban",
		Usage: "failtoban plugin, block ip after too many auth failures",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "max-failures",
				Usage:   "max failures",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_MAX_FAILURES"},
				Value:   5,
			},
			&cli.DurationFlag{
				Name:    "ban-duration",
				Usage:   "ban duration",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_BAN_DURATION"},
				Value:   60 * time.Minute,
			},
			&cli.BoolFlag{
				Name:    "log-only",
				Usage:   "log only mode, no ban, useful for working with other tools like fail2ban",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_LOG_ONLY"},
				Value:   false,
			},
			&cli.StringSliceFlag{
				Name:    "ignore-ip",
				Usage:   "ignore ip, will not ban host matches from these ip addresses",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_IGNORE_IP"},
				Value:   cli.NewStringSlice(),
			},
			&cli.StringSliceFlag{
				Name:    "deny-ip",
				Usage:   "ips or CIDRs (IPv4 and IPv6) that are always rejected, regardless of failures, ignore-ip or log-only",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_DENY_IP"},
				Value:   cli.NewStringSlice(),
			},
			&cli.StringFlag{
				Name:    "store",
				Usage:   "where to keep failure counters: memory (per instance) or redis (shared between instances)",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_STORE"},
				Value:   storeMemory,
			},
			&cli.StringFlag{
				Name:    "store-failure-mode",
				Usage:   "behavior when the shared store is unavailable: local (fall back to per instance counters) or deny (reject new connections)",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_STORE_FAILURE_MODE"},
				Value:   storeFailureModeLocal,
			},
			&cli.StringFlag{
				Name:    "redis-url",
				Usage:   "redis url, e.g. rediss://redis:6379/0, use rediss:// for TLS",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_URL"},
			},
			&cli.StringFlag{
				Name:    "redis-username",
				Usage:   "redis ACL username",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_USERNAME"},
			},
			&cli.StringFlag{
				Name:    "redis-password-file",
				Usage:   "file containing the redis password, alternatively set env SSHPIPERD_FAILTOBAN_REDIS_PASSWORD",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_PASSWORD_FILE"},
			},
			&cli.StringFlag{
				Name:    "redis-key-prefix",
				Usage:   "prefix of all redis keys, use different prefixes to separate independent jails",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_KEY_PREFIX"},
				Value:   "sshpiper:failtoban:",
			},
			&cli.StringFlag{
				Name:    "redis-tls-ca-file",
				Usage:   "CA bundle to verify the redis server certificate, system roots if not set",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_TLS_CA_FILE"},
			},
			&cli.StringFlag{
				Name:    "redis-tls-cert-file",
				Usage:   "client certificate for redis mTLS",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_TLS_CERT_FILE"},
			},
			&cli.StringFlag{
				Name:    "redis-tls-key-file",
				Usage:   "client private key for redis mTLS",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_TLS_KEY_FILE"},
			},
			&cli.StringFlag{
				Name:    "redis-tls-server-name",
				Usage:   "override the server name used to verify the redis server certificate",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_TLS_SERVER_NAME"},
			},
			&cli.BoolFlag{
				Name:    "redis-insecure",
				Usage:   "allow plaintext (non TLS) redis connections, NOT recommended",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_INSECURE"},
			},
			&cli.DurationFlag{
				Name:    "redis-timeout",
				Usage:   "timeout of a single redis operation",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_REDIS_TIMEOUT"},
				Value:   500 * time.Millisecond,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			j, err := newJailFromCli(c)
			if err != nil {
				return nil, err
			}

			// register signal handler
			go func() {
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGHUP)

				for {
					<-sigChan
					j.reset()
				}
			}()

			return &libplugin.SshPiperPluginConfig{
				NoClientAuthCallback: func(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
					// in case someone put the failtoban plugin before other plugins
					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{}),
					}, nil
				},
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					return j.check(context.Background(), conn.RemoteAddr())
				},
				UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowmethods []string) {
					j.recordFailure(context.Background(), conn.RemoteAddr(), "failtoban auth failed")
				},
				PipeCreateErrorCallback: func(remoteAddr string, err error) {
					j.recordPipeCreateFailure(context.Background(), remoteAddr, err)
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					j.pipeStarted(conn.RemoteAddr())
				},
			}, nil
		},
	})
}

func newJailFromCli(c *cli.Context) (*jail, error) {
	maxFailures := c.Int("max-failures")
	banDuration := c.Duration("ban-duration")
	logOnly := c.Bool("log-only")

	if maxFailures < 1 {
		return nil, errors.New("failtoban: max-failures must be at least 1")
	}

	if banDuration <= 0 {
		return nil, errors.New("failtoban: ban-duration must be positive")
	}

	whitelist, err := buildIPSet(c.StringSlice("ignore-ip"))
	if err != nil {
		return nil, fmt.Errorf("failtoban: invalid ignore-ip: %w", err)
	}

	denylist, err := buildIPSet(c.StringSlice("deny-ip"))
	if err != nil {
		return nil, fmt.Errorf("failtoban: invalid deny-ip: %w", err)
	}

	warnDenyAll(denylist)

	switch c.String("store") {
	case storeMemory:
		if c.IsSet("redis-url") {
			slog.Warn("failtoban: redis-url is set but store is memory, redis is not used")
		}

		return newLocalJail(maxFailures, banDuration, logOnly, whitelist, denylist), nil

	case storeRedis:
		password, err := readRedisPassword(c.String("redis-password-file"))
		if err != nil {
			return nil, err
		}

		failureMode := c.String("store-failure-mode")

		rs, err := newRedisStore(redisConfig{
			URL:        c.String("redis-url"),
			Username:   c.String("redis-username"),
			Password:   password,
			KeyPrefix:  c.String("redis-key-prefix"),
			CAFile:     c.String("redis-tls-ca-file"),
			CertFile:   c.String("redis-tls-cert-file"),
			KeyFile:    c.String("redis-tls-key-file"),
			ServerName: c.String("redis-tls-server-name"),
			Insecure:   c.Bool("redis-insecure"),
			Timeout:    c.Duration("redis-timeout"),
		}, banDuration)
		if err != nil {
			return nil, err
		}

		j, err := newSharedJail(maxFailures, banDuration, logOnly, whitelist, denylist, rs, failureMode)
		if err != nil {
			_ = rs.Close()
			return nil, err
		}

		if err := rs.Ping(context.Background()); err != nil {
			if failureMode == storeFailureModeDeny {
				_ = rs.Close()
				return nil, fmt.Errorf("failtoban: cannot reach redis: %w", err)
			}

			slog.Warn("failtoban: cannot reach redis, using local counters until it is available", "error", err)
		}

		return j, nil

	default:
		return nil, fmt.Errorf("failtoban: unknown store %q, must be %q or %q", c.String("store"), storeMemory, storeRedis)
	}
}

// readRedisPassword reads the password from file or env, never from a cli
// flag, as flags are visible to other users in the process list.
func readRedisPassword(file string) (string, error) {
	env := os.Getenv(redisPasswordEnv)

	if file == "" {
		return env, nil
	}

	if env != "" {
		return "", fmt.Errorf("failtoban: only one of --redis-password-file and %v may be set", redisPasswordEnv)
	}

	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failtoban: reading redis password file: %w", err)
	}

	return strings.TrimRight(string(b), "\r\n"), nil
}

func buildIPSet(cidrs []string) (*netipx.IPSet, error) {
	var ipsetBuilder netipx.IPSetBuilder

	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		if strings.Contains(cidr, "/") {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, err
			}

			prefix, err = unmapPrefix(prefix)
			if err != nil {
				return nil, err
			}

			ipsetBuilder.AddPrefix(prefix.Masked())
		} else {
			ip, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, err
			}
			ipsetBuilder.Add(ip.WithZone("").Unmap())
		}
	}

	return ipsetBuilder.IPSet()
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix (e.g. ::ffff:10.0.0.0/104)
// to its IPv4 form (10.0.0.0/8). Remote addresses are unmapped before
// matching, so a mapped prefix would otherwise never match.
func unmapPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.Addr().Is4In6() {
		return prefix, nil
	}

	if prefix.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %v must be at least /96", prefix)
	}

	return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96), nil
}

// warnDenyAll warns if the deny list rejects every IPv4 or IPv6 client.
func warnDenyAll(denylist *netipx.IPSet) {
	if denylist.ContainsPrefix(netip.MustParsePrefix("0.0.0.0/0")) {
		slog.Warn("failtoban: deny-ip contains 0.0.0.0/0, all IPv4 clients are rejected")
	}

	if denylist.ContainsPrefix(netip.MustParsePrefix("::/0")) {
		slog.Warn("failtoban: deny-ip contains ::/0, all IPv6 clients are rejected")
	}
}
