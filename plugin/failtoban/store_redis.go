//go:build full || e2e

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrScript atomically increments the counter and makes sure it always
// carries an expiry, so that a key can never stay forever (e.g. when INCR
// succeeded but a separate EXPIRE call would have been lost).
var incrScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

const (
	resetScanCount = 100
	resetMaxPasses = 5

	// healthKeyTTL is the expiry of the key written by ProbeWrite
	healthKeyTTL = 10 * time.Second
)

type redisConfig struct {
	URL        string
	Username   string
	Password   string
	KeyPrefix  string
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
	Timeout    time.Duration
}

// redisStore keeps failure counters in a Redis protocol compatible server
// (Redis, Valkey, ...), shared by all sshpiperd instances using it.
type redisStore struct {
	client  *redis.Client
	prefix  string
	ttl     time.Duration
	timeout time.Duration
}

func newRedisStore(cfg redisConfig, ttl time.Duration) (*redisStore, error) {
	opts, err := buildRedisOptions(cfg)
	if err != nil {
		return nil, err
	}

	return &redisStore{
		client:  redis.NewClient(opts),
		prefix:  cfg.KeyPrefix,
		ttl:     ttl,
		timeout: cfg.Timeout,
	}, nil
}

func buildRedisOptions(cfg redisConfig) (*redis.Options, error) {
	if cfg.URL == "" {
		return nil, errors.New("failtoban: redis url is required when using the redis store")
	}

	if cfg.KeyPrefix == "" {
		return nil, errors.New("failtoban: redis key prefix must not be empty")
	}

	if cfg.Timeout <= 0 {
		return nil, errors.New("failtoban: redis timeout must be positive")
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		// do not include the error, it may contain the url with credentials
		return nil, errors.New("failtoban: invalid redis url")
	}

	// the url may be a cli flag, visible to other users in the process list
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, errors.New("failtoban: redis url must not contain a password, use --redis-password-file or SSHPIPERD_FAILTOBAN_REDIS_PASSWORD")
	}

	useTLS := u.Scheme == "rediss"
	hasTLSFiles := cfg.CAFile != "" || cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ServerName != ""

	switch {
	case useTLS:
	case cfg.Insecure && hasTLSFiles:
		return nil, errors.New("failtoban: redis tls options given but redis url does not use rediss://")
	case cfg.Insecure:
		slog.Warn("failtoban: connecting to redis WITHOUT TLS, traffic and credentials are not protected", "url", u.Redacted())
	default:
		return nil, fmt.Errorf("failtoban: redis url must use rediss:// (TLS), use --redis-insecure to allow plaintext connections (url: %v)", u.Redacted())
	}

	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failtoban: invalid redis url %v", u.Redacted())
	}

	if cfg.Username != "" {
		opts.Username = cfg.Username
	}

	if cfg.Password != "" {
		opts.Password = cfg.Password
	}

	if useTLS {
		if opts.TLSConfig == nil {
			opts.TLSConfig = &tls.Config{ServerName: u.Hostname()}
		}

		if opts.TLSConfig.InsecureSkipVerify {
			return nil, errors.New("failtoban: skipping redis tls certificate verification is not allowed")
		}

		if err := applyTLSFiles(opts.TLSConfig, cfg); err != nil {
			return nil, err
		}
	}

	// keep auth path latency bounded, the per operation context also applies
	opts.DialTimeout = cfg.Timeout
	opts.ReadTimeout = cfg.Timeout
	opts.WriteTimeout = cfg.Timeout
	opts.PoolTimeout = cfg.Timeout
	opts.ContextTimeoutEnabled = true
	// no automatic retries: the increment is not idempotent, a retry after a
	// lost reply would count a failure twice. Errors are handled by the store
	// failure mode instead. -1 disables retries in go-redis (0 means default).
	opts.MaxRetries = -1
	// skip CLIENT SETINFO, not needed and requires extra ACL permissions
	opts.DisableIdentity = true

	return opts, nil
}

func applyTLSFiles(c *tls.Config, cfg redisConfig) error {
	c.MinVersion = tls.VersionTLS12

	if cfg.ServerName != "" {
		c.ServerName = cfg.ServerName
	}

	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return fmt.Errorf("failtoban: reading redis ca file: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("failtoban: no valid certificates in redis ca file %v", cfg.CAFile)
		}

		c.RootCAs = pool
	}

	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("failtoban: both --redis-tls-cert-file and --redis-tls-key-file must be set for redis mTLS")
	}

	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("failtoban: loading redis client certificate: %w", err)
		}

		c.Certificates = []tls.Certificate{cert}
	}

	return nil
}

func (r *redisStore) key(ip netip.Addr) string {
	return r.prefix + "fail:" + ipKey(ip)
}

func (r *redisStore) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Ping(ctx).Err()
}

func (r *redisStore) Failures(ctx context.Context, ip netip.Addr) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	n, err := r.client.Get(ctx, r.key(ip)).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}

	return n, err
}

func (r *redisStore) Incr(ctx context.Context, ip netip.Addr) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return incrScript.Run(ctx, r.client, []string{r.key(ip)}, r.ttl.Milliseconds()).Int()
}

// ProbeWrite increments a dedicated health key (same key prefix and commands
// as the counters, no extra ACL permissions needed). It never touches the
// failure counters.
func (r *redisStore) ProbeWrite(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return incrScript.Run(ctx, r.client, []string{r.prefix + "health"}, healthKeyTTL.Milliseconds()).Err()
}

// Reset removes all failure counters below the key prefix, for all instances
// sharing the store.
//
// A single SCAN iteration may miss keys created while it runs (e.g. other
// instances recording failures during the reset), so passes are repeated
// until one finds nothing, bounded by resetMaxPasses.
func (r *redisStore) Reset(ctx context.Context) error {
	match := escapeGlob(r.prefix) + "fail:*"

	for pass := 0; pass < resetMaxPasses; pass++ {
		deleted, err := r.resetPass(ctx, match)
		if err != nil {
			return err
		}

		if deleted == 0 {
			return nil
		}
	}

	slog.Debug("failtoban reset stopped after max passes, keys are still being created", "passes", resetMaxPasses)
	return nil
}

func (r *redisStore) resetPass(ctx context.Context, match string) (int, error) {
	var cursor uint64
	deleted := 0

	for {
		keys, next, err := r.scan(ctx, cursor, match)
		if err != nil {
			return deleted, err
		}

		if len(keys) > 0 {
			if err := r.unlink(ctx, keys); err != nil {
				return deleted, err
			}

			deleted += len(keys)
		}

		if next == 0 {
			return deleted, nil
		}

		cursor = next
	}
}

func (r *redisStore) scan(ctx context.Context, cursor uint64, match string) ([]string, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Scan(ctx, cursor, match, resetScanCount).Result()
}

func (r *redisStore) unlink(ctx context.Context, keys []string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Unlink(ctx, keys...).Err()
}

func (r *redisStore) Close() error {
	return r.client.Close()
}

// escapeGlob escapes redis glob-style pattern special characters.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '*', '?', '[', ']', '\\', '^', '-':
			b.WriteRune('\\')
		}
		b.WriteRune(c)
	}

	return b.String()
}
