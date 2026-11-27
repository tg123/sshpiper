//go:build full || e2e

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"go4.org/netipx"
)

const testPrefix = "sshpiper:failtoban:"

func emptyIPSet(t *testing.T) *netipx.IPSet {
	t.Helper()
	s, err := buildIPSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestRedisStore(t *testing.T, addr string, ttl time.Duration) *redisStore {
	t.Helper()
	rs, err := newRedisStore(redisConfig{
		URL:       "redis://" + addr,
		KeyPrefix: testPrefix,
		Insecure:  true,
		Timeout:   200 * time.Millisecond,
	}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rs.Close() })
	return rs
}

func TestIPKeyNormalization(t *testing.T) {
	a := netip.MustParseAddr("1.2.3.4")
	b := netip.MustParseAddr("::ffff:1.2.3.4")
	c := netip.MustParseAddr("fe80::1%eth0")

	if ipKey(a) != ipKey(b) {
		t.Errorf("ipv4 mapped address not normalized: %v != %v", ipKey(a), ipKey(b))
	}

	if ipKey(c) != "fe80::1" {
		t.Errorf("zone not stripped: %v", ipKey(c))
	}
}

func TestParseRemoteIP(t *testing.T) {
	ip, err := parseRemoteIP("[::ffff:10.0.0.1]:22")
	if err != nil {
		t.Fatal(err)
	}
	if ip != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("unexpected ip %v", ip)
	}

	for _, bad := range []string{"", "10.0.0.1", "foo:22", "@"} {
		if _, err := parseRemoteIP(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestBuildIPSet(t *testing.T) {
	s, err := buildIPSet([]string{"10.0.0.0/8", " 192.168.1.1 ", ""})
	if err != nil {
		t.Fatal(err)
	}

	if !s.Contains(netip.MustParseAddr("10.1.2.3")) || !s.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Errorf("ipset missing entries")
	}

	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "300.1.1.1"} {
		if _, err := buildIPSet([]string{bad}); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	m := newMemoryStore(100 * time.Millisecond)
	ip := netip.MustParseAddr("1.2.3.4")

	for i := 1; i <= 3; i++ {
		n, err := m.Incr(ctx, ip)
		if err != nil || n != i {
			t.Fatalf("incr %d: got %d, %v", i, n, err)
		}
	}

	if n, _ := m.Failures(ctx, netip.MustParseAddr("::ffff:1.2.3.4")); n != 3 {
		t.Errorf("expected 3 failures, got %d", n)
	}

	time.Sleep(150 * time.Millisecond)

	if n, _ := m.Failures(ctx, ip); n != 0 {
		t.Errorf("expected expiry, got %d", n)
	}

	if n, _ := m.Incr(ctx, ip); n != 1 {
		t.Errorf("expected new window, got %d", n)
	}

	_ = m.Reset(ctx)
	if n, _ := m.Failures(ctx, ip); n != 0 {
		t.Errorf("expected reset, got %d", n)
	}
}

func TestRedisStoreShared(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	a := newTestRedisStore(t, mr.Addr(), time.Minute)
	b := newTestRedisStore(t, mr.Addr(), time.Minute)
	ip := netip.MustParseAddr("1.2.3.4")

	if _, err := a.Incr(ctx, ip); err != nil {
		t.Fatal(err)
	}
	n, err := b.Incr(ctx, ip)
	if err != nil || n != 2 {
		t.Fatalf("expected shared counter 2, got %d, %v", n, err)
	}

	if n, _ := a.Failures(ctx, ip); n != 2 {
		t.Errorf("expected 2, got %d", n)
	}

	key := testPrefix + "fail:1.2.3.4"
	if ttl := mr.TTL(key); ttl <= 0 || ttl > time.Minute {
		t.Errorf("unexpected ttl %v", ttl)
	}

	// the window is not extended by further failures
	mr.FastForward(30 * time.Second)
	_, _ = a.Incr(ctx, ip)
	if ttl := mr.TTL(key); ttl > 30*time.Second {
		t.Errorf("ttl extended by incr: %v", ttl)
	}

	mr.FastForward(31 * time.Second)
	if n, _ := a.Failures(ctx, ip); n != 0 {
		t.Errorf("expected expiry, got %d", n)
	}
}

func TestRedisStoreRepairsMissingTTL(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rs := newTestRedisStore(t, mr.Addr(), time.Minute)

	key := testPrefix + "fail:1.2.3.4"
	_ = mr.Set(key, "1")

	if n, err := rs.Incr(ctx, netip.MustParseAddr("1.2.3.4")); err != nil || n != 2 {
		t.Fatalf("got %d, %v", n, err)
	}

	if ttl := mr.TTL(key); ttl <= 0 {
		t.Errorf("expected ttl to be set, got %v", ttl)
	}
}

func TestRedisStoreReset(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rs := newTestRedisStore(t, mr.Addr(), time.Minute)

	for i := range 250 {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		if _, err := rs.Incr(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	_ = mr.Set("unrelated", "keep")
	_ = mr.Set("other:fail:1.1.1.1", "keep")

	if err := rs.Reset(ctx); err != nil {
		t.Fatal(err)
	}

	keys := mr.Keys()
	if len(keys) != 2 {
		t.Errorf("expected only unrelated keys to remain, got %v", keys)
	}
}

func TestSharedJail(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	newJ := func() *jail {
		j, err := newSharedJail(3, time.Minute, false, emptyIPSet(t), emptyIPSet(t), newTestRedisStore(t, mr.Addr(), time.Minute), storeFailureModeLocal)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}

	a, b := newJ(), newJ()
	addr := "1.2.3.4:1234"

	a.recordFailure(ctx, addr, "test")
	a.recordFailure(ctx, addr, "test")

	if err := b.check(ctx, addr); err != nil {
		t.Fatalf("not yet banned: %v", err)
	}

	b.recordFailure(ctx, "[::ffff:1.2.3.4]:999", "test")

	if err := a.check(ctx, addr); err == nil {
		t.Errorf("expected ban on a")
	}
	if err := b.check(ctx, addr); err == nil {
		t.Errorf("expected ban on b")
	}
	if err := a.check(ctx, "5.6.7.8:22"); err != nil {
		t.Errorf("other ip must not be banned: %v", err)
	}

	// reset clears shared and local state
	a.reset()
	b.reset()
	if err := b.check(ctx, addr); err != nil {
		t.Errorf("expected no ban after reset: %v", err)
	}
}

func TestSharedJailStoreDownLocal(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	j, err := newSharedJail(2, time.Minute, false, emptyIPSet(t), emptyIPSet(t), newTestRedisStore(t, mr.Addr(), time.Minute), storeFailureModeLocal)
	if err != nil {
		t.Fatal(err)
	}
	mr.Close()

	addr := "1.2.3.4:1234"
	if err := j.check(ctx, addr); err != nil {
		t.Fatalf("local mode must allow while store is down: %v", err)
	}

	j.recordFailure(ctx, addr, "test")
	j.recordFailure(ctx, addr, "test")

	if err := j.check(ctx, addr); err == nil {
		t.Errorf("expected local ban while store is down")
	}

	// still banned after the store is back (via local fallback counters)
	if err := mr.Restart(); err != nil {
		t.Fatal(err)
	}
	j.banCache.Flush()
	if err := j.check(ctx, addr); err == nil {
		t.Errorf("expected ban from fallback after store recovery")
	}
}

func TestSharedJailStoreDownDeny(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	j, err := newSharedJail(2, time.Minute, false, emptyIPSet(t), emptyIPSet(t), newTestRedisStore(t, mr.Addr(), time.Minute), storeFailureModeDeny)
	if err != nil {
		t.Fatal(err)
	}
	mr.Close()

	if err := j.check(ctx, "1.2.3.4:1234"); !errors.Is(err, errStoreUnavailable) {
		t.Errorf("expected store unavailable error, got %v", err)
	}
}

func TestJailWhitelistAndParseFailure(t *testing.T) {
	ctx := context.Background()
	wl, err := buildIPSet([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	j := newLocalJail(1, time.Minute, false, wl, emptyIPSet(t))

	j.recordFailure(ctx, "10.1.1.1:22", "test")
	j.recordFailure(ctx, "[::ffff:10.1.1.1]:22", "test")
	if err := j.check(ctx, "10.1.1.1:22"); err != nil {
		t.Errorf("whitelisted ip banned: %v", err)
	}

	j.recordFailure(ctx, "1.1.1.1:22", "test")
	if err := j.check(ctx, "1.1.1.1:22"); err == nil {
		t.Errorf("expected ban")
	}

	if err := j.check(ctx, "garbage"); err == nil {
		t.Errorf("expected unparsable address to be rejected")
	}
}

func TestSharedJailInvalidMode(t *testing.T) {
	if _, err := newSharedJail(1, time.Minute, false, emptyIPSet(t), emptyIPSet(t), newMemoryStore(time.Minute), "allow"); err == nil {
		t.Errorf("expected error for unknown mode")
	}
}

func TestRedisOptionsValidation(t *testing.T) {
	base := redisConfig{URL: "redis://127.0.0.1:6379", KeyPrefix: testPrefix, Timeout: time.Second}

	if _, err := buildRedisOptions(base); err == nil {
		t.Errorf("plaintext must be rejected without insecure")
	}

	ok := base
	ok.Insecure = true
	if _, err := buildRedisOptions(ok); err != nil {
		t.Errorf("plaintext with insecure should work: %v", err)
	}

	mixed := ok
	mixed.CAFile = "/some/ca.pem"
	if _, err := buildRedisOptions(mixed); err == nil {
		t.Errorf("tls options with plaintext url must be rejected")
	}

	tlsCfg := base
	tlsCfg.URL = "rediss://127.0.0.1:6379"
	opts, err := buildRedisOptions(tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig == nil || opts.TLSConfig.InsecureSkipVerify || opts.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("unexpected tls config %+v", opts.TLSConfig)
	}

	halfMTLS := tlsCfg
	halfMTLS.CertFile = "/some/cert.pem"
	if _, err := buildRedisOptions(halfMTLS); err == nil {
		t.Errorf("cert without key must be rejected")
	}

	// password in the url is rejected (visible in the process list), a
	// username is fine
	withPassword := ok
	withPassword.URL = "redis://user:secret@127.0.0.1:6379"
	if _, err := buildRedisOptions(withPassword); err == nil {
		t.Errorf("password in url must be rejected")
	}

	withUser := ok
	withUser.URL = "redis://user@127.0.0.1:6379"
	if _, err := buildRedisOptions(withUser); err != nil {
		t.Errorf("username in url should work: %v", err)
	}

	// automatic retries are disabled, also if requested in the url
	retries := ok
	retries.URL = "redis://127.0.0.1:6379?max_retries=3"
	ropts, err := buildRedisOptions(retries)
	if err != nil {
		t.Fatal(err)
	}
	if ropts.MaxRetries != -1 {
		t.Errorf("expected retries disabled, got %d", ropts.MaxRetries)
	}

	for _, c := range []redisConfig{
		{KeyPrefix: testPrefix, Timeout: time.Second},
		{URL: "rediss://h:1", Timeout: time.Second},
		{URL: "rediss://h:1", KeyPrefix: testPrefix},
		{URL: "://bad", KeyPrefix: testPrefix, Timeout: time.Second},
	} {
		if _, err := buildRedisOptions(c); err == nil {
			t.Errorf("expected error for %+v", c)
		}
	}
}

func TestReadRedisPassword(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(redisPasswordEnv, "")
	pw, err := readRedisPassword(f)
	if err != nil || pw != "s3cret" {
		t.Errorf("got %q, %v", pw, err)
	}

	t.Setenv(redisPasswordEnv, "fromenv")
	if pw, err := readRedisPassword(""); err != nil || pw != "fromenv" {
		t.Errorf("got %q, %v", pw, err)
	}
	if _, err := readRedisPassword(f); err == nil {
		t.Errorf("expected error when both file and env are set")
	}
}

func TestRedisAuthAndTLS(t *testing.T) {
	dir := t.TempDir()
	caFile, serverCert := writeTestCA(t, dir)

	mr := miniredis.NewMiniRedis()
	mr.RequireUserAuth("sshpiper", "s3cret")
	if err := mr.StartTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)

	cfg := redisConfig{
		URL:       "rediss://" + mr.Addr(),
		Username:  "sshpiper",
		Password:  "s3cret",
		KeyPrefix: testPrefix,
		CAFile:    caFile,
		Timeout:   time.Second,
	}

	rs, err := newRedisStore(cfg, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()

	if err := rs.Ping(context.Background()); err != nil {
		t.Fatalf("tls ping failed: %v", err)
	}

	// server certificate must be verified: without the CA the connection fails
	noCA := cfg
	noCA.CAFile = ""
	rs2, err := newRedisStore(noCA, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer rs2.Close()

	if err := rs2.Ping(context.Background()); err == nil {
		t.Errorf("expected certificate verification failure")
	}

	// wrong password
	badPw := cfg
	badPw.Password = "wrong"
	rs3, err := newRedisStore(badPw, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer rs3.Close()

	if err := rs3.Ping(context.Background()); err == nil {
		t.Errorf("expected auth failure")
	}
}

// writeTestCA creates a CA and a server certificate for 127.0.0.1, writes
// the CA to dir and returns its path and the server certificate.
func writeTestCA(t *testing.T, dir string) (string, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "failtoban test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return caFile, tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

func TestPipeCreateFailureOnlyCountedAfterSSHAuthStage(t *testing.T) {
	ctx := context.Background()
	j := newLocalJail(2, time.Minute, false, emptyIPSet(t), emptyIPSet(t))
	ip := netip.MustParseAddr("1.2.3.4")
	errPipe := errors.New("pipe create failed")

	// tcp health checks / port scans never reach NewConnection
	for i := range 10 {
		j.recordPipeCreateFailure(ctx, fmt.Sprintf("1.2.3.4:%d", 2000+i), errPipe)
	}
	if n, _ := j.primary.Failures(ctx, ip); n != 0 {
		t.Fatalf("pre auth failures must not count, got %d", n)
	}

	// connection reaching the auth stage, then failing
	if err := j.check(ctx, "1.2.3.4:1000"); err != nil {
		t.Fatal(err)
	}
	j.recordPipeCreateFailure(ctx, "1.2.3.4:1000", errPipe)
	// a second callback for the same connection is not counted twice
	j.recordPipeCreateFailure(ctx, "1.2.3.4:1000", errPipe)

	if n, _ := j.primary.Failures(ctx, ip); n != 1 {
		t.Fatalf("expected 1 failure, got %d", n)
	}

	if err := j.check(ctx, "1.2.3.4:1001"); err != nil {
		t.Fatal(err)
	}
	j.recordPipeCreateFailure(ctx, "1.2.3.4:1001", errPipe)

	if err := j.check(ctx, "1.2.3.4:1002"); err == nil {
		t.Errorf("expected ban after 2 counted failures")
	}

	// the rejected connection is not counted again
	j.recordPipeCreateFailure(ctx, "1.2.3.4:1002", errPipe)
	if n, _ := j.primary.Failures(ctx, ip); n != 2 {
		t.Errorf("rejected connection must not be counted, got %d", n)
	}
}

func TestRejectedConnectionsCauseNoStoreWrites(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	j, err := newSharedJail(1, time.Minute, false, emptyIPSet(t), emptyIPSet(t), newTestRedisStore(t, mr.Addr(), time.Minute), storeFailureModeDeny)
	if err != nil {
		t.Fatal(err)
	}

	if err := j.check(ctx, "1.2.3.4:1000"); err != nil {
		t.Fatal(err)
	}
	j.recordFailure(ctx, "1.2.3.4:1000", "test")

	before := mr.CommandCount()

	// flood of a banned ip: served from the local ban cache, not counted
	for i := range 50 {
		addr := fmt.Sprintf("1.2.3.4:%d", 2000+i)
		if err := j.check(ctx, addr); err == nil {
			t.Fatalf("expected ban")
		}
		j.recordPipeCreateFailure(ctx, addr, errors.New("banned"))
	}

	if n := mr.CommandCount() - before; n != 0 {
		t.Errorf("expected no redis commands for a banned flood, got %d", n)
	}
}

func mustIPSet(t *testing.T, entries ...string) *netipx.IPSet {
	t.Helper()
	s, err := buildIPSet(entries)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildIPSetMappedPrefix(t *testing.T) {
	s := mustIPSet(t, "::ffff:10.0.0.0/104", "::ffff:192.168.1.1/128")

	for _, ip := range []string{"10.1.2.3", "192.168.1.1"} {
		if !s.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("mapped prefix must match %v", ip)
		}
	}

	if s.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Errorf("unexpected match")
	}

	if _, err := buildIPSet([]string{"::ffff:0:0/80"}); err == nil {
		t.Errorf("expected error for mapped prefix shorter than /96")
	}
}

func TestDenyList(t *testing.T) {
	ctx := context.Background()
	deny := mustIPSet(t, "203.0.113.7", "198.51.100.0/24", "2001:db8::1", "2001:db8:1::/48")

	for _, logOnly := range []bool{false, true} {
		// whitelist overlaps the deny list: deny wins
		j := newLocalJail(5, time.Minute, logOnly, mustIPSet(t, "198.51.100.0/24", "2001:db8::/32"), deny)

		for _, addr := range []string{
			"203.0.113.7:22",
			"198.51.100.42:22",
			"[2001:db8::1]:22",
			"[2001:db8:1:2::3]:22",
			"[::ffff:203.0.113.7]:22",
		} {
			ip, err := parseRemoteIP(addr)
			if err != nil {
				t.Fatal(err)
			}

			err = j.check(ctx, addr)
			if err == nil || err.Error() != deniedError(ip).Error() {
				t.Errorf("log-only=%v: %v must be denied, got %v", logOnly, addr, err)
			}
		}

		for _, addr := range []string{"203.0.113.8:22", "[2001:db8::2]:22", "198.51.101.1:22"} {
			if err := j.check(ctx, addr); err != nil {
				t.Errorf("log-only=%v: %v must not be denied: %v", logOnly, addr, err)
			}
		}
	}
}

func TestDeniedConnectionsCauseNoStoreAccess(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	j, err := newSharedJail(1, time.Minute, false, emptyIPSet(t), mustIPSet(t, "1.2.3.0/24"), newTestRedisStore(t, mr.Addr(), time.Minute), storeFailureModeDeny)
	if err != nil {
		t.Fatal(err)
	}

	before := mr.CommandCount()

	for i := range 50 {
		addr := fmt.Sprintf("1.2.3.4:%d", 2000+i)
		if err := j.check(ctx, addr); err == nil {
			t.Fatalf("expected deny")
		}
		// denied connections are not tracked, their pipe failure is not counted
		j.recordPipeCreateFailure(ctx, addr, errors.New("denied"))
	}

	if n := mr.CommandCount() - before; n != 0 {
		t.Errorf("expected no redis commands for denied ips, got %d", n)
	}

	if n, _ := j.primary.Failures(ctx, netip.MustParseAddr("1.2.3.4")); n != 0 {
		t.Errorf("denied connections must not be counted, got %d", n)
	}
}

// writeFailingStore serves reads but rejects writes, like a read-only replica
// or a redis out of memory with noeviction.
type writeFailingStore struct {
	incrErr  error
	probeErr error
}

func (w *writeFailingStore) Failures(context.Context, netip.Addr) (int, error) { return 0, nil }

func (w *writeFailingStore) Incr(context.Context, netip.Addr) (int, error) { return 0, w.incrErr }

func (w *writeFailingStore) Reset(context.Context) error { return nil }

func (w *writeFailingStore) ProbeWrite(context.Context) error { return w.probeErr }

func TestDenyModeRejectsAfterWriteFailure(t *testing.T) {
	ctx := context.Background()
	errReadOnly := errors.New("READONLY You can't write against a read only replica")
	st := &writeFailingStore{incrErr: errReadOnly, probeErr: errReadOnly}

	j, err := newSharedJail(3, time.Minute, false, emptyIPSet(t), emptyIPSet(t), st, storeFailureModeDeny)
	if err != nil {
		t.Fatal(err)
	}
	j.probeInterval = 0

	if err := j.check(ctx, "1.2.3.4:1000"); err != nil {
		t.Fatal(err)
	}
	j.recordFailure(ctx, "1.2.3.4:1000", "test")

	// the failure is counted locally, not lost
	if n, _ := j.fallback.Failures(ctx, netip.MustParseAddr("1.2.3.4")); n != 1 {
		t.Errorf("expected failure counted locally, got %d", n)
	}

	// reads still work, but new connections (any ip) must be rejected
	for _, addr := range []string{"1.2.3.4:1001", "5.6.7.8:1000"} {
		if err := j.check(ctx, addr); !errors.Is(err, errStoreUnavailable) {
			t.Errorf("%v: expected store unavailable while writes fail, got %v", addr, err)
		}
	}

	// writable again: the probe succeeds and connections are accepted
	st.incrErr, st.probeErr = nil, nil
	if err := j.check(ctx, "5.6.7.8:1001"); err != nil {
		t.Errorf("expected recovery after successful write probe: %v", err)
	}
	if j.storeUnhealthy.Load() {
		t.Errorf("expected store to be healthy again")
	}
}

func TestLocalModeIgnoresWriteFailureForAdmission(t *testing.T) {
	ctx := context.Background()
	st := &writeFailingStore{incrErr: errors.New("OOM"), probeErr: errors.New("OOM")}

	j, err := newSharedJail(2, time.Minute, false, emptyIPSet(t), emptyIPSet(t), st, storeFailureModeLocal)
	if err != nil {
		t.Fatal(err)
	}

	j.recordFailure(ctx, "1.2.3.4:1000", "test")
	if err := j.check(ctx, "5.6.7.8:1000"); err != nil {
		t.Errorf("local mode must keep accepting: %v", err)
	}

	// failures still count per instance
	j.recordFailure(ctx, "1.2.3.4:1001", "test")
	if err := j.check(ctx, "1.2.3.4:1002"); err == nil {
		t.Errorf("expected local ban")
	}
}

func TestRedisProbeWrite(t *testing.T) {
	mr := miniredis.RunT(t)
	rs := newTestRedisStore(t, mr.Addr(), time.Minute)

	if err := rs.ProbeWrite(context.Background()); err != nil {
		t.Fatal(err)
	}

	key := testPrefix + "health"
	if !mr.Exists(key) || mr.TTL(key) <= 0 {
		t.Errorf("expected health key with ttl, exists=%v ttl=%v", mr.Exists(key), mr.TTL(key))
	}

	// reset only removes failure counters
	if err := rs.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !mr.Exists(key) {
		t.Errorf("reset must not touch the health key")
	}
}

func TestPipeStartClearsTracking(t *testing.T) {
	ctx := context.Background()
	j := newLocalJail(5, time.Minute, false, emptyIPSet(t), emptyIPSet(t))

	if err := j.check(ctx, "1.2.3.4:1000"); err != nil {
		t.Fatal(err)
	}
	j.pipeStarted("1.2.3.4:1000")

	// a later plain tcp probe reusing the same ip:port is not counted
	j.recordPipeCreateFailure(ctx, "1.2.3.4:1000", errors.New("EOF"))
	if n, _ := j.primary.Failures(ctx, netip.MustParseAddr("1.2.3.4")); n != 0 {
		t.Errorf("stale tracking entry counted, got %d", n)
	}
}
