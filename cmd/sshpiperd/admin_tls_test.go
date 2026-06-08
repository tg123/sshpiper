package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert generates a self-signed cert/key pair and writes them to
// tempdir, returning their paths. The cert is valid for 1h and uses a
// throwaway ECDSA key so the test stays fast and offline.
func writeTestCert(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestLoadAdminTLSConfig_ServerOnly(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir, "server")

	cfg, err := loadAdminTLSConfig(cert, key, "")
	if err != nil {
		t.Fatalf("loadAdminTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(cfg.Certificates))
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert when no CA supplied", cfg.ClientAuth)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want >=TLS1.2", cfg.MinVersion)
	}
}

func TestLoadAdminTLSConfig_MutualTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir, "server")
	caCert, _ := writeTestCert(t, dir, "ca")

	cfg, err := loadAdminTLSConfig(cert, key, caCert)
	if err != nil {
		t.Fatalf("loadAdminTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs should be populated when CA file is supplied")
	}
}

func TestLoadAdminTLSConfig_BadKeypair(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "missing.pem")
	if _, err := loadAdminTLSConfig(bad, bad, ""); err == nil {
		t.Fatal("expected error when cert/key files are missing")
	}
}

func TestLoadAdminTLSConfig_BadCAFile(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir, "server")
	garbage := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminTLSConfig(cert, key, garbage); err == nil {
		t.Fatal("expected error for non-PEM CA")
	}
}
