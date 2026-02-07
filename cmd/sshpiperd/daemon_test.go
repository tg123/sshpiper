package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

// generateTestKey generates an ed25519 private key, writes it to dir/name, and returns the signer
func generateTestKey(t *testing.T, dir, name string) ssh.Signer {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	_ = pub

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPath := filepath.Join(dir, name)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	return signer
}

// generateTestCert creates a self-signed ssh certificate for the given signer, writes it to dir/name
func generateTestCert(t *testing.T, signer ssh.Signer, dir, name string) string {
	t.Helper()

	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             signer.PublicKey(),
		KeyId:           "test-host-cert",
		ValidPrincipals: []string{"localhost"},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	// self-sign with the same key for testing
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	certPath := filepath.Join(dir, name)
	certBytes := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(certPath, certBytes, 0o644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	return certPath
}

func generateTestUserCert(t *testing.T, signer ssh.Signer, dir, name string) string {
	t.Helper()

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             signer.PublicKey(),
		KeyId:           "test-user-cert",
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("failed to sign user certificate: %v", err)
	}

	certPath := filepath.Join(dir, name)
	certBytes := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(certPath, certBytes, 0o644); err != nil {
		t.Fatalf("failed to write user cert file: %v", err)
	}

	return certPath
}

func TestLoadCertSigner(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestKey(t, dir, "host_key")
	certPath := generateTestCert(t, signer, dir, "host_key-cert.pub")

	t.Run("valid cert", func(t *testing.T) {
		certSigner, err := loadCertSigner(signer, certPath)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if certSigner == nil {
			t.Fatal("expected a non-nil cert signer")
		}
		// cert signer's public key should be a certificate
		if certSigner.PublicKey().Type() != "ssh-ed25519-cert-v01@openssh.com" {
			t.Errorf("expected cert key type, got %v", certSigner.PublicKey().Type())
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadCertSigner(signer, filepath.Join(dir, "nonexistent"))
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("invalid cert content", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad-cert.pub")
		if err := os.WriteFile(badPath, []byte("not a certificate"), 0o644); err != nil {
			t.Fatalf("failed to write bad cert: %v", err)
		}
		_, err := loadCertSigner(signer, badPath)
		if err == nil {
			t.Fatal("expected error for invalid cert, got nil")
		}
	})

	t.Run("valid key but not a certificate", func(t *testing.T) {
		// write a plain public key (not a cert) in authorized_key format
		pubPath := filepath.Join(dir, "plain.pub")
		pubBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
		if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
			t.Fatalf("failed to write pub key: %v", err)
		}
		_, err := loadCertSigner(signer, pubPath)
		if err == nil {
			t.Fatal("expected error for non-cert public key, got nil")
		}
	})

	t.Run("rejects user certificate", func(t *testing.T) {
		// a user cert has the right fingerprint but wrong cert type
		userCertPath := generateTestUserCert(t, signer, dir, "user-cert.pub")
		_, err := loadCertSigner(signer, userCertPath)
		if err == nil {
			t.Fatal("expected error for user certificate, got nil")
		}
	})
}

func TestFindMatchingCert(t *testing.T) {
	dir := t.TempDir()

	// generate two keys and a cert for the first key only
	signer1 := generateTestKey(t, dir, "key1")
	signer2 := generateTestKey(t, dir, "key2")
	cert1Path := generateTestCert(t, signer1, dir, "cert1.pub")

	t.Run("matches correct cert", func(t *testing.T) {
		result := findMatchingCert(signer1, []string{cert1Path})
		if result != cert1Path {
			t.Errorf("expected %v, got %v", cert1Path, result)
		}
	})

	t.Run("no match for different key", func(t *testing.T) {
		result := findMatchingCert(signer2, []string{cert1Path})
		if result != "" {
			t.Errorf("expected empty string, got %v", result)
		}
	})

	t.Run("picks correct cert from multiple", func(t *testing.T) {
		cert2Path := generateTestCert(t, signer2, dir, "cert2.pub")
		result := findMatchingCert(signer2, []string{cert1Path, cert2Path})
		if result != cert2Path {
			t.Errorf("expected %v, got %v", cert2Path, result)
		}
	})

	t.Run("empty cert list", func(t *testing.T) {
		result := findMatchingCert(signer1, []string{})
		if result != "" {
			t.Errorf("expected empty string, got %v", result)
		}
	})

	t.Run("skips unreadable files", func(t *testing.T) {
		result := findMatchingCert(signer1, []string{
			filepath.Join(dir, "nonexistent"),
			cert1Path,
		})
		if result != cert1Path {
			t.Errorf("expected %v, got %v", cert1Path, result)
		}
	})

	t.Run("skips invalid cert files", func(t *testing.T) {
		badPath := filepath.Join(dir, "garbage.pub")
		if err := os.WriteFile(badPath, []byte("not a cert"), 0o644); err != nil {
			t.Fatalf("failed to write bad file: %v", err)
		}
		result := findMatchingCert(signer1, []string{badPath, cert1Path})
		if result != cert1Path {
			t.Errorf("expected %v, got %v", cert1Path, result)
		}
	})
}

func newTestCLIContext(t *testing.T, flags map[string]string) *cli.Context {
	t.Helper()

	set := flag.NewFlagSet("test", flag.ContinueOnError)
	for k, v := range flags {
		set.String(k, v, "")
	}

	return cli.NewContext(&cli.App{}, set, nil)
}

func keyToBase64(t *testing.T, path string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(mustReadFile(t, path))
}

func TestLoadHostKeys(t *testing.T) {
	dir := t.TempDir()

	// generate a valid host key for the file-based path
	generateTestKey(t, dir, "host_key")
	keyPath := filepath.Join(dir, "host_key")

	// generate a second unrelated key + cert for mismatch tests
	otherSigner := generateTestKey(t, dir, "other_key")
	otherCertPath := generateTestCert(t, otherSigner, dir, "other_key-cert.pub")

	// generate a matching host cert for the primary key
	primarySigner, _ := ssh.ParsePrivateKey(mustReadFile(t, keyPath))
	matchingCertPath := generateTestCert(t, primarySigner, dir, "host_key-cert.pub")

	// generate a user cert for the primary key (wrong cert type)
	userCertPath := generateTestUserCert(t, primarySigner, dir, "host_key-user-cert.pub")

	t.Run("plain key without server-cert flag", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          "",
			"server-cert":              "",
			"server-key":               keyPath,
			"server-key-generate-mode": "disable",
		})

		signers, err := loadHostKeys(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(signers) == 0 {
			t.Fatal("expected at least one signer")
		}
		if strings.Contains(signers[0].PublicKey().Type(), "cert") {
			t.Errorf("expected plain key type, got %v", signers[0].PublicKey().Type())
		}
	})

	t.Run("errors when cert glob matches nothing", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          "",
			"server-cert":              filepath.Join(dir, "*.nonexistent"),
			"server-key":               keyPath,
			"server-key-generate-mode": "disable",
		})

		_, err := loadHostKeys(ctx)
		if err == nil {
			t.Fatal("expected error when cert glob matches nothing, got nil")
		}
		if !strings.Contains(err.Error(), "matched no files") {
			t.Errorf("expected 'matched no files' error, got: %v", err)
		}
	})

	t.Run("file key errors when no cert matches fingerprint", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          "",
			"server-cert":              otherCertPath,
			"server-key":               keyPath,
			"server-key-generate-mode": "disable",
		})

		_, err := loadHostKeys(ctx)
		if err == nil {
			t.Fatal("expected error when no cert matches key, got nil")
		}
		if !strings.Contains(err.Error(), "no host certificate") {
			t.Errorf("expected 'no host certificate' in error, got: %v", err)
		}
	})

	t.Run("file key errors when matched cert fails to load", func(t *testing.T) {
		// a user cert matches the fingerprint but has wrong cert type
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          "",
			"server-cert":              userCertPath,
			"server-key":               keyPath,
			"server-key-generate-mode": "disable",
		})

		_, err := loadHostKeys(ctx)
		if err == nil {
			t.Fatal("expected error when cert fails to load, got nil")
		}
		if !strings.Contains(err.Error(), "not a host certificate") {
			t.Errorf("expected 'not a host certificate' in error, got: %v", err)
		}
	})

	t.Run("file key loads cert successfully", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          "",
			"server-cert":              matchingCertPath,
			"server-key":               keyPath,
			"server-key-generate-mode": "disable",
		})

		signers, err := loadHostKeys(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(signers) == 0 {
			t.Fatal("expected at least one signer")
		}
		if !strings.Contains(signers[0].PublicKey().Type(), "cert") {
			t.Errorf("expected cert key type, got %v", signers[0].PublicKey().Type())
		}
	})

	t.Run("base64 key errors when no cert matches fingerprint", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          keyToBase64(t, keyPath),
			"server-cert":              otherCertPath,
			"server-key":               "",
			"server-key-generate-mode": "disable",
		})

		_, err := loadHostKeys(ctx)
		if err == nil {
			t.Fatal("expected error when no cert matches base64 key, got nil")
		}
		if !strings.Contains(err.Error(), "no host certificate") {
			t.Errorf("expected 'no host certificate' in error, got: %v", err)
		}
	})

	t.Run("base64 key errors when matched cert fails to load", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          keyToBase64(t, keyPath),
			"server-cert":              userCertPath,
			"server-key":               "",
			"server-key-generate-mode": "disable",
		})

		_, err := loadHostKeys(ctx)
		if err == nil {
			t.Fatal("expected error when cert fails to load, got nil")
		}
		if !strings.Contains(err.Error(), "not a host certificate") {
			t.Errorf("expected 'not a host certificate' in error, got: %v", err)
		}
	})

	t.Run("base64 key loads cert successfully", func(t *testing.T) {
		ctx := newTestCLIContext(t, map[string]string{
			"server-key-data":          keyToBase64(t, keyPath),
			"server-cert":              matchingCertPath,
			"server-key":               "",
			"server-key-generate-mode": "disable",
		})

		signers, err := loadHostKeys(ctx)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(signers) == 0 {
			t.Fatal("expected at least one signer")
		}
		if !strings.Contains(signers[0].PublicKey().Type(), "cert") {
			t.Errorf("expected cert key type, got %v", signers[0].PublicKey().Type())
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %v: %v", path, err)
	}

	return data
}
