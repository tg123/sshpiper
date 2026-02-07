package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

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
