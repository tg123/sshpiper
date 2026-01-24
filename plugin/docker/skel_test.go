//go:build full || e2e

package main

import (
	"encoding/base64"
	"testing"
)

func TestTrustedUserCAKeysDecode(t *testing.T) {
	ca := "ca-key"

	p := pipe{
		TrustedUserCAKeys: base64.StdEncoding.EncodeToString([]byte(ca)),
		PrivateKey:        base64.StdEncoding.EncodeToString([]byte("key")),
	}

	w := skelpipeWrapper{pipe: &p}

	froms := w.From()
	if len(froms) != 1 {
		t.Fatalf("expected one from wrapper, got %d", len(froms))
	}

	pub, ok := froms[0].(*skelpipePublicKeyWrapper)
	if !ok {
		t.Fatalf("expected public key wrapper, got %T", froms[0])
	}

	data, err := pub.TrustedUserCAKeys(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(data) != ca {
		t.Fatalf("unexpected trusted ca data, got %q", string(data))
	}
}

func TestTrustedUserCAKeysDecodeError(t *testing.T) {
	p := pipe{
		TrustedUserCAKeys: "!!not-base64!!",
		PrivateKey:        base64.StdEncoding.EncodeToString([]byte("key")),
	}

	w := skelpipeWrapper{pipe: &p}

	froms := w.From()
	if len(froms) != 1 {
		t.Fatalf("expected one from wrapper, got %d", len(froms))
	}

	pub, ok := froms[0].(*skelpipePublicKeyWrapper)
	if !ok {
		t.Fatalf("expected public key wrapper, got %T", froms[0])
	}

	if _, err := pub.TrustedUserCAKeys(nil); err == nil {
		t.Fatalf("expected decode error, got nil")
	}
}

func TestDockerSshdUsesContainerID(t *testing.T) {
	p := pipe{
		ContainerUsername: "container-id",
		Host:              "127.0.0.1:2232",
		AuthorizedKeys:    base64.StdEncoding.EncodeToString([]byte("key")),
		PrivateKey:        base64.StdEncoding.EncodeToString([]byte("mapping")),
	}

	w := skelpipeWrapper{pipe: &p}
	froms := w.From()
	if len(froms) != 1 {
		t.Fatalf("expected one from wrapper, got %d", len(froms))
	}

	pub, ok := froms[0].(*skelpipePublicKeyWrapper)
	if !ok {
		t.Fatalf("expected public key wrapper, got %T", froms[0])
	}

	to, err := pub.MatchConn(nil)
	if err != nil {
		t.Fatalf("unexpected match error: %v", err)
	}
	if to == nil {
		t.Fatal("expected match result, got nil")
	}

	if to.User(nil) != "container-id" {
		t.Fatalf("expected container username, got %q", to.User(nil))
	}

	if to.Host(nil) != "127.0.0.1:2232" {
		t.Fatalf("expected docker-sshd host, got %q", to.Host(nil))
	}
}
