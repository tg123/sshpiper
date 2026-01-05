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
