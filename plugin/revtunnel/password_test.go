//go:build full || e2e

package main

import (
	"testing"
	"time"
)

func TestEnvTruthy(t *testing.T) {
	for _, v := range []string{"", "1", "true", "TRUE", "yes", "On", " 1 "} {
		if !envTruthy(v) {
			t.Errorf("envTruthy(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "off", "nope"} {
		if envTruthy(v) {
			t.Errorf("envTruthy(%q) = true, want false", v)
		}
	}
}

// TestPasswordCallback verifies that connect-side password auth is refused
// unless the tunnel record has AllowPassword set, and that when allowed the
// offered password is forwarded to the upstream target unchanged.
func TestPasswordCallback(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	srv, err := newRegisterServer(reg, "")
	if err != nil {
		t.Fatalf("newRegisterServer: %v", err)
	}
	cfg := buildPluginConfig(reg, srv)
	if cfg.PasswordCallback == nil {
		t.Fatal("PasswordCallback must always be registered")
	}

	const guid = "guid-pw"
	rec := record{
		Guid:         guid,
		TargetUser:   "alice",
		BindAddr:     "host",
		BindPort:     22,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	if err := reg.Put(rec, nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Unknown guid → error.
	if _, err := cfg.PasswordCallback(fakeMeta{user: "nope"}, []byte("pw")); err == nil {
		t.Fatal("password auth for unknown guid should fail")
	}

	// Known guid but password not allowed → error.
	if _, err := cfg.PasswordCallback(fakeMeta{user: guid}, []byte("pw")); err == nil {
		t.Fatal("password auth must be refused until ALLOWPASSWORD is set")
	}

	// Enable password auth (as the ALLOWPASSWORD env would) and retry.
	if !reg.UpdateAllowPassword(guid, true) {
		t.Fatal("UpdateAllowPassword returned false for a live guid")
	}
	up, err := cfg.PasswordCallback(fakeMeta{user: guid}, []byte("s3cret"))
	if err != nil {
		t.Fatalf("password auth should succeed once allowed: %v", err)
	}
	if up.UserName != "alice" {
		t.Fatalf("upstream user = %q, want alice", up.UserName)
	}
	pw := up.GetPassword()
	if pw == nil {
		t.Fatal("upstream auth is not password auth")
	}
	if pw.GetPassword() != "s3cret" {
		t.Fatalf("forwarded password = %q, want s3cret", pw.GetPassword())
	}
	if up.Uri != connectScheme+"://"+guid {
		t.Fatalf("uri = %q, want %s://%s", up.Uri, connectScheme, guid)
	}
}
