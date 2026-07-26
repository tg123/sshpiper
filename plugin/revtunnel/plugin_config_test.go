//go:build full || e2e

package main

import (
	"net/url"
	"testing"
)

func TestRegistrationUsernameWithFileStore(t *testing.T) {
	store, err := newFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	reg := newRegistry(store)
	srv, err := newRegisterServer(reg, "")
	if err != nil {
		t.Fatalf("newRegisterServer: %v", err)
	}
	defer srv.ln.Close()

	cfg := buildPluginConfig(reg, srv)
	up, err := cfg.PublicKeyCallback(
		fakeMeta{user: "alice@example.com"},
		makeMinimalEd25519WireKey(),
	)
	if err != nil {
		t.Fatalf("registration username must not be looked up as a persisted guid: %v", err)
	}
	u, err := url.Parse(up.Uri)
	if err != nil {
		t.Fatalf("parse registration URI: %v", err)
	}
	if u.Scheme != registerScheme {
		t.Fatalf("URI scheme = %q, want %q", u.Scheme, registerScheme)
	}
}

func TestIsGeneratedGUID(t *testing.T) {
	const guid = "123e4567-e89b-12d3-a456-426614174000"
	if !isGeneratedGUID(guid) {
		t.Fatalf("isGeneratedGUID(%q) = false, want true", guid)
	}
	for _, value := range []string{
		"alice@example.com",
		"123e4567e89b12d3a456426614174000",
		"123E4567-E89B-12D3-A456-426614174000",
	} {
		if isGeneratedGUID(value) {
			t.Errorf("isGeneratedGUID(%q) = true, want false", value)
		}
	}
}

func TestUnknownGeneratedGUIDIsNotRegistration(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	srv, err := newRegisterServer(reg, "")
	if err != nil {
		t.Fatalf("newRegisterServer: %v", err)
	}
	defer srv.ln.Close()

	cfg := buildPluginConfig(reg, srv)
	_, err = cfg.PublicKeyCallback(
		fakeMeta{user: "123e4567-e89b-12d3-a456-426614174000"},
		makeMinimalEd25519WireKey(),
	)
	if err == nil {
		t.Fatal("unknown canonical GUID must be rejected, not treated as registration")
	}
}
