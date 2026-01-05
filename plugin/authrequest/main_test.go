//go:build full || e2e

package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
)

func TestAuthRequestSuccess(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/auth" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	config, err := createAuthRequestConfig(srv.URL, "/auth", time.Second)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	upstream, err := config.PasswordCallback(&libplugin.ConnMeta{
		UserName: "alice",
		FromAddr: "192.168.1.5:2222",
	}, []byte("secret"))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if upstream.GetNextPlugin() == nil {
		t.Fatalf("expected next plugin auth, got %#v", upstream)
	}

	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if gotAuth != expectedAuth {
		t.Fatalf("unexpected auth header %q, expected %q", gotAuth, expectedAuth)
	}
}

func TestAuthRequestFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	config, err := createAuthRequestConfig(srv.URL, "/auth", time.Second)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, err = config.PasswordCallback(&libplugin.ConnMeta{
		UserName: "bob",
		FromAddr: "192.0.2.1:2222",
	}, []byte("bad"))
	if err == nil {
		t.Fatalf("expected error for forbidden response")
	}
}
