//go:build full || e2e

package main

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDockerSshdCmdReturnsDefaultShellWhenContainerNotConfigured(t *testing.T) {
	p := &plugin{
		dockerSshdCmds: map[string]string{},
	}

	if got := p.dockerSshdCmd("missing"); got != "/bin/sh" {
		t.Fatalf("expected /bin/sh, got %q", got)
	}
}

func TestDockerSshdCmdUsesConfiguredValue(t *testing.T) {
	p := &plugin{
		dockerSshdCmds: map[string]string{
			"cid": "/bin/ash",
		},
	}

	if got := p.dockerSshdCmd("cid"); got != "/bin/ash" {
		t.Fatalf("expected configured command, got %q", got)
	}
}

func TestGenerateDockerSshdPrivateKey(t *testing.T) {
	b64, err := generateDockerSshdPrivateKey()
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}

	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode key failed: %v", err)
	}

	if _, err := ssh.ParsePrivateKey(key); err != nil {
		t.Fatalf("generated key is not parseable: %v", err)
	}
}

func TestRegisterDockerSshdContainerAlwaysGeneratesKey(t *testing.T) {
	p := &plugin{
		dockerSshdCmds:           map[string]string{},
		dockerSshdKeys:           map[string][]byte{},
		dockerSshdKeyToContainer: map[string]string{},
	}

	b64, err := p.registerDockerSshdContainer("cid", "/bin/ash")
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode key failed: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatalf("registered key is not parseable: %v", err)
	}

	if got := p.dockerSshdCmd("cid"); got != "/bin/ash" {
		t.Fatalf("expected configured command, got %q", got)
	}

	if _, ok := p.dockerSshdKeys["cid"]; !ok {
		t.Fatalf("missing key mapping for container")
	}

	if got := p.dockerSshdKeyToContainer[string(signer.PublicKey().Marshal())]; got != "cid" {
		t.Fatalf("unexpected key routing mapping: %q", got)
	}
}
