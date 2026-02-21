//go:build full || e2e

package main

import (
	"bytes"
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
		dockerSshdPrivateKeys:    map[string]string{},
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

func TestRegisterDockerSshdContainerReusesExistingKeyMapping(t *testing.T) {
	p := &plugin{
		dockerSshdCmds:           map[string]string{},
		dockerSshdKeys:           map[string][]byte{},
		dockerSshdPrivateKeys:    map[string]string{},
		dockerSshdKeyToContainer: map[string]string{},
	}

	firstB64, err := p.registerDockerSshdContainer("cid", "")
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	firstKey, err := base64.StdEncoding.DecodeString(firstB64)
	if err != nil {
		t.Fatalf("decode first key failed: %v", err)
	}
	firstSigner, err := ssh.ParsePrivateKey(firstKey)
	if err != nil {
		t.Fatalf("parse first key failed: %v", err)
	}

	secondB64, err := p.registerDockerSshdContainer("cid", "")
	if err != nil {
		t.Fatalf("second register failed: %v", err)
	}
	secondKey, err := base64.StdEncoding.DecodeString(secondB64)
	if err != nil {
		t.Fatalf("decode second key failed: %v", err)
	}
	secondSigner, err := ssh.ParsePrivateKey(secondKey)
	if err != nil {
		t.Fatalf("parse second key failed: %v", err)
	}

	if !bytes.Equal(firstSigner.PublicKey().Marshal(), secondSigner.PublicKey().Marshal()) {
		t.Fatalf("expected key reuse on re-register, got different keys")
	}

	if len(p.dockerSshdKeyToContainer) != 1 {
		t.Fatalf("expected single key mapping, got %d", len(p.dockerSshdKeyToContainer))
	}

	if got := p.dockerSshdKeyToContainer[string(secondSigner.PublicKey().Marshal())]; got != "cid" {
		t.Fatalf("expected new key mapping for cid, got %q", got)
	}
}

func TestSyncDockerSshdStateRemovesStaleContainerMappings(t *testing.T) {
	p := &plugin{
		dockerSshdCmds:           map[string]string{},
		dockerSshdKeys:           map[string][]byte{},
		dockerSshdPrivateKeys:    map[string]string{},
		dockerSshdKeyToContainer: map[string]string{},
	}

	activeKey, err := p.registerDockerSshdContainer("active", "")
	if err != nil {
		t.Fatalf("register active failed: %v", err)
	}
	staleKey, err := p.registerDockerSshdContainer("stale", "/bin/ash")
	if err != nil {
		t.Fatalf("register stale failed: %v", err)
	}

	p.syncDockerSshdState(map[string]struct{}{
		"active": {},
	})

	if _, ok := p.dockerSshdPrivateKeys["stale"]; ok {
		t.Fatalf("expected stale private key to be removed")
	}
	if _, ok := p.dockerSshdKeys["stale"]; ok {
		t.Fatalf("expected stale public key to be removed")
	}
	if _, ok := p.dockerSshdCmds["stale"]; ok {
		t.Fatalf("expected stale command to be removed")
	}
	stalePriv, err := base64.StdEncoding.DecodeString(staleKey)
	if err != nil {
		t.Fatalf("decode stale key failed: %v", err)
	}
	staleSigner, err := ssh.ParsePrivateKey(stalePriv)
	if err != nil {
		t.Fatalf("parse stale key failed: %v", err)
	}
	if _, ok := p.dockerSshdKeyToContainer[string(staleSigner.PublicKey().Marshal())]; ok {
		t.Fatalf("expected stale key routing to be removed")
	}

	activePriv, err := base64.StdEncoding.DecodeString(activeKey)
	if err != nil {
		t.Fatalf("decode active key failed: %v", err)
	}
	activeSigner, err := ssh.ParsePrivateKey(activePriv)
	if err != nil {
		t.Fatalf("parse active key failed: %v", err)
	}
	if got := p.dockerSshdKeyToContainer[string(activeSigner.PublicKey().Marshal())]; got != "active" {
		t.Fatalf("expected active key mapping to stay, got %q", got)
	}
}
