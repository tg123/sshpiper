//go:build full || e2e

package main

import "testing"

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
