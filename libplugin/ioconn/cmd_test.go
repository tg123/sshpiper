//go:build linux

package ioconn_test

import (
	"os/exec"
	"testing"

	"github.com/tg123/sshpiper/libplugin/ioconn"
)

func TestDialCmd(t *testing.T) {
	cmd := exec.Command("cat")

	conn, _, err := ioconn.DialCmd(cmd)
	if err != nil {
		t.Errorf("DialCmd returned an error: %v", err)
	}
	defer conn.Close()

	go conn.Write([]byte("world"))
	buf := make([]byte, 5)
	conn.Read(buf)

	if string(buf) != "world" {
		t.Errorf("unexpected string read: %v", string(buf))
	}
}
