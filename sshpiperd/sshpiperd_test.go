package main

import (
	"testing"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

func Test_getAndInstall(t *testing.T) {

	// ignore empty
	getAndInstall("", func(n string) registry.Plugin {
		t.Errorf("should not call get")
		return nil
	}, func(plugin registry.Plugin) {
		t.Errorf("should not call install")
	})


}
