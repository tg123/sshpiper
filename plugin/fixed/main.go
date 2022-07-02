package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("no target address provided")
	}

	target := os.Args[1]

	host, port, err := libplugin.SplitHostPortForSSH(target)
	if err != nil {
		panic(err)
	}

	config := libplugin.SshPiperPluginConfig{
		PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
			log.Info("routing to ", target)
			return &libplugin.Upstream{
				Host:          host,
				Port:          int32(port),
				IgnoreHostKey: true,
				Auth:          libplugin.CreatePasswordAuth(password),
			}, nil

		},
	}

	p, err := libplugin.NewFromStdio(config)
	if err != nil {
		panic(err)
	}

	libplugin.ConfigStdioLogrus(p, nil)

	log.Printf("starting fix routing to ssh %v (password only)", target)
	panic(p.Serve())
}
