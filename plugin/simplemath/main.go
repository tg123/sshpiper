package main

import (
	"fmt"
	"math/rand"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
)

func main() {
	config := libplugin.SshPiperPluginConfig{
		KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
			client("lets do math", "", false)

			for {

				a := rand.Intn(10)
				b := rand.Intn(10)

				ans, err := client("", fmt.Sprintf("what is %v + %v = ", a, b), true)
				if err != nil {
					return nil, err
				}

				log.Printf("got ans = %v", ans)

				if ans == fmt.Sprintf("%v", a+b) {
					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{
							"a":   strconv.Itoa(a),
							"b":   strconv.Itoa(b),
							"ans": ans,
						}),
					}, nil
				}
			}
		},
	}

	p, err := libplugin.NewFromStdio(config)
	if err != nil {
		panic(err)
	}

	libplugin.ConfigStdioLogrus(p, nil)

	log.Printf("starting simple math additional auth")
	panic(p.Serve())
}
