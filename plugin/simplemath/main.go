package main

import (
	"fmt"
	"math/rand"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "simplemath",
		Usage: "sshpiperd simplemath plugin, do math before ssh login",
		CreateConfig: func(_ *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
					_, _ = client("", "lets do math", "", false)

					for {

						a := rand.Intn(10)
						b := rand.Intn(10)

						ans, err := client("", "", fmt.Sprintf("what is %v + %v = ", a, b), true)
						if err != nil {
							return nil, err
						}

						log.Printf("got ans = %v", ans)

						if ans == fmt.Sprintf("%v", a+b) {

							log.Printf("got ans = %v", ans)

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
			}, nil
		},
	})
}
