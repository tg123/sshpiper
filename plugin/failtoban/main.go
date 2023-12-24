//go:build full || e2e

package main

import (
	"fmt"
	"net"
	"time"

	gocache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "failtoban",
		Usage: "sshpiperd fixed plugin, only password auth is supported",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "max-failures",
				Usage:   "max failures",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_MAX_FAILURES"},
				Value:   5,
			},
			&cli.DurationFlag{
				Name:    "ban-duration",
				Usage:   "ban duration",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_BAN_DURATION"},
				Value:   60 * time.Minute,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			maxFailures := c.Int("max-failures")
			banDuration := c.Duration("ban-duration")

			cache := gocache.New(banDuration, banDuration/2*3)

			return &libplugin.SshPiperPluginConfig{
				NoClientAuthCallback: func(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
					// in case someone put the failtoban plugin before other plugins
					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{}),
					}, nil
				},
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())

					failed, found := cache.Get(ip)
					if !found {
						// init
						return cache.Add(ip, 0, banDuration)
					}

					if failed.(int) >= maxFailures {
						return fmt.Errorf("failtoban: ip %v too auth many failures", ip)
					}

					return nil
				},
				UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowmethods []string) {
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					failed, _ := cache.IncrementInt(ip, 1)
					log.Debugf("failtoban: %v auth failed. current status: fail %v times, max allowed %v", ip, failed, maxFailures)
				},
				PipeCreateErrorCallback: func(remoteAddr string, err error) {
					ip, _, _ := net.SplitHostPort(remoteAddr)
					failed, _ := cache.IncrementInt(ip, 1)
					log.Debugf("failtoban: %v pipe create failed, reason %v. current status: fail %v times, max allowed %v", ip, err, failed, maxFailures)
				},
			}, nil
		},
	})
}
