//go:build full || e2e

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gocache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "failtoban",
		Usage: "failtoban plugin, block ip after too many auth failures",
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
			&cli.BoolFlag{
				Name:    "log-only",
				Usage:   "log only mode, no ban, useful for working with other tools like fail2ban",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_LOG_ONLY"},
				Value:   false,
			},
			&cli.StringSliceFlag{
				Name:    "ignore-ip",
				Usage:   "ignore ip, will not ban host matches from these ip addresses",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_IGNORE_IP"},
				Value:   cli.NewStringSlice(),
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			maxFailures := c.Int("max-failures")
			banDuration := c.Duration("ban-duration")
			logOnly := c.Bool("log-only")
			ignoreIP := c.StringSlice("ignore-ip")
			var whitelist []*net.IPNet

			cache := gocache.New(banDuration, banDuration/2*3)
			for _, cidr := range ignoreIP {
				currCIDR := cidr

				if !strings.Contains(currCIDR, "/") {
					currCIDR += "/24"
				}

				_, ipv4Net, err := net.ParseCIDR(currCIDR)
				if err != nil {
					log.Debugf("failtoban: error while parsing ignore IP: \n%v", err)
					continue
				}
				whitelist = append(whitelist, ipv4Net)
			}

			// register signal handler
			go func() {
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGHUP)

				for {
					<-sigChan
					cache.Flush()
					log.Info("failtoban: cache reset due to SIGHUP")
				}
			}()

			return &libplugin.SshPiperPluginConfig{
				NoClientAuthCallback: func(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
					// in case someone put the failtoban plugin before other plugins
					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{}),
					}, nil
				},
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					if logOnly {
						return nil
					}

					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())

					for _, ipnet := range whitelist {
						if ipnet.Contains(net.ParseIP(ip)) {
							log.Debugf("failtoban: %v in whitelist, ignored.", ip)
							return nil
						}
					}

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

					for _, ipnet := range whitelist {
						if ipnet.Contains(net.ParseIP(ip)) {
							log.Debugf("failtoban: %v in whitelist, ignored.", ip)
							return
						}
					}

					failed, _ := cache.IncrementInt(ip, 1)
					log.Warnf("failtoban: %v auth failed. current status: fail %v times, max allowed %v", ip, failed, maxFailures)
				},
				PipeCreateErrorCallback: func(remoteAddr string, err error) {
					ip, _, _ := net.SplitHostPort(remoteAddr)

					for _, ipnet := range whitelist {
						if ipnet.Contains(net.ParseIP(ip)) {
							log.Debugf("failtoban: %v in whitelist, ignored.", ip)
							return
						}
					}

					failed, _ := cache.IncrementInt(ip, 1)
					log.Warnf("failtoban: %v pipe create failed, reason %v. current status: fail %v times, max allowed %v", ip, err, failed, maxFailures)
				},
			}, nil
		},
	})
}
