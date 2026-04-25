// Package main implements sshpiperd-webadmin, an aggregating admin server
// that connects to one or more sshpiperd admin gRPC endpoints and exposes a
// browser-friendly HTTP API and embedded web UI.
//
// It is intentionally a separate binary from sshpiperd so that it can:
//
//   - run on a dedicated host with restricted network access;
//   - manage many sshpiperd instances through a single dashboard; and
//   - share its aggregator/discovery code with a future sshpiperd-admin CLI.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/cmd/sshpiperd-webadmin/internal/aggregator"
	"github.com/tg123/sshpiper/cmd/sshpiperd-webadmin/internal/httpapi"
	"github.com/tg123/sshpiper/libadmin"
	"github.com/urfave/cli/v2"
)

var mainver = "(devel)"

func version() string {
	v := mainver
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 9 {
				v = fmt.Sprintf("%s, %s", v, s.Value[:9])
			}
		}
		v = fmt.Sprintf("%s, %s", v, bi.GoVersion)
	}
	return v
}

func main() {
	app := &cli.App{
		Name:        "sshpiperd-webadmin",
		Usage:       "browser-based admin dashboard for one or more sshpiperd instances",
		Description: "sshpiperd-webadmin connects to sshpiperd admin gRPC endpoints and exposes a unified HTTP UI for listing live SSH sessions, viewing live screen output, and killing sessions.\nhttps://github.com/tg123/sshpiper",
		Version:     version(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "address",
				Aliases: []string{"l"},
				Value:   "127.0.0.1",
				Usage:   "listening address for the HTTP UI",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_ADDRESS"},
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   8080,
				Usage:   "listening port for the HTTP UI",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_PORT"},
			},
			&cli.StringSliceFlag{
				Name:    "sshpiperd",
				Usage:   "address of a sshpiperd admin gRPC endpoint (host:port). Repeat for multiple instances",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_ENDPOINTS"},
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Value:   true,
				Usage:   "use plaintext gRPC when connecting to sshpiperd admin endpoints",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_INSECURE"},
			},
			&cli.StringFlag{
				Name:    "tls-cacert",
				Usage:   "CA cert used to verify sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_TLS_CACERT"},
			},
			&cli.StringFlag{
				Name:    "tls-cert",
				Usage:   "client cert used when connecting to sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_TLS_CERT"},
			},
			&cli.StringFlag{
				Name:    "tls-key",
				Usage:   "client key used when connecting to sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_TLS_KEY"},
			},
			&cli.DurationFlag{
				Name:    "refresh-interval",
				Value:   30 * time.Second,
				Usage:   "how often to refresh the discovered sshpiperd endpoint list and ServerInfo cache",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_REFRESH_INTERVAL"},
			},
			&cli.BoolFlag{
				Name:    "allow-kill",
				Value:   true,
				Usage:   "allow the UI to kill sessions; set to false for read-only deployments",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_ALLOW_KILL"},
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Usage:   "log level: trace, debug, info, warn, error",
				EnvVars: []string{"SSHPIPERD_WEBADMIN_LOG_LEVEL"},
			},
		},
		Action: func(ctx *cli.Context) error {
			lvl, err := log.ParseLevel(ctx.String("log-level"))
			if err != nil {
				return err
			}
			log.SetLevel(lvl)

			endpoints := ctx.StringSlice("sshpiperd")
			// Also accept comma-separated values from the env var to make
			// container deployments easier (single env var with a list).
			// Explicit --sshpiperd flags always take precedence; the env
			// var is only consulted when no flags were provided.
			if len(endpoints) == 0 {
				if envEndpoints := os.Getenv("SSHPIPERD_WEBADMIN_ENDPOINTS"); envEndpoints != "" {
					for _, e := range strings.Split(envEndpoints, ",") {
						if e = strings.TrimSpace(e); e != "" {
							endpoints = append(endpoints, e)
						}
					}
				}
			}
			if len(endpoints) == 0 {
				return fmt.Errorf("no sshpiperd endpoints configured: pass --sshpiperd <addr> at least once or set SSHPIPERD_WEBADMIN_ENDPOINTS")
			}

			discovery := libadmin.NewStaticDiscovery(endpoints)
			dialOpts := libadmin.DialOptions{
				Insecure: ctx.Bool("insecure"),
				CAFile:   ctx.String("tls-cacert"),
				CertFile: ctx.String("tls-cert"),
				KeyFile:  ctx.String("tls-key"),
			}
			agg := aggregator.New(discovery, dialOpts, ctx.Duration("refresh-interval"))
			defer agg.Close()

			// Initial refresh so the first request is served from a populated cache.
			if _, errs := agg.Refresh(context.Background()); len(errs) > 0 {
				for _, e := range errs {
					log.Warnf("initial refresh: %v", e)
				}
			}
			agg.StartBackgroundRefresh()

			handler := httpapi.New(agg, httpapi.Options{
				AllowKill: ctx.Bool("allow-kill"),
				Version:   version(),
			})

			addr := fmt.Sprintf("%s:%d", ctx.String("address"), ctx.Int("port"))
			log.Infof("sshpiperd-webadmin %s listening on http://%s (managing %d sshpiperd endpoints)", version(), addr, len(endpoints))
			srv := &http.Server{
				Addr:              addr,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			return srv.ListenAndServe()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
