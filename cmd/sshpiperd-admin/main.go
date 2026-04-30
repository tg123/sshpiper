// Package main implements sshpiperd-admin, a small command-line client for
// the sshpiperd admin gRPC API.
//
// It complements sshpiperd-webadmin (the browser UI) by offering an
// ssh-style/kubectl-style CLI for operators and scripts:
//
//	sshpiperd-admin --sshpiperd 127.0.0.1:8082 list
//	sshpiperd-admin --sshpiperd 127.0.0.1:8082 kill <session-id>
//	sshpiperd-admin --sshpiperd 127.0.0.1:8082 stream <session-id>
//
// Multiple --sshpiperd endpoints may be provided; in that case session ids
// are routed to the correct backend either automatically (when the id is
// unique across instances) or via the explicit --instance flag.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"
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
		Name:        "sshpiperd-admin",
		Usage:       "command-line client for the sshpiperd admin gRPC API",
		Description: "sshpiperd-admin connects to one or more sshpiperd admin gRPC endpoints and lets operators list, kill, and live-stream SSH sessions from the shell.\nhttps://github.com/tg123/sshpiper",
		Version:     version(),
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "sshpiperd",
				Usage:   "address of a sshpiperd admin gRPC endpoint (host:port). Repeat for multiple instances",
				EnvVars: []string{"SSHPIPERD_ADMIN_ENDPOINTS"},
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Value:   true,
				Usage:   "use plaintext gRPC when connecting to sshpiperd admin endpoints",
				EnvVars: []string{"SSHPIPERD_ADMIN_INSECURE"},
			},
			&cli.StringFlag{
				Name:    "tls-cacert",
				Usage:   "CA cert used to verify sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_ADMIN_TLS_CACERT"},
			},
			&cli.StringFlag{
				Name:    "tls-cert",
				Usage:   "client cert used when connecting to sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_ADMIN_TLS_CERT"},
			},
			&cli.StringFlag{
				Name:    "tls-key",
				Usage:   "client key used when connecting to sshpiperd admin TLS endpoints; ignored when --insecure",
				EnvVars: []string{"SSHPIPERD_ADMIN_TLS_KEY"},
			},
			&cli.StringFlag{
				Name:    "tls-server-name",
				Usage:   "override the SNI / TLS verification hostname for sshpiperd admin endpoints",
				EnvVars: []string{"SSHPIPERD_ADMIN_TLS_SERVER_NAME"},
			},
			&cli.DurationFlag{
				Name:    "timeout",
				Value:   15 * time.Second,
				Usage:   "per-RPC timeout for non-streaming admin calls",
				EnvVars: []string{"SSHPIPERD_ADMIN_TIMEOUT"},
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "warn",
				Usage:   "log level: trace, debug, info, warn, error",
				EnvVars: []string{"SSHPIPERD_ADMIN_LOG_LEVEL"},
			},
		},
		Before: func(ctx *cli.Context) error {
			lvl, err := log.ParseLevel(ctx.String("log-level"))
			if err != nil {
				return err
			}
			log.SetLevel(lvl)
			return nil
		},
		Commands: []*cli.Command{
			listCommand(),
			killCommand(),
			streamCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// resolveEndpoints returns the configured admin endpoint list, falling back
// to a comma-separated env var for parity with sshpiperd-webadmin.
func resolveEndpoints(ctx *cli.Context) ([]string, error) {
	endpoints := ctx.StringSlice("sshpiperd")
	if len(endpoints) == 0 {
		if env := os.Getenv("SSHPIPERD_ADMIN_ENDPOINTS"); env != "" {
			for _, e := range strings.Split(env, ",") {
				if e = strings.TrimSpace(e); e != "" {
					endpoints = append(endpoints, e)
				}
			}
		}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no sshpiperd endpoints configured: pass --sshpiperd <addr> at least once or set SSHPIPERD_ADMIN_ENDPOINTS")
	}
	return endpoints, nil
}

func dialOpts(ctx *cli.Context) libadmin.DialOptions {
	return libadmin.DialOptions{
		Insecure:   ctx.Bool("insecure"),
		CAFile:     ctx.String("tls-cacert"),
		CertFile:   ctx.String("tls-cert"),
		KeyFile:    ctx.String("tls-key"),
		ServerName: ctx.String("tls-server-name"),
	}
}

// newAggregator dials every configured endpoint and refreshes ServerInfo.
// The caller owns the returned Aggregator and must Close it.
func newAggregator(ctx *cli.Context) (*libadmin.Aggregator, error) {
	endpoints, err := resolveEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	agg := libadmin.NewAggregator(libadmin.NewStaticDiscovery(endpoints), dialOpts(ctx))

	rctx, cancel := context.WithTimeout(ctx.Context, ctx.Duration("timeout"))
	defer cancel()
	if _, errs := agg.Refresh(rctx); len(errs) > 0 {
		// ServerInfo failures are warnings rather than fatal so that the
		// CLI remains useful when one of several endpoints is down. If
		// every endpoint failed, downstream calls will surface the error.
		for _, e := range errs {
			log.Warnf("refresh: %v", e)
		}
		if len(agg.Instances()) == 0 {
			_ = agg.Close()
			return nil, fmt.Errorf("no sshpiperd admin endpoints reachable")
		}
	}
	return agg, nil
}

func listCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list active sessions across all configured sshpiperd instances",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "emit JSON instead of a human-readable table",
			},
		},
		Action: func(ctx *cli.Context) error {
			agg, err := newAggregator(ctx)
			if err != nil {
				return err
			}
			defer agg.Close()

			rctx, cancel := context.WithTimeout(ctx.Context, ctx.Duration("timeout"))
			defer cancel()
			sessions, errs := agg.ListAllSessions(rctx)
			for _, e := range errs {
				log.Warnf("list: %v", e)
			}

			if ctx.Bool("json") {
				out := make([]map[string]any, 0, len(sessions))
				for _, s := range sessions {
					out = append(out, map[string]any{
						"instance_id":     s.InstanceID,
						"instance_addr":   s.InstanceAddr,
						"id":              s.Session.GetId(),
						"downstream_user": s.Session.GetDownstreamUser(),
						"downstream_addr": s.Session.GetDownstreamAddr(),
						"upstream_user":   s.Session.GetUpstreamUser(),
						"upstream_addr":   s.Session.GetUpstreamAddr(),
						"started_at":      s.Session.GetStartedAt(),
						"streamable":      s.Session.GetStreamable(),
					})
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "INSTANCE\tSESSION ID\tDOWNSTREAM\tUPSTREAM\tSTARTED\tSTREAMABLE")
			for _, s := range sessions {
				started := time.Unix(s.Session.GetStartedAt(), 0).UTC().Format(time.RFC3339)
				fmt.Fprintf(tw, "%s\t%s\t%s@%s\t%s@%s\t%s\t%v\n",
					s.InstanceID,
					s.Session.GetId(),
					s.Session.GetDownstreamUser(), s.Session.GetDownstreamAddr(),
					s.Session.GetUpstreamUser(), s.Session.GetUpstreamAddr(),
					started,
					s.Session.GetStreamable(),
				)
			}
			return tw.Flush()
		},
	}
}

// resolveInstance returns the instance id that hosts sessionID. When the
// caller passes an explicit --instance it is used verbatim; otherwise the
// aggregator is queried and the call succeeds only when exactly one
// instance reports a session with that id.
func resolveInstance(ctx *cli.Context, agg *libadmin.Aggregator, sessionID string) (string, error) {
	if explicit := ctx.String("instance"); explicit != "" {
		return explicit, nil
	}

	rctx, cancel := context.WithTimeout(ctx.Context, ctx.Duration("timeout"))
	defer cancel()
	sessions, errs := agg.ListAllSessions(rctx)
	for _, e := range errs {
		log.Warnf("resolve: %v", e)
	}

	var matches []string
	for _, s := range sessions {
		if s.Session.GetId() == sessionID {
			matches = append(matches, s.InstanceID)
		}
	}
	switch len(matches) {
	case 0:
		// Fall back to the only configured instance, if any. This keeps the
		// CLI ergonomic in the common single-piper deployment even when the
		// session id is wrong (the subsequent RPC will surface the error).
		if instances := agg.Instances(); len(instances) == 1 {
			for id := range instances {
				return id, nil
			}
		}
		return "", fmt.Errorf("session %q not found on any configured sshpiperd instance; pass --instance to disambiguate", sessionID)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("session %q is reported by multiple instances %v; pass --instance to disambiguate", sessionID, matches)
	}
}

func killCommand() *cli.Command {
	return &cli.Command{
		Name:      "kill",
		Usage:     "kill an active session",
		ArgsUsage: "<session-id>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "instance",
				Usage: "id of the sshpiperd instance hosting the session (auto-detected when omitted)",
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() != 1 {
				return fmt.Errorf("expected exactly one <session-id> argument")
			}
			sessionID := ctx.Args().First()

			agg, err := newAggregator(ctx)
			if err != nil {
				return err
			}
			defer agg.Close()

			instance, err := resolveInstance(ctx, agg, sessionID)
			if err != nil {
				return err
			}

			rctx, cancel := context.WithTimeout(ctx.Context, ctx.Duration("timeout"))
			defer cancel()
			killed, err := agg.KillSession(rctx, instance, sessionID)
			if err != nil {
				return fmt.Errorf("kill %s/%s: %w", instance, sessionID, err)
			}
			if !killed {
				return fmt.Errorf("session %s/%s not found", instance, sessionID)
			}
			fmt.Fprintf(os.Stdout, "killed %s on %s\n", sessionID, instance)
			return nil
		},
	}
}

func streamCommand() *cli.Command {
	return &cli.Command{
		Name:      "stream",
		Usage:     "stream live screen output of an active session",
		ArgsUsage: "<session-id>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "instance",
				Usage: "id of the sshpiperd instance hosting the session (auto-detected when omitted)",
			},
			&cli.BoolFlag{
				Name:  "replay",
				Value: true,
				Usage: "replay the cached header frame(s) before switching to live streaming",
			},
			&cli.StringFlag{
				Name:  "format",
				Value: "raw",
				Usage: "output format: 'raw' (write upstream output bytes to stdout) or 'asciicast' (asciicast v2 JSON, one record per line)",
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() != 1 {
				return fmt.Errorf("expected exactly one <session-id> argument")
			}
			sessionID := ctx.Args().First()

			format := strings.ToLower(ctx.String("format"))
			switch format {
			case "raw", "asciicast":
			default:
				return fmt.Errorf("unknown --format %q (want raw or asciicast)", format)
			}

			agg, err := newAggregator(ctx)
			if err != nil {
				return err
			}
			defer agg.Close()

			instance, err := resolveInstance(ctx, agg, sessionID)
			if err != nil {
				return err
			}

			// Streaming RPCs run for as long as the session is alive, so
			// the per-call timeout is intentionally not applied here;
			// cancel via the parent context (Ctrl-C).
			err = agg.StreamSession(ctx.Context, instance, sessionID, ctx.Bool("replay"), streamHandler(format))
			if err != nil && ctx.Err() == nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fmt.Errorf("stream %s/%s: %w", instance, sessionID, err)
			}
			return nil
		},
	}
}

// streamHandler returns a frame handler that writes session frames to
// stdout in the requested format.
func streamHandler(format string) func(*libadmin.SessionFrame) error {
	if format == "asciicast" {
		// asciicast v2: first line is the header object, subsequent lines
		// are [time, kind, data] arrays. We emit one JSON value per line.
		var headerEmitted bool
		var t0 float64
		return func(frame *libadmin.SessionFrame) error {
			if hdr := frame.GetHeader(); hdr != nil {
				obj := map[string]any{
					"version":   2,
					"width":     hdr.GetWidth(),
					"height":    hdr.GetHeight(),
					"timestamp": hdr.GetTimestamp(),
					"env":       hdr.GetEnv(),
				}
				if !headerEmitted {
					t0 = float64(hdr.GetTimestamp())
					headerEmitted = true
				}
				return writeJSONLine(obj)
			}
			if ev := frame.GetEvent(); ev != nil {
				// asciicast v2 records use seconds since header.timestamp.
				// The admin proto already exposes "time" as that delta;
				// fall back to a wall-clock-derived value when zero.
				ts := ev.GetTime()
				if ts == 0 && headerEmitted {
					ts = float64(time.Now().Unix()) - t0
				}
				return writeJSONLine([]any{ts, ev.GetKind(), string(ev.GetData())})
			}
			return nil
		}
	}

	// "raw": only forward upstream output ("o") bytes to stdout, mirroring
	// what an attached terminal would have seen. Other event kinds and
	// header frames are dropped, which makes piping into a real terminal
	// (or `tee file.log`) Just Work.
	return func(frame *libadmin.SessionFrame) error {
		ev := frame.GetEvent()
		if ev == nil {
			return nil
		}
		if ev.GetKind() != "o" {
			return nil
		}
		_, err := os.Stdout.Write(ev.GetData())
		return err
	}
}

func writeJSONLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = os.Stdout.Write(b)
	return err
}
