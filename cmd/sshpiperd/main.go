package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"time"

	"github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"github.com/urfave/cli/v2"
)

var mainver string = "(devel)"

func version() string {

	var v = mainver

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v = fmt.Sprintf("%v, %v", v, s.Value[:9])
		case "vcs.time":
			v = fmt.Sprintf("%v, %v", v, s.Value)
		}
	}

	v = fmt.Sprintf("%v, %v", v, bi.GoVersion)

	return v
}

func splitByDash(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}

	return args, nil
}

func createPlugin(args []string) (*plugin.GrpcPlugin, error) {
	exe := args[0]

	switch exe {
	case "grpc":
		log.Info("starting net grpc plugin: ")
		return createNetGrpcPlugin(args)

	default:
		cmd := exec.Command(exe)
		cmd.Args = args
		setPdeathsig(cmd)

		log.Info("starting child process plugin: ", cmd.Args)

		p, err := plugin.DialCmd(cmd)
		if err != nil {
			return nil, err
		}

		p.Name = exe

		return &p.GrpcPlugin, nil
	}
}

func main() {

	app := &cli.App{
		Name:        "sshpiperd",
		Usage:       "the missing reverse proxy for ssh scp",
		UsageText:   "sshpiperd [options] <plugin1> [plugin options] [-- [plugin2] [plugin options] [-- ...]]",
		Description: "sshpiperd works as a proxy-like ware, and route connections by username, src ip , etc.\nhttps://github.com/tg123/sshpiper",
		Version:     version(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "address",
				Aliases: []string{"l"},
				Value:   "0.0.0.0",
				Usage:   "listening address",
				EnvVars: []string{"SSHPIPERD_ADDRESS"},
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   2222,
				Usage:   "listening port",
				EnvVars: []string{"SSHPIPERD_PORT"},
			},
			&cli.StringFlag{
				Name:    "server-key",
				Aliases: []string{"i"},
				Usage:   "server key files, support wildcard",
				Value:   "/etc/ssh/ssh_host_rsa_key",
				EnvVars: []string{"SSHPIPERD_SERVER_KEY"},
			},
			&cli.DurationFlag{
				Name:    "login-grace-time",
				Value:   30 * time.Second,
				Usage:   "sshpiperd forcely close the connection after this time if the pipe has not successfully established",
				EnvVars: []string{"SSHPIPERD_LOGIN_GRACE_TIME"},
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Usage:   "log level, one of: trace, debug, info, warn, error, fatal, panic",
				EnvVars: []string{"SSHPIPERD_LOG_LEVEL"},
			},
			&cli.StringFlag{
				Name:    "typescript-log-dir",
				Value:   "",
				Usage:   "create typescript format screen recording and save into the directory see https://linux.die.net/man/1/script",
				EnvVars: []string{"SSHPIPERD_TYPESCRIPT_LOG_DIR"},
			},
		},
		Action: func(ctx *cli.Context) error {
			level, err := log.ParseLevel(ctx.String("log-level"))
			if err != nil {
				return err
			}

			log.SetLevel(level)

			log.Info("starting sshpiperd version: ", version())
			d, err := newDaemon(ctx)

			if err != nil {
				return err
			}

			d.lis = &proxyproto.Listener{Listener: d.lis}

			var plugins []*plugin.GrpcPlugin

			args := ctx.Args().Slice()
			remain := args

			for {
				if len(remain) <= 0 {
					break
				}

				args, remain = splitByDash(remain)

				if len(args) <= 0 {
					continue
				}

				p, err := createPlugin(args)
				if err != nil {
					return err
				}

				go func() {
					if err := p.RecvLogs(log.StandardLogger().Out); err != nil {
						log.Errorf("plugin %v recv logs error: %v", p.Name, err)
					}
				}()
				plugins = append(plugins, p)
			}

			if err := d.install(plugins...); err != nil {
				return err
			}

			d.recorddir = ctx.String("typescript-log-dir")

			return d.run()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
