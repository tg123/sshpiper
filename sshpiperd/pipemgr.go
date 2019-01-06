package main

import (
	"fmt"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"os"
	"text/template"
)

func createPipeMgr(load func() (upstream.Provider, error)) interface{} {
	// pipe management
	pipeMgrCmd := struct {
		List struct {
			subCommand
		} `command:"list" description:"list all pipes"`
		Add struct {
			subCommand

			PiperUserName string `short:"n" long:"piper-username" description:"" required:"true" no-ini:"true"`
			// PiperAuthorizedKeysFile flags.Filename

			UpstreamUserName string `long:"upstream-username" description:"mapped user name" no-ini:"true"`
			UpstreamHost     string `short:"u" long:"host" description:"upstream sshd host" required:"true" no-ini:"true"`
			UpstreamPort     int    `short:"p" long:"port" description:"upstream sshd port" default:"22" no-ini:"true"`
			// UpstreamKeyFile  flags.Filename

			// UpstreamHostKey
			// MapType

		} `command:"add" description:"add a pipe to current upstream"`
		Remove struct {
			subCommand

			Name string `short:"n" long:"piper-username" required:"true" no-ini:"true"`
		} `command:"remove" description:"remove a pipe from current upstream"`
	}{}

	pipeMgrCmd.List.callback = func(args []string) error {
		p, err := load()
		if err != nil {
			return err
		}

		// opt := pipeMgrCmd.List
		pipes, err := p.ListPipe()
		if err != nil {
			return err
		}

		t := template.Must(template.New("").Parse(`{{.Username}} -> {{.UpstreamUsername}}@{{.Host}}:{{.Port}}`))

		for _, pipe := range pipes {
			t.Execute(os.Stdout, pipe)
			fmt.Println()
		}

		return nil
	}

	pipeMgrCmd.Add.callback = func(args []string) error {
		p, err := load()
		if err != nil {
			return err
		}

		opt := pipeMgrCmd.Add

		return p.CreatePipe(upstream.CreatePipeOption{
			Username:         opt.PiperUserName,
			UpstreamUsername: opt.UpstreamUserName,
			Host:             opt.UpstreamHost,
			Port:             opt.UpstreamPort,
		})
	}

	pipeMgrCmd.Remove.callback = func(args []string) error {
		p, err := load()
		if err != nil {
			return err
		}

		opt := pipeMgrCmd.Remove

		return p.RemovePipe(opt.Name)
	}

	return &pipeMgrCmd
}
