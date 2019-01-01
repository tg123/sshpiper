package main

import (
	"fmt"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

func createPipeMgr(driver *string) interface{} {

	load := func() (upstream.Provider, error) {
		if *driver == "" {
			return nil, fmt.Errorf("must provider upstream driver")
		}

		return upstream.Get(*driver).(upstream.Provider), nil
	}

	// pipe management
	pipeMgrCmd := struct {
		List struct {
			subCommand
		} `command:"list" description:"list all pipes"`
		Add struct {
			subCommand
		} `command:"add" description:"add a pipe to current upstream"`
		Remove struct {
			subCommand
			Name string `long:"name" required:"true"`
		} `command:"remove" description:"remove a pipe from current upstream"`
	}{}

	pipeMgrCmd.List.callback = func(args []string) error {
		return nil
	}

	pipeMgrCmd.Add.callback = func(args []string) error {
		return nil
	}

	pipeMgrCmd.Remove.callback = func(args []string) error {

		p, err := load()

		name := pipeMgrCmd.Remove.Name

		if err != nil {
			return err

		}

		return p.RemovePipe(name)

	}

	return &pipeMgrCmd
}
