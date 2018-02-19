package main

import (
	//		"fmt"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/loader"
)

type subCommand struct{ callback func(args []string) error }

func (s *subCommand) Execute(args []string) error {
	return s.callback(args)
}

func addSubCommand(parser *flags.Parser, name, desc string, callback func(args []string) error) {
	_, err := parser.AddCommand(name, desc, "", &subCommand{callback})

	if err != nil {
		panic(err)
	}
}

func addOpt(parser *flags.Parser, name string, data interface{}) {
	_, err := parser.AddGroup(name, "", data)

	if err != nil {
		panic(err)
	}
}

func main() {

	parser := flags.NewNamedParser("sshpiperd", flags.Default)
	parser.SubcommandsOptional = true

	// version
	addSubCommand(parser, "version", "show version", func(args []string) error {
		showVersion()
		return nil
	})

    dumpConfig := func(){
		ini := flags.NewIniParser(parser)
		ini.Write(os.Stdout, flags.IniIncludeDefaults)
    }

	// dumpini
	addSubCommand(parser, "dumpconfig", "dump current config ini to stdout", func(args []string) error {
		return nil
	})

	config := &piperdConfig{}
	addOpt(parser, "sshpiperd", config)

	// registry upstream
	//upstreamOpt := make(map[string]interface{})
	for _, n := range upstream.All() {

		u := upstream.Get(n)

		opt := u.GetOpts()

		if opt == nil {
			continue
		}

		_, err := parser.AddGroup("upstream."+u.GetName(), "", opt)

		if err != nil {
			panic(err)
		}

		//upstreamOpt[u.GetName()] = opt
	}

	if _, err := parser.Parse(); err != nil {
		return
	}

	// TODO
	// load from ini
	//ini := flags.NewIniParser(parser)
	//err = ini.ParseFile(globalConfig.Config)

	//fmt.Println(err)

	// start to serve
	if parser.Active == nil {
        showVersion()
        dumpConfig()
        
		startPiper(config)
	}

}
