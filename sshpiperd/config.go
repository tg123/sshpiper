// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"flag"
	"os"
	"strings"
	"text/template"

	"github.com/docker/docker/pkg/mflag"
	"github.com/rakyll/globalconf"
)

var (
	config = struct {
		ListenAddr   string
		Port         uint
		WorkingDir   string
		PiperKeyFile string
		ShowHelp     bool
		Challenger   string
		ShowVersion  bool
	}{}

	out = os.Stdout

	configTemplate  *template.Template
	versionTemplate *template.Template
)

func initTemplate() {
	configTemplate = template.Must(template.New("config").Parse(`
Listening             : {{.ListenAddr}}:{{.Port}}
Server Key File       : {{.PiperKeyFile}}
Working Dir           : {{.WorkingDir}}
Additional Challenger : {{.Challenger}}

`[1:]))

	versionTemplate = template.Must(template.New("ver").Parse(`
SSHPiper ver: {{.}} by tgic<farmer1992@gmail.com>
https://github.com/tg123/sshpiper

`[1:]))
}

func init() {

	initTemplate()

	configfile := mflag.String([]string{"-config"}, "/etc/sshpiperd.conf", "Config file path. Note: any option will be overwrite if it is set by commandline")

	mflag.StringVar(&config.ListenAddr, []string{"l", "-listen_addr"}, "0.0.0.0", "Listening Address")
	mflag.UintVar(&config.Port, []string{"p", "-port"}, 2222, "Listening Port")
	mflag.StringVar(&config.WorkingDir, []string{"w", "-working_dir"}, "/var/sshpiper", "Working Dir")
	mflag.StringVar(&config.PiperKeyFile, []string{"i", "-server_key"}, "/etc/ssh/ssh_host_rsa_key", "Key file for SSH Piper")
	mflag.StringVar(&config.Challenger, []string{"c", "-challenger"}, "", "Additional challenger name, e.g. pam, emtpy for no additional challenge")
	mflag.BoolVar(&config.ShowHelp, []string{"h", "-help"}, false, "Print help and exit")
	mflag.BoolVar(&config.ShowVersion, []string{"-version"}, false, "Print version and exit")

	mflag.Parse()

	if _, err := os.Stat(*configfile); os.IsNotExist(err) {
		if !mflag.IsSet("-config") {
			*configfile = ""
		} else {
			logger.Fatalf("config file %v not found", *configfile)
		}
	}

	gconf, err := globalconf.NewWithOptions(&globalconf.Options{
		Filename:  *configfile,
		EnvPrefix: "SSHPIPERD_",
	})

	if err != nil { // this error will happen only if file error
		logger.Fatalln("load config file error %v: %v", *configfile, err)
	}

	// build a dummy flag set for globalconf to parse
	fs := flag.NewFlagSet("", flag.ContinueOnError)

	ignoreSet := make(map[string]bool)
	mflag.Visit(func(f *mflag.Flag) {
		for _, n := range f.Names {
			ignoreSet[n] = true
		}
	})

	// should be ignored
	ignoreSet["-help"] = true
	ignoreSet["-version"] = true

	mflag.VisitAll(func(f *mflag.Flag) {
		for _, n := range f.Names {
			if len(n) < 2 {
				continue
			}

			if !ignoreSet[n] {
				n = strings.TrimPrefix(n, "-")
				fs.Var(f.Value, n, f.Usage)
			}
		}
	})

	gconf.ParseSet("", fs)
}

func showHelp() {
	mflag.Usage()
}

func showVersion() {
	// TODO to build flag
	versionTemplate.Execute(out, "v0.1")
}

func showConfig() {
	configTemplate.Execute(out, config)
}
