// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"text/template"

	"github.com/rakyll/globalconf"
	"github.com/spf13/pflag"
)

var version = "DEV"
var githash = "0000000000"

var (
	config = struct {
		ListenAddr       string
		Port             uint
		WorkingDir       string
		PiperKeyFile     string
		ShowHelp         bool
		Challenger       string
		Logfile          string
		ShowVersion      bool
		AllowBadUsername bool
		NoCheckPerm      bool
		RecordTypescript bool
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
Logging file          : {{.Logfile}}

`[1:]))

	versionTemplate = template.Must(template.New("ver").Parse(`
SSHPiper ver: {{.VER}} by Boshi Lian<farmer1992@gmail.com>
https://github.com/tg123/sshpiper

go runtime  : {{.GOVER}}
git hash    : {{.GITHASH}}

`[1:]))
}

func initLogger() {
	// change this value for display might be not a good idea
	if config.Logfile != "" {
		f, err := os.OpenFile(config.Logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.Printf("cannot open log file %v", err)
			config.Logfile = fmt.Sprintf("stdout, fall back from %v", config.Logfile)
			return
		}

		logger = log.New(f, "", logger.Flags())
	} else {
		config.Logfile = "stdout"
	}
}

func initConfig() {
	configfile := pflag.String("config", "/etc/sshpiperd.conf", "Config file path. Note: any option will be overwrite if it is set by commandline")

	pflag.StringVarP(&config.ListenAddr, "listen_addr", "l", "0.0.0.0", "Listening Address")
	pflag.UintVarP(&config.Port, "port", "p", 2222, "Listening Port")
	pflag.StringVarP(&config.WorkingDir, "working_dir", "w", "/var/sshpiper", "Working Dir")
	pflag.StringVarP(&config.PiperKeyFile, "server_key", "i", "/etc/ssh/ssh_host_rsa_key", "Key file for SSH Piper")
	pflag.StringVarP(&config.Challenger, "challenger", "c", "", "Additional challenger name, e.g. pam, empty for no additional challenge")

	pflag.StringVar(&config.Logfile, "log", "", "Logfile path. Leave empty or any error occurs will fall back to stdout")
	pflag.BoolVar(&config.AllowBadUsername, "allow_bad_username", false, "Disable username check while search the working dir")
	pflag.BoolVar(&config.NoCheckPerm, "no_check_perm", false, "Disable 0400 checking when using files in the working dir")
	pflag.BoolVar(&config.RecordTypescript, "record_typescript", false, "record screen output into the working dir with typescript format")

	pflag.BoolVarP(&config.ShowHelp, "help", "h", false, "Print help and exit")
	pflag.BoolVar(&config.ShowVersion, "version", false, "Print version and exit")

	pflag.Parse()

	if _, err := os.Stat(*configfile); os.IsNotExist(err) {
		if !pflag.Lookup("config").Changed {
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
	pflag.Visit(func(f *pflag.Flag) {
		ignoreSet[f.Name] = true
	})

	// should be ignored
	ignoreSet["help"] = true
	ignoreSet["version"] = true

	pflag.VisitAll(func(f *pflag.Flag) {

		n := f.Name
		if !ignoreSet[n] {
			n = strings.TrimPrefix(n, "-")
			fs.Var(f.Value, n, f.Usage)
		}
	})

	gconf.ParseSet("", fs)
}

func showHelp() {
	pflag.Usage()
}

func showVersion() {
	versionTemplate.Execute(out, struct {
		VER     string
		GOVER   string
		GITHASH string
	}{
		VER:     version,
		GITHASH: githash,
		GOVER:   runtime.Version(),
	})
}

func showConfig() {
	configTemplate.Execute(out, config)
}
