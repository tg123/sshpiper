package main

import (
	"os"
	"runtime"
	"text/template"
)

var version = "DEV"
var githash = "0000000000"

func showVersion() {
	versionTemplate := template.Must(template.New("ver").Parse(`
sshpiperd by Boshi Lian<farmer1992@gmail.com>
https://github.com/tg123/sshpiper

Version       : {{.VER}} 
Go  Runtime   : {{.GOVER}}
Git Commit    : {{.GITHASH}}
`[1:]))

	_ = versionTemplate.Execute(os.Stdout, struct {
		VER     string
		GOVER   string
		GITHASH string
	}{
		VER:     version,
		GITHASH: githash,
		GOVER:   runtime.Version(),
	})
}
