package main

import (
	"os"
	"runtime/debug"
	"text/template"
)

var version = "(devel)"

func showVersion() {
	versionTemplate := template.Must(template.New("ver").Parse(`
sshpiperd by Boshi Lian<farmer1992@gmail.com>
https://github.com/tg123/sshpiper

Version       : {{.VER}} 
Go  Runtime   : {{.GOVER}}
Git Commit    : {{.GITHASH}}
Timestamp     : {{.TIMESTAMP}}
`[1:]))

	data := struct {
		VER       string
		GOVER     string
		GITHASH   string
		TIMESTAMP string
	}{
		VER: version,
	}

	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				data.GITHASH = s.Value[:9]
			case "vcs.time":
				data.TIMESTAMP = s.Value
			}
		}

		data.GOVER = bi.GoVersion
	}

	_ = versionTemplate.Execute(os.Stdout, data)
}
