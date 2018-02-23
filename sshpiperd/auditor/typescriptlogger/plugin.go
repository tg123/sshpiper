package typescriptlogger

import (
	"log"
	"os"
	"path"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
)

type plugin struct {
	Config struct {
		OutputDir string `long:"auditor-typescriptlogger-outputdir" default:"/var/sshpiper" description:"Place where logged typescript files were saved"  env:"SSHPIPERD_AUDITOR_TYPESCRIPTLOGGER_OUTPUTDIR"  ini-name:"auditor-typescriptlogger-outputdir"`
	}
}

func (p *plugin) GetName() string {
	return "typescript-logger"
}

func (p *plugin) GetOpts() interface{} {
	return &p.Config
}

func (p *plugin) Create(conn ssh.ConnMetadata) (auditor.Auditor, error) {
	dir := path.Join(p.Config.OutputDir, conn.User())
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, err
	}

	return newFilePtyLogger(dir)
}

func (p *plugin) Init(logger *log.Logger) error {

	return nil
}

func (l *filePtyLogger) GetUpstreamHook() auditor.Hook {
	return l.loggingTty
}

func (l *filePtyLogger) GetDownstreamHook() auditor.Hook {
	return nil
}

func init() {
	auditor.Register("typescript-logger", new(plugin))
}
