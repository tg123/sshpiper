package workingdir

import (
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

var logger *log.Logger

type plugin struct {
}

func (p *plugin) GetName() string {
	return "workingdir"
}

func (p *plugin) GetOpts() interface{} {
	return &config
}

func (p *plugin) GetHandler() upstream.Handler {
	return findUpstreamFromUserfile
}

func (p *plugin) Init(glogger *log.Logger) error {

	logger = glogger

	logger.Printf("upstream provider: workingdir from path [%v] initializing", config.WorkingDir)

	return nil
}

func init() {
	upstream.Register("workingdir", &plugin{})
}
