package workingdir

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

var logger *log.Logger

type plugin struct {
}

func (p *plugin) ListPipe() ([]upstream.Pipe, error) {
	files, err := ioutil.ReadDir(config.WorkingDir)
	if err != nil {
		return nil, err
	}

	pipes := make([]upstream.Pipe, 0, len(files))
	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		data, err := userUpstreamFile.read(file.Name())
		if err != nil {
			continue
		}

		host, port, mappedUser, err := parseUpstreamFile(string(data))

		pipes = append(pipes, upstream.Pipe{
			Host:             host,
			Port:             uint(port),
			Username:         file.Name(),
			UpstreamUsername: mappedUser,
		})
	}

	return pipes, nil
}

func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	err := os.MkdirAll(config.WorkingDir+"/"+opt.Username, 0775)
	if err != nil {
		return err
	}

	path := userUpstreamFile.realPath(opt.Username)
	if _, err := os.Stat(path); os.IsNotExist(err) {

		upuser := opt.UpstreamUsername

		if len(upuser) == 0 {
			upuser = opt.Username
		}

		content := fmt.Sprintf("%v@%v:%v", upuser, opt.Host, opt.Port)
		return ioutil.WriteFile(path, []byte(content), 0600)
	} else if err != nil {
		return err
	}

	return fmt.Errorf("upstream file of [%v] alreay exists", opt.Username)
}

func (p *plugin) RemovePipe(name string) error {
	path := userUpstreamFile.realPath(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	return os.Remove(path)
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
