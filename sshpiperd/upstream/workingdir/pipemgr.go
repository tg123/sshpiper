package workingdir

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

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

		userUpstreamFile := userFile{filename: userUpstreamFile, userdir: path.Join(config.WorkingDir, file.Name())}
		data, err := userUpstreamFile.read()
		if err != nil {
			continue
		}

		host, port, mappedUser, err := parseUpstreamFile(string(data))
		if err != nil {
			continue
		}

		pipes = append(pipes, upstream.Pipe{
			Host:             host,
			Port:             port,
			Username:         file.Name(),
			UpstreamUsername: mappedUser,
		})
	}

	return pipes, nil
}

func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	userdir := path.Join(config.WorkingDir, opt.Username)
	err := os.MkdirAll(userdir, 0775)
	if err != nil {
		return err
	}

	userUpstreamFile := userFile{filename: userUpstreamFile, userdir: userdir}
	path := userUpstreamFile.realPath()
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
	userUpstreamFile := userFile{filename: userUpstreamFile, userdir: path.Join(config.WorkingDir, name)}
	path := userUpstreamFile.realPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	return os.Remove(path)
}
