package database

import (
	"fmt"

	"github.com/jinzhu/gorm"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
	"github.com/tg123/sshpiper/sshpiperd/utils"
)

func (p *plugin) ListPipe() ([]upstreamprovider.Pipe, error) {
	db := p.db

	downstreams := make([]downstream, 0)
	err := db.Set("gorm:auto_preload", true).Find(&downstreams).Error
	if err != nil {
		return nil, err
	}

	pipes := make([]upstreamprovider.Pipe, 0, len(downstreams))
	for _, d := range downstreams {

		host, port, err := upstreamprovider.SplitHostPortForSSH(d.Upstream.Server.Address)

		if err != nil {
			continue
		}

		upuser := d.Upstream.Username

		if upuser == "" {
			upuser = d.Username
		}

		pipes = append(pipes, upstreamprovider.Pipe{
			Host:             utils.FormatIPAddress(host),
			Port:             port,
			Username:         d.Username,
			UpstreamUsername: upuser,
		})
	}

	return pipes, nil
}

func (p *plugin) CreatePipe(opt upstreamprovider.CreatePipeOption) error {
	db := p.db

	return db.Create(&downstream{
		Username: opt.Username,
		Upstream: upstream{
			Username:    opt.UpstreamUsername,
			AuthMapType: authMapTypeNone,
			Server: server{
				Address:       fmt.Sprintf("%v:%v", opt.Host, opt.Port),
				IgnoreHostKey: true,
			},
		},
	}).Error
}

func (p *plugin) RemovePipe(name string) error {
	db := p.db

	d, err := lookupDownstream(db, name)
	if err != nil {

		if gorm.IsRecordNotFoundError(err) {
			return nil
		}

		return err
	}
	return db.Unscoped().Delete(d).Error
}
