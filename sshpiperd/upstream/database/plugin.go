package database

import (
	"fmt"
	"log"

	"github.com/jinzhu/gorm"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

var logger *log.Logger

type createdb interface {
	create() (*gorm.DB, error)
}

type plugin struct {
	createdb

	db *gorm.DB
}

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
			Host:             host,
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

func (p *plugin) GetHandler() upstreamprovider.Handler {
	return p.findUpstream
}

func (p *plugin) Init(glogger *log.Logger) error {

	logger = glogger

	db, err := p.create()

	if err != nil {
		return err
	}

	logger.Printf("upstream provider: Database driver [%v] initializing", db.Dialect().GetName())

	err = db.AutoMigrate(
		new(keydata),
		new(privateKey),
		new(hostKey),
		new(server),
		new(upstream),
		new(authorizedKey),
		new(downstream),
		new(config),
	).Error

	if err != nil {
		logger.Printf("AutoMigrate error: %v", err)
	}

	p.db = db

	// plugin is alive within program lifecycle, close when unload added
	// defer db.Close()

	return nil
}
