package database

import (
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
	panic("implement me")
}

func (p *plugin) CreatePipe(opt upstreamprovider.CreatePipeOption) error {
	panic("implement me")
}

func (p *plugin) RemovePipe(name string) error {
	panic("implement me")
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
