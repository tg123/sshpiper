package database

import (
	"log"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"

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

func (p *plugin) GetHandler() upstreamprovider.Handler {
	return p.findUpstream
}

func (p *plugin) Init(glogger *log.Logger) error {

	logger = glogger

	db, err := p.create()

	if err != nil {
		return err
	}
	db.LogMode(true)

	db.AutoMigrate(
		new(privateKey),
		new(hostKey),
		new(server),
		new(upstream),
		new(authorizedKey),
		new(downstream),
	)

	p.db = db

	// plugin is alive within program lifecycle, close when unload added
	// defer db.Close()

	return nil
}
