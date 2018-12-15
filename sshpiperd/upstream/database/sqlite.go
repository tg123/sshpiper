package database

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

type sqliteplugin struct {
	plugin

	Config struct {
		File string `long:"sqlite-dbfile" default:"file:sshpiper.sqlite" description:"databasefile for sqlite" env:"SSHPIPERD_UPSTREAM_SQLITE_FILE" ini-name:"upstream-sqlite-file"`
	}
}

func (p *sqliteplugin) create() (*gorm.DB, error) {

	db, err := gorm.Open("sqlite3", p.Config.File)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (sqliteplugin) GetName() string {
	return "sqlite"
}

func (p *sqliteplugin) GetOpts() interface{} {
	return &p.Config
}

func init() {
	p := &sqliteplugin{}
	p.createdb = p
	upstreamprovider.Register("sqlite", p)
}
