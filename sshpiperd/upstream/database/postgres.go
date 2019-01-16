package database

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // gorm dialect

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

type postgresplugin struct {
	plugin

	Config struct {
		Host        string `long:"upstream-postgres-host" default:"127.0.0.1" description:"PostgreSQL host" env:"SSHPIPERD_UPSTREAM_POSTGRES_HOST" ini-name:"upstream-postgres-host"`
		User        string `long:"upstream-postgres-user" default:"postgres" description:"PostgreSQL user" env:"SSHPIPERD_UPSTREAM_POSTGRES_USER" ini-name:"upstream-postgres-user"`
		Password    string `long:"upstream-postgres-password" description:"PostgreSQL password" env:"SSHPIPERD_UPSTREAM_POSTGRES_PASSWORD" ini-name:"upstream-postgres-password"`
		Port        uint   `long:"upstream-postgres-port" default:"5432" description:"PostgreSQL port" env:"SSHPIPERD_UPSTREAM_POSTGRES_PORT" ini-name:"upstream-postgres-port"`
		Dbname      string `long:"upstream-postgres-dbname" default:"sshpiper" description:"PostgreSQL database name" env:"SSHPIPERD_UPSTREAM_POSTGRES_DBNAME" ini-name:"upstream-postgres-dbname"`
		SslMode     string `long:"upstream-postgres-sslmode" default:"require" description:"PostgreSQL ssl mode" env:"SSHPIPERD_UPSTREAM_POSTGRES_SSLMODE" ini-name:"upstream-postgres-sslmode"`
		SslCert     string `long:"upstream-postgres-sslcert" description:"PostgreSQL ssl cert path" env:"SSHPIPERD_UPSTREAM_POSTGRES_SSLCERT" ini-name:"upstream-postgres-sslcert"`
		SslKey      string `long:"upstream-postgres-sslkey" description:"PostgreSQL ssl key path" env:"SSHPIPERD_UPSTREAM_POSTGRES_SSLKEY" ini-name:"upstream-postgres-sslkey"`
		SslRootCert string `long:"upstream-postgres-sslrootcert" description:"PostgreSQL ssl root cert path" env:"SSHPIPERD_UPSTREAM_POSTGRES_SSLROOTCERT" ini-name:"upstream-postgres-sslrootcert"`
	}
}

func (p *postgresplugin) create() (*gorm.DB, error) {

	conn := fmt.Sprintf("host=%v port=%v user=%v password=%v dbname=%v sslmode=%v sslcert=%v sslkey=%v sslrootcert=%v",
		p.Config.Host,
		p.Config.Port,
		p.Config.User,
		p.Config.Password,
		p.Config.Dbname,
		p.Config.SslMode,
		p.Config.SslCert,
		p.Config.SslKey,
		p.Config.SslRootCert,
	)

	db, err := gorm.Open("postgres", conn)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (postgresplugin) GetName() string {
	return "postgres"
}

func (p *postgresplugin) GetOpts() interface{} {
	return &p.Config
}

func init() {
	p := &postgresplugin{}
	p.createdb = p
	upstreamprovider.Register("postgres", p)
}
