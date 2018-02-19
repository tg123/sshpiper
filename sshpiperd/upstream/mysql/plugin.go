package mysql

import (
	"database/sql"
	"log"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"github.com/tg123/sshpiper/sshpiperd/upstream/mysql/crud"
)

var logger *log.Logger

type plugin struct {
	Config struct {
		Host     string `long:"upstream-mysql-host" default:"127.0.0.1" description:"mysql host for driver" env:"SSHPIPERD_UPSTREAM_MYSQL_HOST" ini-name:"upstream-mysql-host"`
		User     string `long:"upstream-mysql-user" default:"root" description:"mysql user for driver" env:"SSHPIPERD_UPSTREAM_MYSQL_USER" ini-name:"upstream-mysql-user"`
		Password string `long:"upstream-mysql-password" default:"" description:"mysql password for driver" env:"SSHPIPERD_UPSTREAM_MYSQL_PASSWORD" ini-name:"upstream-mysql-password"`
		Port     uint   `long:"upstream-mysql-port" default:"3306" description:"mysql port for driver" env:"SSHPIPERD_UPSTREAM_MYSQL_PORT" ini-name:"upstream-mysql-port"`
		Dbname   string `long:"upstream-mysql-dbname" default:"sshpiper" description:"mysql dbname for driver" env:"SSHPIPERD_UPSTREAM_MYSQL_DBNAME" ini-name:"upstream-mysql-dbname"`
	}

	w MysqlWorkingDir
}

func (p *plugin) GetName() string {
	return "mysql"
}

func (p *plugin) GetOpts() interface{} {
	return &p.Config
}

func (p *plugin) GetFindUpstreamHandle() upstream.UpstreamHandler {
	return p.w.FindUpstream
}

func (p *plugin) Init(glogger *log.Logger) error {

	logger = glogger
	logger.Printf("upstream provider: mysql")

	p.w.ConnectDB = func() (*sql.DB, error) {
		return crud.OpenMySql(p.Config.User, p.Config.Password, p.Config.Host, p.Config.Port, p.Config.Dbname)
	}

	return nil
}

func init() {
	upstream.Register("mysql", &plugin{})
}
