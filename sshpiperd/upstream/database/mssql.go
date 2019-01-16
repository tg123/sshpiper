package database

import (
	"fmt"
	"net/url"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mssql" // gorm dialect

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

type mssqlplugin struct {
	plugin

	Config struct {
		Host     string `long:"upstream-mssql-host" default:"127.0.0.1" description:"SQL Server host" env:"SSHPIPERD_UPSTREAM_MSSQL_HOST" ini-name:"upstream-mssql-host"`
		User     string `long:"upstream-mssql-user" default:"sa" description:"SQL Server user" env:"SSHPIPERD_UPSTREAM_MSSQL_USER" ini-name:"upstream-mssql-user"`
		Password string `long:"upstream-mssql-password" default:"" description:"SQL Server password" env:"SSHPIPERD_UPSTREAM_MSSQL_PASSWORD" ini-name:"upstream-mssql-password"`
		Port     uint   `long:"upstream-mssql-port" default:"1433" description:"SQL Server port" env:"SSHPIPERD_UPSTREAM_MSSQL_PORT" ini-name:"upstream-mssql-port"`
		Dbname   string `long:"upstream-mssql-dbname" default:"sshpiper" description:"SQL server database name" env:"SSHPIPERD_UPSTREAM_MSSQL_DBNAME" ini-name:"upstream-mssql-dbname"`
		Instance string `long:"upstream-mssql-instance" description:"SQL Server database instance" env:"SSHPIPERD_UPSTREAM_MSSQL_INSTANCE" ini-name:"upstream-mssql-instance"`
	}
}

func (p *mssqlplugin) create() (*gorm.DB, error) {
	query := url.Values{}
	query.Add("database", p.Config.Dbname)

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(p.Config.User, p.Config.Password),
		Host:     fmt.Sprintf("%s:%d", p.Config.Host, p.Config.Port),
		Path:     p.Config.Instance,
		RawQuery: query.Encode(),
	}

	db, err := gorm.Open("mssql", u.String())
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (mssqlplugin) GetName() string {
	return "mssql"
}

func (p *mssqlplugin) GetOpts() interface{} {
	return &p.Config
}

func init() {
	p := &mssqlplugin{}
	p.createdb = p
	upstreamprovider.Register("mssql", p)
}
