package crud

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

func OpenMySql(user, pass, host string, port uint, dbname string) (*sql.DB, error) {
	return sql.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", user, pass, host, port, dbname))
}
