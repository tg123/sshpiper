package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type ServerRecord struct {
	Id          int64
	Name        string
	Address     string
	GmtCreate   time.Time
	GmtModified time.Time
}

type Server struct {
	db *sql.DB
	tx *sql.Tx
}

func NewServer(db *sql.DB) *Server {
	return &Server{
		db: db,
	}
}

// Function to help make the api feel cleaner
func (t *Server) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *Server) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *Server) Post(u *ServerRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `server` set `name`=?,`address`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.Name, u.Address)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Server) Put(u *ServerRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `server` set `id`=?,`name`=?,`address`=?, `gmt_modified` = now() where `id`=?", u.Id, u.Name, u.Address, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Server) Delete(u *ServerRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from server where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Server) GetById(Id int64) ([]*ServerRecord, error) {
	r, err := t.db.Query("select * from server where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*ServerRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colAddress sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colAddress, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &ServerRecord{Id: colId.Int64, Name: colName.String, Address: colAddress.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Server) GetByName(Name string) ([]*ServerRecord, error) {
	r, err := t.db.Query("select * from server where name=?", Name)
	if err != nil {
		return nil, err
	}
	res := make([]*ServerRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colAddress sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colAddress, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &ServerRecord{Id: colId.Int64, Name: colName.String, Address: colAddress.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Server) GetByAddress(Address string) ([]*ServerRecord, error) {
	r, err := t.db.Query("select * from server where address=?", Address)
	if err != nil {
		return nil, err
	}
	res := make([]*ServerRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colAddress sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colAddress, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &ServerRecord{Id: colId.Int64, Name: colName.String, Address: colAddress.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Server) GetByGmtCreate(GmtCreate time.Time) ([]*ServerRecord, error) {
	r, err := t.db.Query("select * from server where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*ServerRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colAddress sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colAddress, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &ServerRecord{Id: colId.Int64, Name: colName.String, Address: colAddress.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Server) GetByGmtModified(GmtModified time.Time) ([]*ServerRecord, error) {
	r, err := t.db.Query("select * from server where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*ServerRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colAddress sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colAddress, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &ServerRecord{Id: colId.Int64, Name: colName.String, Address: colAddress.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Server) GetFirstById(Id int64) (*ServerRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Server) GetFirstByName(Name string) (*ServerRecord, error) {
	r, err := t.GetByName(Name)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Server) GetFirstByAddress(Address string) (*ServerRecord, error) {
	r, err := t.GetByAddress(Address)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Server) GetFirstByGmtCreate(GmtCreate time.Time) (*ServerRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Server) GetFirstByGmtModified(GmtModified time.Time) (*ServerRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
