package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type UserUpstreamMapRecord struct {
	Id          int64
	UpstreamId  int64
	Username    string
	GmtCreate   time.Time
	GmtModified time.Time
}

type UserUpstreamMap struct {
	db *sql.DB
	tx *sql.Tx
}

func NewUserUpstreamMap(db *sql.DB) *UserUpstreamMap {
	return &UserUpstreamMap{
		db: db,
	}
}

// Function to help make the api feel cleaner
func (t *UserUpstreamMap) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *UserUpstreamMap) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *UserUpstreamMap) Post(u *UserUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `user_upstream_map` set `upstream_id`=?,`username`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.UpstreamId, u.Username)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *UserUpstreamMap) Put(u *UserUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `user_upstream_map` set `id`=?,`upstream_id`=?,`username`=?, `gmt_modified` = now() where `id`=?", u.Id, u.UpstreamId, u.Username, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *UserUpstreamMap) Delete(u *UserUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from user_upstream_map where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *UserUpstreamMap) GetById(Id int64) ([]*UserUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from user_upstream_map where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*UserUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colUsername sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colUsername, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UserUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, Username: colUsername.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *UserUpstreamMap) GetByUpstreamId(UpstreamId int64) ([]*UserUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from user_upstream_map where upstream_id=?", UpstreamId)
	if err != nil {
		return nil, err
	}
	res := make([]*UserUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colUsername sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colUsername, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UserUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, Username: colUsername.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *UserUpstreamMap) GetByUsername(Username string) ([]*UserUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from user_upstream_map where username=?", Username)
	if err != nil {
		return nil, err
	}
	res := make([]*UserUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colUsername sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colUsername, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UserUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, Username: colUsername.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *UserUpstreamMap) GetByGmtCreate(GmtCreate time.Time) ([]*UserUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from user_upstream_map where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*UserUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colUsername sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colUsername, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UserUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, Username: colUsername.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *UserUpstreamMap) GetByGmtModified(GmtModified time.Time) ([]*UserUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from user_upstream_map where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*UserUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colUsername sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colUsername, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UserUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, Username: colUsername.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *UserUpstreamMap) GetFirstById(Id int64) (*UserUpstreamMapRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *UserUpstreamMap) GetFirstByUpstreamId(UpstreamId int64) (*UserUpstreamMapRecord, error) {
	r, err := t.GetByUpstreamId(UpstreamId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *UserUpstreamMap) GetFirstByUsername(Username string) (*UserUpstreamMapRecord, error) {
	r, err := t.GetByUsername(Username)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *UserUpstreamMap) GetFirstByGmtCreate(GmtCreate time.Time) (*UserUpstreamMapRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *UserUpstreamMap) GetFirstByGmtModified(GmtModified time.Time) (*UserUpstreamMapRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
