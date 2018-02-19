package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type UpstreamRecord struct {
	Id           int64
	Name         string
	ServerId     int64
	Username     string
	PrivateKeyId int64
	GmtCreate    time.Time
	GmtModified  time.Time
}

type Upstream struct {
	db *sql.DB
	tx *sql.Tx
}

func NewUpstream(db *sql.DB) *Upstream {
	return &Upstream{
		db: db,
	}
}

// Function to help make the api feel cleaner
func (t *Upstream) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *Upstream) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *Upstream) Post(u *UpstreamRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `upstream` set `name`=?,`server_id`=?,`username`=?,`private_key_id`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.Name, u.ServerId, u.Username, u.PrivateKeyId)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Upstream) Put(u *UpstreamRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `upstream` set `id`=?,`name`=?,`server_id`=?,`username`=?,`private_key_id`=?, `gmt_modified` = now() where `id`=?", u.Id, u.Name, u.ServerId, u.Username, u.PrivateKeyId, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Upstream) Delete(u *UpstreamRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from upstream where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *Upstream) GetById(Id int64) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByName(Name string) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where name=?", Name)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByServerId(ServerId int64) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where server_id=?", ServerId)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByUsername(Username string) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where username=?", Username)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByPrivateKeyId(PrivateKeyId int64) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where private_key_id=?", PrivateKeyId)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByGmtCreate(GmtCreate time.Time) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetByGmtModified(GmtModified time.Time) ([]*UpstreamRecord, error) {
	r, err := t.db.Query("select * from upstream where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*UpstreamRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colServerId sql.NullInt64
		var colUsername sql.NullString
		var colPrivateKeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colServerId, &colUsername, &colPrivateKeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &UpstreamRecord{Id: colId.Int64, Name: colName.String, ServerId: colServerId.Int64, Username: colUsername.String, PrivateKeyId: colPrivateKeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *Upstream) GetFirstById(Id int64) (*UpstreamRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByName(Name string) (*UpstreamRecord, error) {
	r, err := t.GetByName(Name)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByServerId(ServerId int64) (*UpstreamRecord, error) {
	r, err := t.GetByServerId(ServerId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByUsername(Username string) (*UpstreamRecord, error) {
	r, err := t.GetByUsername(Username)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByPrivateKeyId(PrivateKeyId int64) (*UpstreamRecord, error) {
	r, err := t.GetByPrivateKeyId(PrivateKeyId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByGmtCreate(GmtCreate time.Time) (*UpstreamRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *Upstream) GetFirstByGmtModified(GmtModified time.Time) (*UpstreamRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
