package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type PubkeyUpstreamMapRecord struct {
	Id          int64
	UpstreamId  int64
	PubkeyId    int64
	GmtCreate   time.Time
	GmtModified time.Time
}

type PubkeyUpstreamMap struct {
	db *sql.DB
	tx *sql.Tx
}

//func NewPubkeyUpstreamMap(db *sql.DB) *PubkeyUpstreamMap {
//	return &PubkeyUpstreamMap{
//		db: db,
//	}
//}

// Function to help make the api feel cleaner
func (t *PubkeyUpstreamMap) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *PubkeyUpstreamMap) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *PubkeyUpstreamMap) Post(u *PubkeyUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `pubkey_upstream_map` set `upstream_id`=?,`pubkey_id`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.UpstreamId, u.PubkeyId)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyUpstreamMap) Put(u *PubkeyUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `pubkey_upstream_map` set `id`=?,`upstream_id`=?,`pubkey_id`=?, `gmt_modified` = now() where `id`=?", u.Id, u.UpstreamId, u.PubkeyId, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyUpstreamMap) Delete(u *PubkeyUpstreamMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from pubkey_upstream_map where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyUpstreamMap) GetById(Id int64) ([]*PubkeyUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_upstream_map where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyUpstreamMap) GetByUpstreamId(UpstreamId int64) ([]*PubkeyUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_upstream_map where upstream_id=?", UpstreamId)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyUpstreamMap) GetByPubkeyId(PubkeyId int64) ([]*PubkeyUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_upstream_map where pubkey_id=?", PubkeyId)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyUpstreamMap) GetByGmtCreate(GmtCreate time.Time) ([]*PubkeyUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_upstream_map where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyUpstreamMap) GetByGmtModified(GmtModified time.Time) ([]*PubkeyUpstreamMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_upstream_map where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyUpstreamMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colUpstreamId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colUpstreamId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyUpstreamMapRecord{Id: colId.Int64, UpstreamId: colUpstreamId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyUpstreamMap) GetFirstById(Id int64) (*PubkeyUpstreamMapRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyUpstreamMap) GetFirstByUpstreamId(UpstreamId int64) (*PubkeyUpstreamMapRecord, error) {
	r, err := t.GetByUpstreamId(UpstreamId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyUpstreamMap) GetFirstByPubkeyId(PubkeyId int64) (*PubkeyUpstreamMapRecord, error) {
	r, err := t.GetByPubkeyId(PubkeyId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyUpstreamMap) GetFirstByGmtCreate(GmtCreate time.Time) (*PubkeyUpstreamMapRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyUpstreamMap) GetFirstByGmtModified(GmtModified time.Time) (*PubkeyUpstreamMapRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
