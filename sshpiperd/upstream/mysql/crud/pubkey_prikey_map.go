package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type PubkeyPrikeyMapRecord struct {
	Id           int64
	PrivateKeyId int64
	PubkeyId     int64
	GmtCreate    time.Time
	GmtModified  time.Time
}

type PubkeyPrikeyMap struct {
	db *sql.DB
	tx *sql.Tx
}

func NewPubkeyPrikeyMap(db *sql.DB) *PubkeyPrikeyMap {
	return &PubkeyPrikeyMap{
		db: db,
	}
}

// Function to help make the api feel cleaner
func (t *PubkeyPrikeyMap) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *PubkeyPrikeyMap) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *PubkeyPrikeyMap) Post(u *PubkeyPrikeyMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `pubkey_prikey_map` set `private_key_id`=?,`pubkey_id`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.PrivateKeyId, u.PubkeyId)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyPrikeyMap) Put(u *PubkeyPrikeyMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `pubkey_prikey_map` set `id`=?,`private_key_id`=?,`pubkey_id`=?, `gmt_modified` = now() where `id`=?", u.Id, u.PrivateKeyId, u.PubkeyId, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyPrikeyMap) Delete(u *PubkeyPrikeyMapRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from pubkey_prikey_map where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PubkeyPrikeyMap) GetById(Id int64) ([]*PubkeyPrikeyMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_prikey_map where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyPrikeyMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colPrivateKeyId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colPrivateKeyId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyPrikeyMapRecord{Id: colId.Int64, PrivateKeyId: colPrivateKeyId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyPrikeyMap) GetByPrivateKeyId(PrivateKeyId int64) ([]*PubkeyPrikeyMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_prikey_map where private_key_id=?", PrivateKeyId)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyPrikeyMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colPrivateKeyId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colPrivateKeyId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyPrikeyMapRecord{Id: colId.Int64, PrivateKeyId: colPrivateKeyId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyPrikeyMap) GetByPubkeyId(PubkeyId int64) ([]*PubkeyPrikeyMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_prikey_map where pubkey_id=?", PubkeyId)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyPrikeyMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colPrivateKeyId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colPrivateKeyId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyPrikeyMapRecord{Id: colId.Int64, PrivateKeyId: colPrivateKeyId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyPrikeyMap) GetByGmtCreate(GmtCreate time.Time) ([]*PubkeyPrikeyMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_prikey_map where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyPrikeyMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colPrivateKeyId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colPrivateKeyId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyPrikeyMapRecord{Id: colId.Int64, PrivateKeyId: colPrivateKeyId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyPrikeyMap) GetByGmtModified(GmtModified time.Time) ([]*PubkeyPrikeyMapRecord, error) {
	r, err := t.db.Query("select * from pubkey_prikey_map where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*PubkeyPrikeyMapRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colPrivateKeyId sql.NullInt64
		var colPubkeyId sql.NullInt64
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colPrivateKeyId, &colPubkeyId, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PubkeyPrikeyMapRecord{Id: colId.Int64, PrivateKeyId: colPrivateKeyId.Int64, PubkeyId: colPubkeyId.Int64, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PubkeyPrikeyMap) GetFirstById(Id int64) (*PubkeyPrikeyMapRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyPrikeyMap) GetFirstByPrivateKeyId(PrivateKeyId int64) (*PubkeyPrikeyMapRecord, error) {
	r, err := t.GetByPrivateKeyId(PrivateKeyId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyPrikeyMap) GetFirstByPubkeyId(PubkeyId int64) (*PubkeyPrikeyMapRecord, error) {
	r, err := t.GetByPubkeyId(PubkeyId)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyPrikeyMap) GetFirstByGmtCreate(GmtCreate time.Time) (*PubkeyPrikeyMapRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PubkeyPrikeyMap) GetFirstByGmtModified(GmtModified time.Time) (*PubkeyPrikeyMapRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
