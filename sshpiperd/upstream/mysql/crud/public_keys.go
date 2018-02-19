package crud

import (
	"database/sql"
	"time"

	"github.com/go-sql-driver/mysql"
)

type PublicKeysRecord struct {
	Id          int64
	Name        string
	Data        string
	Type        string
	GmtCreate   time.Time
	GmtModified time.Time
}

type PublicKeys struct {
	db *sql.DB
	tx *sql.Tx
}

func NewPublicKeys(db *sql.DB) *PublicKeys {
	return &PublicKeys{
		db: db,
	}
}

// Function to help make the api feel cleaner
func (t *PublicKeys) Commit() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Commit()
	t.tx = nil
	return err
}

func (t *PublicKeys) Rollback() error {
	if t.tx == nil {
		return nil
	}

	err := t.tx.Rollback()
	t.tx = nil
	return err
}

func (t *PublicKeys) Post(u *PublicKeysRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("insert into `public_keys` set `name`=?,`data`=?,`type`=?,  `gmt_modified` = now(), `gmt_create` = now()", u.Name, u.Data, u.Type)
	if err != nil {
		return 0, err
	}

	v, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PublicKeys) Put(u *PublicKeysRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("update `public_keys` set `id`=?,`name`=?,`data`=?,`type`=?, `gmt_modified` = now() where `id`=?", u.Id, u.Name, u.Data, u.Type, u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PublicKeys) Delete(u *PublicKeysRecord) (int64, error) {
	var err error
	if t.tx == nil {
		// new transaction
		t.tx, err = t.db.Begin()
		if err != nil {
			return 0, err
		}
	}

	r, err := t.tx.Exec("delete from public_keys where `id`=?", u.Id)
	if err != nil {
		return 0, err
	}

	v, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}

	return v, nil
}

func (t *PublicKeys) GetById(Id int64) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where id=?", Id)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetByName(Name string) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where name=?", Name)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetByData(Data string) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where data=?", Data)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetByType(Type string) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where type=?", Type)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetByGmtCreate(GmtCreate time.Time) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where gmt_create=?", GmtCreate)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetByGmtModified(GmtModified time.Time) ([]*PublicKeysRecord, error) {
	r, err := t.db.Query("select * from public_keys where gmt_modified=?", GmtModified)
	if err != nil {
		return nil, err
	}
	res := make([]*PublicKeysRecord, 0)
	for r.Next() {
		var colId sql.NullInt64
		var colName sql.NullString
		var colData sql.NullString
		var colType sql.NullString
		var colGmtCreate mysql.NullTime
		var colGmtModified mysql.NullTime
		err = r.Scan(&colId, &colName, &colData, &colType, &colGmtCreate, &colGmtModified)
		if err != nil {
			return nil, err
		}
		s := &PublicKeysRecord{Id: colId.Int64, Name: colName.String, Data: colData.String, Type: colType.String, GmtCreate: colGmtCreate.Time, GmtModified: colGmtModified.Time}
		res = append(res, s)
	}
	return res, nil
}

func (t *PublicKeys) GetFirstById(Id int64) (*PublicKeysRecord, error) {
	r, err := t.GetById(Id)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PublicKeys) GetFirstByName(Name string) (*PublicKeysRecord, error) {
	r, err := t.GetByName(Name)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PublicKeys) GetFirstByData(Data string) (*PublicKeysRecord, error) {
	r, err := t.GetByData(Data)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PublicKeys) GetFirstByType(Type string) (*PublicKeysRecord, error) {
	r, err := t.GetByType(Type)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PublicKeys) GetFirstByGmtCreate(GmtCreate time.Time) (*PublicKeysRecord, error) {
	r, err := t.GetByGmtCreate(GmtCreate)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}

func (t *PublicKeys) GetFirstByGmtModified(GmtModified time.Time) (*PublicKeysRecord, error) {
	r, err := t.GetByGmtModified(GmtModified)
	if err != nil {
		return nil, err
	}

	if len(r) > 0 {
		return r[0], nil
	}

	return nil, nil
}
