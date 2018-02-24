package mysql

import (
	"github.com/jinzhu/gorm"

)

type keydata struct {
	gorm.Model

	Name string `gorm:"type:varchar(45)`
	Data string `gorm:"type:varchar(3000)`
	Type string `gorm:"type:varchar(45)`
}

type PrivateKey struct {
	keydata
}

type HostKey struct {
	keydata

	ServerId int
}

type Server struct {
	gorm.Model

	Name    string `gorm:"type:varchar(45)`
	Address string `gorm:"type:varchar(100)`

	HostKeys      []HostKey
	IgnoreHostKey bool
}

type AuthMapType int

const (
	AuthMapTypeNone       = iota
	AuthMapTypePassword
	AuthMapTypePrivateKey
)

type Upstream struct {
	gorm.Model

	Name     string `gorm:"type:varchar(45)`
	ServerId int
	Server   Server

	Username     string `gorm:"type:varchar(45)`
	Password     string `gorm:"type:varchar(60)`
	PrivateKeyId int
	PrivateKey   PrivateKey
	AuthMapType  AuthMapType
}

type AuthorizedKey struct {
	keydata

	DownstreamId int
}

type Downstream struct {
	gorm.Model

	Name     string `gorm:"type:varchar(45)`
	Username string `gorm:"type:varchar(45);unique_index`

	AuthorizedKeys []AuthorizedKey
}
