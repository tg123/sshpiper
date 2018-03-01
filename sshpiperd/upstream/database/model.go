package database

import (
	"github.com/jinzhu/gorm"
)

type key struct {
	gorm.Model

	Name string `gorm:"type:varchar(45)"`
	Data string `gorm:"type:varchar(3000)"`
	Type string `gorm:"type:varchar(45)"`
}

type privateKey struct {
	Key key
	KeyId int
}

type hostKey struct {
	Key key
	KeyId int

	ServerID int
}

type server struct {
	gorm.Model

	Name    string `gorm:"type:varchar(45)"`
	Address string `gorm:"type:varchar(100)"`

	HostKeys      []hostKey
	IgnoreHostKey bool
}

type authMapType int

const (
	authMapTypeNone       = iota
	authMapTypePassword
	authMapTypePrivateKey
)

type upstream struct {
	gorm.Model

	Name     string `gorm:"type:varchar(45)"`
	ServerID int
	Server   server

	Username     string `gorm:"type:varchar(45)"`
	Password     string `gorm:"type:varchar(60)"`
	PrivateKeyID int
	PrivateKey   privateKey
	AuthMapType  authMapType
}

type authorizedKey struct {
	Key key
	KeyId int

	DownstreamID int
}

type downstream struct {
	gorm.Model

	Name     string `gorm:"type:varchar(45)"`
	Username string `gorm:"type:varchar(45);unique_index"`

	UpstreamID int
	Upstream   upstream

	AuthorizedKeys []authorizedKey
}
