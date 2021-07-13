package database

import (
	"github.com/jinzhu/gorm"
)

type authMapType int

const (
	authMapTypeNone = iota
	authMapTypePassword
	authMapTypePrivateKey
	authMapTypeAny
)

const fallbackUserEntry = "FALLBACK_USER"

type keydata struct {
	gorm.Model

	Name string `gorm:"type:varchar(45)"`
	Data string `gorm:"type:text"`
	Type string `gorm:"type:varchar(45)"`
}

type server struct {
	gorm.Model

	Name    string `gorm:"type:varchar(45)"`
	Address string `gorm:"type:varchar(100)"`

	HostKeyID     int
	HostKey       keydata
	IgnoreHostKey bool
}

type upstream struct {
	gorm.Model

	Name     string `gorm:"type:varchar(45)"`
	ServerID int
	Server   server

	Username     string `gorm:"type:varchar(45)"`
	Password     string `gorm:"type:varchar(60)"`
	PrivateKeyID int
	PrivateKey   keydata
	AuthMapType  authMapType
	KnownHosts   string `gorm:"type:varchar(100)"`
}

type downstream struct {
	gorm.Model

	Name              string `gorm:"type:varchar(45)"`
	Username          string `gorm:"type:varchar(45);unique_index"`
	Password          string `gorm:"type:varchar(60)"`
	AuthMapType       authMapType
	AllowAnyPublicKey bool
	NoPassthrough     bool

	UpstreamID int
	Upstream   upstream

	AuthorizedKeysID int
	AuthorizedKeys   keydata
}

type config struct {
	gorm.Model

	Entry string `gorm:"type:varchar(45);unique_index"`
	Value string `gorm:"type:varchar(100)"`
}
