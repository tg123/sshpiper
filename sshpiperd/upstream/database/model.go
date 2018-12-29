package database

import (
	"github.com/jinzhu/gorm"
)

type authMapType int

const (
	authMapTypeNone = iota
	authMapTypePassword
	authMapTypePrivateKey
)

const fallbackUserEntry = "FALLBACK_USER"

type keydata struct {
	gorm.Model

	Name string `gorm:"type:varchar(45)"`
	Data string `gorm:"type:varchar(3000)"`
	Type string `gorm:"type:varchar(45)"`
}

type privateKey struct {
	Key   keydata
	KeyID int

	UpstreamID int
}

type hostKey struct {
	Key   keydata
	KeyID int

	ServerID int
}

type server struct {
	gorm.Model

	Name    string `gorm:"type:varchar(45)"`
	Address string `gorm:"type:varchar(100)"`

	HostKeyID     int
	HostKey       hostKey
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
	PrivateKey   privateKey
	AuthMapType  authMapType
}

type authorizedKey struct {
	Key   keydata
	KeyID int

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

type config struct {
	gorm.Model

	Entry string `gorm:"type:varchar(45);unique_index"`
	Value string `gorm:"type:varchar(100)"`
}
