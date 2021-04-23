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

type upstreamPrivateKey struct {
	Key   keydata
	KeyID int

	UpstreamID int
}

type downstreamPrivateKey struct {
	Key   keydata
	KeyID int

	DownstreamID int
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
	PrivateKey   upstreamPrivateKey
	AuthMapType  authMapType
	KnownHosts   string `gorm:"type:varchar(100)"`

	AuthorizedKeys []upstreamAuthorizedKey
}

type upstreamAuthorizedKey struct {
	Key   keydata
	KeyID int

	DownstreamID int
}

type downstream struct {
	gorm.Model

	Name              string `gorm:"type:varchar(45)"`
	Username          string `gorm:"type:varchar(45);unique_index"`
	Password          string `gorm:"type:varchar(60)"`
	PrivateKeyID      int
	PrivateKey        downstreamPrivateKey
	AuthMapType       authMapType
	AllowAnyPublicKey bool
	NoPassthrough     bool

	UpstreamID int
	Upstream   upstream

	AuthorizedKeys []downstreamAuthorizedKey
}

type downstreamAuthorizedKey struct {
	Key   keydata
	KeyID int

	UpstreamID int
}

type config struct {
	gorm.Model

	Entry string `gorm:"type:varchar(45);unique_index"`
	Value string `gorm:"type:varchar(100)"`
}
