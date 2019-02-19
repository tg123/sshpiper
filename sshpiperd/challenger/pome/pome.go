package pome

import (
	"log"
)

type pipe struct {
	Owner      string `json:"owner"`
	ServerID   string `json:"serverId"`
	Username   string `json:"username"`
	Address    string `json:"address"`
	Auth       string `json:"auth"`
	PrivateKey string `json:"privateKey"`
	UpPassword string `json:"upPassword"`

	say func(msg string) error
}

func (pipe) ChallengerName() string {
	return "pome"
}

func (p pipe) Meta() interface{} {
	return p
}

func (p pipe) ChallengedUsername() string {
	return p.Username
}

type pome struct {
	logger *log.Logger

	Config struct {
		LoginBaseURL string `long:"challenger-pome-loginurl" description:"Send this url/{id} to user for login" env:"SSHPIPERD_CHALLENGER_POME_LOGINURL" ini-name:"challenger-pome-loginurl"`
		CheckBaseURL string `long:"challenger-pome-checkurl" description:"Call this url/{id} to retrieve login info" env:"SSHPIPERD_CHALLENGER_POME_CHECKURL" ini-name:"challenger-pome-checkurl"`
		Timeout      uint   `long:"challenger-pome-timeout" default:"60" description:"Timeout for waiting response from checkurl" env:"SSHPIPERD_CHALLENGER_POME_TIMEOUT" ini-name:"challenger-pome-timeout"`
	}
}
