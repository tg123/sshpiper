package challenger

import (
	"fmt"
	"sort"

	"golang.org/x/crypto/ssh"
)

type Challenger func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error)

var challengers = make(map[string]Challenger)

// copied from database/sql

func Register(name string, challenger Challenger) {
	if challenger == nil {
		panic("challenger is nil")
	}
	if _, dup := challengers[name]; dup {
		panic("Register twice for challenger" + name)
	}
	challengers[name] = challenger
}

func Challengers() []string {
	var list []string
	for name := range challengers {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func GetChallenger(name string) (Challenger, error) {
	challenger, ok := challengers[name]
	if !ok {
		return nil, fmt.Errorf("no such challenger:" + name)
	}
	return challenger, nil
}
