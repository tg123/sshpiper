// +build !windows

package sshkey

import "fmt"
import "github.com/gokyle/sshkey/readpass"

func unixReadPassword(prompt string) (password string, err error) {
	binPass, err := readpass.ReadPass(prompt)
	fmt.Printf("\n")
	if err == nil {
		password = string(binPass)
	}
	return
}

func init() {
	PasswordPrompt = unixReadPassword
}
