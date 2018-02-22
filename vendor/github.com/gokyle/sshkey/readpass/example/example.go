// This is a quick demo showing how to use ReadPass. It reads a
// password securely from the console and then displays the
// length of the password.
package main

import "fmt"
import "github.com/gokyle/sshkey/readpass"

func main() {
	password, err := readpass.ReadPass("enter password: ")
	fmt.Printf("\n")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Printf("%d character password read\n", len(password))
	}
}

