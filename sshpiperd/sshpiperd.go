package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/tg123/sshpiper/ssh"
	"io/ioutil"
	"net"
	"strings"
)

type userFile string

var (
	UserAuthorizedKeysFile userFile = "authorized_keys"
	UserKeyFile            userFile = "id_rsa"
	UserUpstreamFile       userFile = "sshpiper_upstream"
)

var (
	ListenAddr   string
	Port         uint
	WorkingDir   string
	PiperKeyFile string
	ShowHelp     bool
)

func init() {
	flag.StringVar(&ListenAddr, "l", "0.0.0.0", "Listening Address")
	flag.UintVar(&Port, "p", 2222, "Listening Port")
	flag.StringVar(&WorkingDir, "w", "/var/sshpiper", "Working Dir")
	flag.StringVar(&PiperKeyFile, "i", "/etc/ssh/ssh_host_rsa_key", "Key file for SSH Piper")
	flag.BoolVar(&ShowHelp, "h", false, "Print help and exit")
	flag.Parse()
}

func parsePrivateKeyFile(filename string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	return private, nil
}

func userSpecFile(user, file string) string {
	return fmt.Sprintf("%s/%s/%s", WorkingDir, user, file)
}

func (file userFile) read(user string) ([]byte, error) {
	return ioutil.ReadFile(userSpecFile(user, string(file)))
}

// TODO log
func main() {

	if ShowHelp {
		flag.PrintDefaults()
		return
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ListenAddr, Port))
	if err != nil {
		panic("failed to listen for connection")
	}
	defer listener.Close()

	piper := &ssh.SSHPiper{
		FindUpstream: func(conn ssh.ConnMetadata) (net.Conn, *ssh.ClientConfig, error) {

			// TODO security
			addr, err := UserUpstreamFile.read(conn.User())
			if err != nil {
				return nil, nil, err
			}

			saddr := strings.TrimSpace(string(addr))

			fmt.Printf("map %s addr to %s \n", conn.User(), saddr)

			c, err := net.Dial("tcp", saddr)
			if err != nil {
				return nil, nil, err
			}

			return c, &ssh.ClientConfig{}, nil
		},

		MapPublicKey: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.Signer, error) {

			keydata := key.Marshal()

			rest, err := UserAuthorizedKeysFile.read(conn.User())
			if err != nil {
				return nil, err
			}

			for len(rest) > 0 {
				authedPubkey, _, _, _rest, err := ssh.ParseAuthorizedKey(rest)

				// TODO fix this name
				rest = _rest

				if err != nil {
					return nil, err
				}

				if bytes.Equal(authedPubkey.Marshal(), keydata) {

					privateBytes, err := UserKeyFile.read(conn.User())
					if err != nil {
						return nil, err
					}

					private, err := ssh.ParsePrivateKey(privateBytes)
					if err != nil {
						return nil, err
					}

					return private, nil
				}
			}

			return nil, nil
		},
	}

	privateBytes, err := ioutil.ReadFile(PiperKeyFile)
	if err != nil {
		panic(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic(err)
	}

	piper.DownstreamConfig.AddHostKey(private)

	for {
		c, err := listener.Accept()
		if err != nil {
			continue
		}

		go func() {
			err := piper.Serve(c)
			fmt.Println(err)
		}()
	}
}
