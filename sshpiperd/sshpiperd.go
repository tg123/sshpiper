package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/tg123/sshpiper/ssh"
	"io/ioutil"
	"log"
	"net"
	"os"
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

	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
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

func (file userFile) realPath(user string) string {
	return userSpecFile(user, string(file))
}

// TODO log
func main() {

	if ShowHelp {
		flag.PrintDefaults()
		return
	}

	piper := &ssh.SSHPiper{
		FindUpstream: func(conn ssh.ConnMetadata) (net.Conn, *ssh.ClientConfig, error) {

			// TODO security
			addr, err := UserUpstreamFile.read(conn.User())
			if err != nil {
				return nil, nil, err
			}

			saddr := strings.TrimSpace(string(addr))

			logger.Printf("mapping user [%s] to [%s]", conn.User(), saddr)

			c, err := net.Dial("tcp", saddr)
			if err != nil {
				return nil, nil, err
			}

			return c, &ssh.ClientConfig{}, nil
		},

		MapPublicKey: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.Signer, error) {

			user := conn.User()

			var err error
			defer func() { // print error when func exit
				if err != nil {
					logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
				}
			}()

			keydata := key.Marshal()

			var rest []byte
			rest, err = UserAuthorizedKeysFile.read(user)
			if err != nil {
				return nil, err
			}

			var authedPubkey ssh.PublicKey

			for len(rest) > 0 {
				authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)

				if err != nil {
					return nil, err
				}

				if bytes.Equal(authedPubkey.Marshal(), keydata) {

					var privateBytes []byte
					privateBytes, err = UserKeyFile.read(user)
					if err != nil {
						return nil, err
					}

					var private ssh.Signer
					private, err = ssh.ParsePrivateKey(privateBytes)
					if err != nil {
						return nil, err
					}

					// in log may see this twice, one is for query the other is real sign again
					logger.Printf("auth succ, using mapped private key [%v] for user [%v] from [%v]", UserKeyFile.realPath(user), user, conn.RemoteAddr())
					return private, nil
				}
			}

			logger.Printf("public key auth failed user [%v] from [%v]", conn.User(), conn.RemoteAddr())

			return nil, nil
		},
	}

	privateBytes, err := ioutil.ReadFile(PiperKeyFile)
	if err != nil {
		logger.Fatalln(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logger.Fatalln(err)
	}

	piper.DownstreamConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ListenAddr, Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection")
	}
	defer listener.Close()

	logger.Printf("listening at %s:%d, server key file %s, working dir %s", ListenAddr, Port, PiperKeyFile, WorkingDir)

	for {
		c, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)
			continue
		}

		logger.Printf("connection accepted: %v", c.RemoteAddr())
		go func() {
			err := piper.Serve(c)
			logger.Printf("connection %v closed reason: %v", c.RemoteAddr(), err)
		}()
	}
}
