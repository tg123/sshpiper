package ssh

import (
	"io/ioutil"
	"net"
)

func ExampleNewSSHPiperConn() {

	// upstream addr
	const serverAddr = "127.0.0.1:22"

	piper := &SSHPiperConfig{
		// return conn dial to serverAddr
		FindUpstream: func(conn ConnMetadata) (net.Conn, error) {
			c, err := net.Dial("tcp", serverAddr)
			if err != nil {
				return nil, err
			}

			return c, nil
		},
	}

	// add private key
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	piper.AddHostKey(private)

	// serve at a address
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		panic("failed to listen for connection")
	}
	nConn, err := listener.Accept()
	if err != nil {
		panic("failed to accept incoming connection")
	}

	// accept nConn and build a SSHPipe
	p, err := NewSSHPiperConn(nConn, piper)
	if err != nil {
		panic("failed to establish piped connection")
	}

	// wait util either side shutdown
	p.Wait()
}
