// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package ssh

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
)

// {{{ Example NewSSHPiperConn

func ExampleNewSSHPiperConn() {

	// upstream addr
	const serverAddr = "127.0.0.1:22"

	piper := &SSHPiperConfig{
		// return conn dial to serverAddr
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			c, err := net.Dial("tcp", serverAddr)
			if err != nil {
				return nil, nil, err
			}

			// change upstream username to root
			return c, &SSHPiperAuthPipe{
				User: "root",
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, nil
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

// }}}

func dialPiper(piper *SSHPiperConfig) (net.Conn, error) {
	c, s, err := netPipe()
	if err != nil {
		return nil, err
	}

	piper.AddHostKey(testSigners["rsa"])

	go func() {
		defer c.Close()
		defer s.Close()

		p, err := NewSSHPiperConn(s, piper)

		if err != nil {
			fmt.Println(err)
			return
		}

		p.Wait()
	}()

	return c, nil
}

func TestPiperFindUpstreamCallback(t *testing.T) {

	const username = "testuser"

	var called bool

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			if username != conn.User() {
				t.Errorf("different username")
			}

			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					called = true

					if conn.User() != username {
						t.Errorf("default username changed")
					}

					if string(password) != "password" {
						t.Errorf("password not equal")
					}

					return nil, nil
				},
			}, t)

			return s, &SSHPiperAuthPipe{
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	NewClientConn(c, "", &ClientConfig{
		User:            username,
		Auth:            []AuthMethod{Password("password")},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if !called {
		t.Fatalf("FindUpstream not called")

	}
}

// TODO clean up duplicate code
func TestPiperFindUpstreamWithUserCallback(t *testing.T) {
	const username = "testuser"
	const mappedname = "mappedname"

	var called bool

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {

			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					called = true

					if conn.User() != mappedname {
						t.Errorf("bad mapped username")
					}

					return nil, nil
				},
			}, t)

			return s, &SSHPiperAuthPipe{
				User: mappedname,
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	NewClientConn(c, "", &ClientConfig{
		User:            username,
		Auth:            []AuthMethod{Password("password")},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if !called {
		t.Fatalf("FindUpstream not called")
	}
}

func TestPiperMapPublicKey(t *testing.T) {

	certChecker := CertChecker{
		IsUserAuthority: func(k PublicKey) bool {
			return bytes.Equal(k.Marshal(), testPublicKeys["ecdsa"].Marshal())
		},
		UserKeyFallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				return nil, nil
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		IsRevoked: func(c *Certificate) bool {
			return c.Serial == 666
		},
	}

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PublicKeyCallback: certChecker.Authenticate,
			}, t)
			return s, &SSHPiperAuthPipe{

				PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (AuthPipeType, AuthMethod, error) {
					return AuthPipeTypeMap, PublicKeys(testSigners["rsa"]), nil
				},

				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	_, _, _, err = NewClientConn(c, "", &ClientConfig{
		User: "testuser",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("can connect to piper %v", err)
	}
}

func TestPiperMapPublicKeyToPassword(t *testing.T) {
	certChecker := CertChecker{
		IsUserAuthority: func(k PublicKey) bool {
			return bytes.Equal(k.Marshal(), testPublicKeys["ecdsa"].Marshal())
		},
		UserKeyFallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				return nil, nil
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		IsRevoked: func(c *Certificate) bool {
			return c.Serial == 666
		},
	}

	var called bool

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					t.Errorf("PasswordCallback should not be called")
					return nil, nil
				},
				PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {

					called = true
					return certChecker.Authenticate(conn, key)
				},
			}, t)
			return s, &SSHPiperAuthPipe{
				PasswordCallback: func(conn ConnMetadata, password []byte) (AuthPipeType, AuthMethod, error) {
					if string(password) != "mypassword" {
						t.Errorf("password not equal")
					}

					return AuthPipeTypeMap, PublicKeys(testSigners["rsa"]), nil
				},

				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	_, _, _, err = NewClientConn(c, "", &ClientConfig{
		User: "testuser",
		Auth: []AuthMethod{
			Password("mypassword"),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("can connect to piper %v", err)
	}

	if !called {
		t.Fatalf("PublicKeyCallback not called")
	}
}

func TestPiperPasswordToMapPublicKey(t *testing.T) {
	var called bool

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					called = true

					if string(password) != "mypassword" {
						t.Errorf("password not equal")
					}

					return nil, nil
				},
				PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {

					t.Errorf("PublicKeyCallback should not be called")
					return nil, nil
				},
			}, t)
			return s, &SSHPiperAuthPipe{

				PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (AuthPipeType, AuthMethod, error) {
					return AuthPipeTypeMap, Password("mypassword"), nil
				},

				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	_, _, _, err = NewClientConn(c, "", &ClientConfig{
		User: "testuser",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("can connect to piper %v", err)
	}

	if !called {
		t.Fatalf("PasswordCallback not called")
	}
}

func TestPiperServerWithBanner(t *testing.T) {

	const username = "testuser"

	var called bool

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			if username != conn.User() {
				t.Errorf("different username")
			}

			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					return nil, nil
				},
				BannerCallback: func(conn ConnMetadata) string {
					called = true
					return "banner"
				},
			}, t)

			return s, &SSHPiperAuthPipe{
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	NewClientConn(c, "", &ClientConfig{
		User:            username,
		Auth:            []AuthMethod{Password("password")},
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(message string) error {
			if message != "banner" {
				t.Errorf("bad banner string")
			}

			return nil
		},
	})

	if !called {
		t.Fatalf("FindUpstream not called")
	}
}

func TestPiperAdditionalChallenge(t *testing.T) {
	c, err := dialPiper(&SSHPiperConfig{
		AdditionalChallenge: func(conn ConnMetadata, challenge KeyboardInteractiveChallenge) (bool, error) {
			ans, err := challenge("user",
				"instruction",
				[]string{"question1", "question2"},
				[]bool{true, true})

			if err != nil {
				return false, err
			}

			ok := conn.User() == "testuser" && ans[0] == "answer1" && ans[1] == "answer2"
			if ok {
				challenge("user", "motd", nil, nil)
				return true, nil
			}
			return false, fmt.Errorf("keyboard-interactive failed")
		},
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{NoClientAuth: true}, t)
			return s, &SSHPiperAuthPipe{
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	answers := keyboardInteractive(map[string]string{
		"question1": "answer1",
		// TODO "question2": "WRONG",
		"question2": "answer2",
	})

	_, _, _, err = NewClientConn(c, "", &ClientConfig{
		User: "testuser",
		Auth: []AuthMethod{
			KeyboardInteractive(answers.Challenge),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("can connect to piper %v", err)
	}

}

func fakeUpstreamServer(s net.Conn, upstream *ServerConfig, handler serverType, t *testing.T) {
	defer s.Close()

	upstream.AddHostKey(testSigners["rsa"])

	_, chans, reqs, err := NewServerConn(s, upstream)
	if err != nil {
		t.Errorf("cannot start upstream %v", err)
	}

	go DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(UnknownChannelType, "unknown channel type")
			continue
		}

		ch, inReqs, err := newCh.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			continue
		}
		go func() {
			handler(ch, inReqs, t)
		}()
	}
}

func dialUpstream(handler serverType, upstream *ServerConfig, t *testing.T) (net.Conn, error) {
	c, s, err := netPipe()
	if err != nil {
		t.Errorf("netPipe piper->upstream: %v", err)
		return nil, err
	}

	go fakeUpstreamServer(s, upstream, handler, t)
	return c, nil
}

func TestPiperPipeData(t *testing.T) {

	c, err := dialPiper(&SSHPiperConfig{
		FindUpstream: func(conn ConnMetadata) (net.Conn, *SSHPiperAuthPipe, error) {
			s, err := dialUpstream(simpleEchoHandler, &ServerConfig{NoClientAuth: true}, t)
			return s, &SSHPiperAuthPipe{
				UpstreamHostKeyCallback: InsecureIgnoreHostKey(),
			}, err
		},
	})

	if err != nil {
		t.Fatalf("connect dial to piper: %v", err)
	}

	// {{{ copy from session_test.go TestClientWriteEOF(t *testing.T)
	sshc, chans, reqs, err := NewClientConn(c, "", &ClientConfig{
		User:            "testuser",
		HostKeyCallback: InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("error create client %v", err)
	}

	conn := NewClient(sshc, chans, reqs)
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}

	data := []byte(`0000`)
	_, err = stdin.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	stdin.Close()

	res, err := ioutil.ReadAll(stdout)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(data, res) {
		t.Fatalf("Read differed from write, wrote: %v, read: %v", data, res)
	}
	// }}}
}
