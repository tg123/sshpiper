package e2e_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func createFakeSshServer(config *ssh.ServerConfig) net.Listener {
	config.SetDefaults()
	private, _ := ssh.ParsePrivateKey([]byte(testprivatekey))
	config.AddHostKey(private)

	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			l, err := l.Accept()
			if err != nil {
				break
			}

			go func() {
				_, _, reqs, err := ssh.NewServerConn(l, config)
				if err != nil {
					panic(err)
				}

				go ssh.DiscardRequests(reqs)
			}()
		}
	}()

	return l
}

type rpcServer struct {
	NewConnectionCallback func() error
	PasswordCallback      func(string) (string, error)
	PipeStartCallback     func() error
	PipeErrorCallback     func(string) error
}

func (r *rpcServer) NewConnection(args string, reply *string) error {
	*reply = ""

	if r.NewConnectionCallback != nil {
		return r.NewConnectionCallback()
	}

	return nil
}

func (r *rpcServer) PipeStart(args string, reply *string) error {
	*reply = ""

	if r.PipeStartCallback != nil {
		return r.PipeStartCallback()
	}

	return nil
}

func (r *rpcServer) PipeError(args string, reply *string) error {
	*reply = ""

	if r.PipeErrorCallback != nil {
		return r.PipeErrorCallback(args)
	}

	return nil
}

func (r *rpcServer) Password(args string, reply *string) error {
	if r.PasswordCallback != nil {
		rpl, err := r.PasswordCallback(args)
		if err != nil {
			return err
		}
		*reply = rpl
		return nil
	}

	*reply = ""
	return nil
}

func createRpcServer(r *rpcServer) net.Listener {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}

	_ = rpc.RegisterName("TestPlugin", r)
	rpc.HandleHTTP()
	go func() {
		_ = http.Serve(l, nil)
	}()

	return l
}

func TestGrpcPlugin(t *testing.T) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)

	sshkey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create ssh signer: %v", err)
	}

	sshsvr := createFakeSshServer(&ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), sshkey.PublicKey().Marshal()) {
				return nil, fmt.Errorf("public key mismatch")
			}

			return nil, nil
		},
	})
	defer sshsvr.Close()

	cbtriggered := make(map[string]bool)

	rpcsvr := createRpcServer(&rpcServer{
		NewConnectionCallback: func() error {
			cbtriggered["NewConnection"] = true
			return nil
		},
		PasswordCallback: func(pass string) (string, error) {
			cbtriggered["Password"] = true
			return "rpcpassword", nil
		},
		PipeStartCallback: func() error {
			cbtriggered["PipeStart"] = true
			return nil
		},
		PipeErrorCallback: func(err string) error {
			cbtriggered["PipeError"] = true
			return nil
		},
	})
	defer rpcsvr.Close()

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testgrpcplugin",
		"--testsshserver",
		sshsvr.Addr().String(),
		"--rpcserver",
		rpcsvr.Addr().String(),
		"--testremotekey",
		base64.StdEncoding.EncodeToString(privKeyPem),
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	client, err := ssh.Dial("tcp", piperaddr, &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.Password("yourpassword"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})

	if err != nil {
		t.Fatalf("failed to connect to sshpiperd: %v", err)
	}

	client.Close()

	time.Sleep(1 * time.Second) // wait for callbacks to be triggered

	if !cbtriggered["NewConnection"] {
		t.Errorf("NewConnection callback not triggered")
	}

	if !cbtriggered["Password"] {
		t.Errorf("Password callback not triggered")
	}

	if !cbtriggered["PipeStart"] {
		t.Errorf("PipeStart callback not triggered")
	}

	if !cbtriggered["PipeError"] {
		t.Errorf("PipeError callback not triggered")
	}
}
