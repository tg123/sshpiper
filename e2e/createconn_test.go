package e2e_test

import (
	"net"
	"net/rpc"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// createConnRpcServer serves the rpcServer over a raw (non-HTTP) rpc connection
// using an isolated *rpc.Server, so it can coexist with createRpcServer which
// registers handlers on the global HTTP rpc server.
func createConnRpcServer(r *rpcServer) net.Listener {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}

	srv := rpc.NewServer()
	_ = srv.RegisterName("TestPlugin", r)
	go srv.Accept(l)

	return l
}

func TestCreateConnPlugin(t *testing.T) {
	sshsvr := createFakeSshServer(&ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	})
	defer sshsvr.Close()

	cbtriggered := make(map[string]bool)

	rpcsvr := createConnRpcServer(&rpcServer{
		CreateConnCallback: func(uri string) error {
			cbtriggered["CreateConn"] = true
			return nil
		},
	})
	defer rpcsvr.Close()

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testcreateconnplugin",
		"--testsshserver",
		sshsvr.Addr().String(),
		"--rpcserver",
		rpcsvr.Addr().String(),
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

	if !cbtriggered["CreateConn"] {
		t.Errorf("CreateConn callback not triggered")
	}
}
