package e2e_test

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCreateConnPlugin(t *testing.T) {
	sshsvr := createFakeSshServer(&ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	})
	defer sshsvr.Close()

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testcreateconnplugin",
		"--testsshserver",
		sshsvr.Addr().String(),
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	// The upstream returned by the plugin points at a bogus address; the
	// connection only succeeds because the plugin's CreateConnCallback dials
	// the real upstream, proving the plugin owns connection creation.
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
}
