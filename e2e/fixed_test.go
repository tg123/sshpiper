package e2e_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOldSshd(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password-old:2222",
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	for _, tc := range []struct {
		name string
		bin  string
	}{
		{
			name: "without-sshping",
			bin:  "ssh-8.0p1",
		},
		{
			name: "with-sshping",
			bin:  "ssh-9.8p1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			c, stdin, stdout, err := runCmd(
				tc.bin,
				"-v",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-o",
				"RequestTTY=yes",
				"-p",
				piperport,
				"-l",
				"user",
				"127.0.0.1",
				fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfie), // sleep 5 to cover https://github.com/tg123/sshpiper/issues/323
			)
			if err != nil {
				t.Errorf("failed to ssh to piper-fixed, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, "pass")

			waitForStdoutContains(stdout, "SSHREADY", func(_ string) {
				_, _ = fmt.Fprintf(stdin, "%v\n", "triggerping")
			})

			time.Sleep(time.Second * 3) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		})
	}
}

func TestHostkeyParam(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	keyparam := base64.StdEncoding.EncodeToString([]byte(testprivatekey))

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"--server-key-data",
		keyparam,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	b, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		piperport,
		"127.0.0.1",
	)

	if !strings.Contains(string(b), testpublickey) {
		t.Errorf("failed to get correct hostkey, %v", err)
	}
}

func TestServerCertParam(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"--server-key",
		"/src/e2e/sshdconfig/piper-host-key",
		"--server-cert",
		"/src/e2e/sshdconfig/piper-host-key-cert.pub",
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-cert:2222",
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	// ssh-keyscan does not support cert key types, so we use ssh -v
	// to verify the negotiated host key algorithm is a cert type
	c, _, stdout, err := runCmd(
		"ssh",
		"-v",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com",
		"-o", "BatchMode=yes",
		"-p", piperport,
		"-l", "user",
		"127.0.0.1",
		"true",
	)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	defer killCmd(c)

	// wait briefly for key exchange to complete, then check output
	time.Sleep(2 * time.Second)

	buf := make([]byte, 64*1024)
	n, _ := stdout.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("expected cert key algorithm in ssh output, got: %s", output)
	}
}
