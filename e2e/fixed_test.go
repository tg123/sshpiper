package e2e_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
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
	// generate host key in memory
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal host key: %v", err)
	}

	keyData := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(pemBlock))

	// generate self-signed host certificate in memory
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	cert := &ssh.Certificate{
		CertType:        ssh.HostCert,
		Key:             signer.PublicKey(),
		KeyId:           "e2e-host-cert",
		ValidPrincipals: []string{"127.0.0.1", "localhost"},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("failed to sign host certificate: %v", err)
	}

	certData := base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(cert))

	// start sshpiperd with base64 key + cert data, no files needed
	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"--server-key-data",
		keyData,
		"--server-cert-data",
		certData,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
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

	waitForStdoutContains(stdout, "ssh-ed25519-cert-v01@openssh.com", func(_ string) {})
}
