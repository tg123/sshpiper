package e2e_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCa(t *testing.T) {

	privateky := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9QAAAJC+j0+Svo9P
kgAAAAtzc2gtZWQyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9Q
AAAEDcQgdh2z2r/6blq0ziJ1l6s6IAX8C+9QHfAH931cHNO9RGTH325rDUp12tplwukHmR
8ytbC9TPZ886gCstynP1AAAADWJvbGlhbkB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----`

	ca := `ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIAf6qglkclnZFuSIlW4ClXcwq+SCYJn7rCYcUpbVVaKrAAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1AAAAAAAAAAAAAAABAAAACHNzaF91c2VyAAAACwAAAAdjYV91c2VyAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJrzCeQ3a+m8PnA/KUmK+JAfC1tM7SG2gkGmW29nXj1nAAAAUwAAAAtzc2gtZWQyNTUxOQAAAECM8mKjWLhTKmhj4sb6r0CVaTz/vO8oy1o/7OzmQyUMMa1ex4mo+HB3RHa5eUGOdcFAJu6O8r6GBEah+O0maH8A`


	os.WriteFile("/shared/ssh_user", []byte(privateky), 0600)
	os.WriteFile("/shared/ssh_user-cert.pub", []byte(ca), 0600)

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testcaplugin",
		"--target",
		"host-capublickey:2222",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	randtext := uuid.New().String()
	targetfie := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh",
		"-v",
		"-o",
		"StrictHostKeyChecking=no",
		"-o",
		"UserKnownHostsFile=/dev/null",
		"-p",
		piperport,
		"-l",
		"ca_user",
		"-i",
		"/tmp/key",
		"127.0.0.1",
		fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
	)

	if err != nil {
		t.Errorf("failed to ssh to piper-fixed, %v", err)
	}

	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	time.Sleep(time.Second) // wait for file flush

	checkSharedFileContent(t, targetfie, randtext)
}
