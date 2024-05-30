package e2e_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFixed(t *testing.T) {

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	randtext := uuid.New().String()
	targetfie := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh-9.7.1p1",
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
		fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfie), // sleep 1 to cover https://github.com/tg123/sshpiper/issues/323
	)

	if err != nil {
		t.Errorf("failed to ssh to piper-fixed, %v", err)
	}

	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	waitForStdoutContains(stdout, "SSHREADY", func(_ string) {
		_, _ = stdin.Write([]byte(fmt.Sprintf("%v\n", "triggerping")))
	})

	time.Sleep(time.Second * 3) // wait for file flush

	checkSharedFileContent(t, targetfie, randtext)
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
