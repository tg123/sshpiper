package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFixed(t *testing.T) {
	waitForEndpointReady("piper-fixed:2222")

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
		"2222",
		"-l",
		"user",
		"piper-fixed",
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
