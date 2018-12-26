// +build pam

package pam

import (
	"fmt"
	"os"
    "errors"

	"golang.org/x/crypto/ssh"

	"github.com/msteinert/pam"

	"github.com/tg123/sshpiper/sshpiperd/challenger"
)

const (
	SSHPIPER_PAM_SERVICE_FILE = "/etc/pam.d/sshpiperd"
)

func pamChallenger(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error) {

	user := conn.User()

	sendQuesttion := func(question string, echo bool) (string, error) {
		ans, err := client(user, "", []string{question}, []bool{echo})

		if err != nil {
			return "", err
		}

		return ans[0], nil
	}

	sendInstruction := func(instruction string) (string, error) {
		_, err := client(user, instruction, nil, nil)
		return "", err
	}

	t, err := pam.StartFunc("sshpiperd", user, func(style pam.Style, msg string) (string, error) {
		switch style {
		case pam.PromptEchoOff:
			return sendQuesttion(msg, false)
		case pam.PromptEchoOn:
			return sendQuesttion(msg, true)
		case pam.ErrorMsg:
			return sendInstruction(fmt.Sprintf("Error: %s", msg))
		case pam.TextInfo:
			return sendInstruction(msg)
		}
		return "", errors.New("Unrecognized message style")
	})

	if err != nil {
		return false, err
	}

	err = t.Authenticate(0)
	if err != nil {
		return false, err
	}

	return true, nil
}

func init() {
	if _, err := os.Stat(SSHPIPER_PAM_SERVICE_FILE); os.IsNotExist(err) {

		return
	}

	challenger.Register("pam", challenger.NewFromHandler("pam", func() challenger.Handler { return pamChallenger }, nil, nil))
}
