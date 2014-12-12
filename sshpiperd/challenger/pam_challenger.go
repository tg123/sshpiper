// +build pam

package challenger

import (
	"fmt"
	"github.com/tg123/sshpiper/ssh"
	pam "github.com/vvanpo/golang-pam"
	"os"
)

const (
	SSHPIPER_PAM_SERVICE_FILE = "/etc/pam.d/sshpiperd"
)

func pamChallenger(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error) {

	user := conn.User()

	sendQuesttion := func(question string, echo bool) (string, bool) {
		ans, err := client(user, "", []string{question}, []bool{echo})

		// TODO lost err
		if err != nil {
			return "", false
		}

		return ans[0], true
	}

	sendInstruction := func(instruction string) (string, bool) {
		_, err := client(user, instruction, nil, nil)
		return "", err == nil
	}

	t, status := pam.Start("sshpiperd", user, pam.ResponseFunc(func(style int, msg string) (string, bool) {
		switch style {
		case pam.PROMPT_ECHO_OFF:
			return sendQuesttion(msg, false)
		case pam.PROMPT_ECHO_ON:
			return sendQuesttion(msg, true)
		case pam.ERROR_MSG:
			return sendInstruction(fmt.Sprintf("Error: %s", msg))
		case pam.TEXT_INFO:
			return sendInstruction(msg)
		}
		return "", false
	}))

	if status != pam.SUCCESS {
		return false, fmt.Errorf("pam.Start() failed: %s\n", t.Error(status))
	}
	defer func() { t.End(status) }()

	status = t.Authenticate(0)
	if status != pam.SUCCESS {
		return false, fmt.Errorf("Auth failed: %s\n", t.Error(status))
	}

	return true, nil
}

func init() {

	if _, err := os.Stat(SSHPIPER_PAM_SERVICE_FILE); os.IsNotExist(err) {
		return
	}

	Register("pam", pamChallenger)
}
