package authy

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dcu/go-authy"
)

type authyClient struct {
	Config struct {
		APIKey string `long:"challenger-authy-apikey" description:"Authy API Key" env:"SSHPIPERD_CHALLENGER_AUTHY_APIKEY" ini-name:"challenger-authy-apikey"`
		// Method string `long:"challenger-authy-method" default:"token" description:"Authy authentication method" env:"SSHPIPERD_CHALLENGER_AUTHY_METHOD" ini-name:"challenger-authy-method" choice:"token" choice:"onetouch"`
		Method string `long:"challenger-authy-method" default:"token" description:"Authy authentication method" env:"SSHPIPERD_CHALLENGER_AUTHY_METHOD" ini-name:"challenger-authy-method" choice:"token"`
		File   string `long:"challenger-authy-idfile" description:"Path to a file with ssh_name [space] authy_id per line (first line win if duplicate)" env:"SSHPIPERD_CHALLENGER_AUTHY_IDFILE" ini-name:"challenger-authy-idfile"`
	}

	authyAPI *authy.Authy
	logger   *log.Logger
}

func (a *authyClient) Init(logger *log.Logger) error {
	a.logger = logger
	a.authyAPI = authy.NewAuthyAPI(a.Config.APIKey)

	return nil
}

func (a *authyClient) challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error) {
	user := conn.User()

	authyID, err := a.findAuthyID(user)

	if err != nil {
		return nil, err
	}

	switch a.Config.Method {
	case "token":

		ans, err := client(user, "", []string{"Please input your Authy token: "}, []bool{true})
		if err != nil {
			return nil, err
		}

		verification, err := a.authyAPI.VerifyToken(authyID, ans[0], url.Values{})
		if err != nil {
			return nil, err
		}

		if verification.Valid() {
			return nil, nil
		}

		_, err = client(conn.User(), verification.Message, nil, nil)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("failed to auth with authy: %v", verification.Message)

	case "onetouch":
		_, err = client(conn.User(), "Please verify login on your Authy app", nil, nil)
		if err != nil {
			return nil, err
		}

		details := authy.Details{
			"User":     user,
			"ClientIP": conn.RemoteAddr().String(),
		}

		approvalRequest, err := a.authyAPI.SendApprovalRequest(authyID, "Log to SSH server", details, url.Values{})
		if err != nil {
			return nil, err
		}

		status, err := a.authyAPI.WaitForApprovalRequest(approvalRequest.UUID, time.Second*30, url.Values{})
		if err != nil {
			return nil, err
		}

		if status == authy.OneTouchStatusApproved {
			return nil, nil
		}

		_, err = client(conn.User(), "Authy OneTouch failed", nil, nil)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("one touch faild code: %v", status)

	default:
		return nil, fmt.Errorf("unsupported authy method")
	}
}
