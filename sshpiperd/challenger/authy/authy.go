package authy

import (
	"github.com/tg123/sshpiper/sshpiperd/challenger"
)

func (authyClient) GetName() string {
	return "authy"
}

func (a *authyClient) GetOpts() interface{} {
	return &a.Config
}

func (a *authyClient) GetHandler() challenger.Handler {
	return a.challenge
}

func init() {
	challenger.Register("authy", &authyClient{})
}
