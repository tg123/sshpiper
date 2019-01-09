package azdevicecode

import (
	"github.com/tg123/sshpiper/sshpiperd/challenger"
)

func (*authClient) GetName() string {
	return "azdevicecode"
}

func (c *authClient) GetOpts() interface{} {
	return &c.Config
}

func (c *authClient) GetHandler() challenger.Handler {
	return c.challenge
}

func init() {
	challenger.Register("azdevicecode", &authClient{})
}
