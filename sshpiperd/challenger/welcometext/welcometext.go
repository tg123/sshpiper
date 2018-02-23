package challenger

import (
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/challenger"
)

func makeWelcomeChallenger(text string) challenger.Handler {
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error) {

		client(conn.User(), text, nil, nil)

		return true, nil
	}
}

func init() {

	var h challenger.Handler

	config := &struct {
		WelcomeText string `long:"challenger-welcometext" description:"Show a welcome text when connect to sshpiper server" env:"SSHPIPERD_CHALLENGER_WELCOMETEXT" ini-name:"challenger-welcometext"`
	}{}

	challenger.Register("welcometext", challenger.NewFromHandler("welcometext", func() challenger.Handler {
		return h
	}, config, func(logger *log.Logger) error {
		h = makeWelcomeChallenger(config.WelcomeText)
		return nil
	}))
}
