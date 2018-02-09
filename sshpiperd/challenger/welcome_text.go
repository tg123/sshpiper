package challenger

import (
	"golang.org/x/crypto/ssh"
)

// piper.AdditionalChallenge = challenger.MakeWelcomeChallenger("Please Use your phone to do the authentication")

func MakeWelcomeChallenger(text string) Challenger {
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error) {

		client(conn.User(), text, nil, nil)

		return true, nil
	}

}
