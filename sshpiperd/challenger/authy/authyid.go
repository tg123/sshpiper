package authy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func (a authyClient) findAuthyID(user string) (string, error) {
	// TODO a better way to handle large database

	file, err := os.Open(a.Config.File)

	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) >= 2 {
			if fields[0] == user {
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("authy id for user not found")
}
