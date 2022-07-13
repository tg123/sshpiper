package e2e_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDocker(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/docker",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	t.Run("password", func(t *testing.T) {
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
			piperport,
			"-l",
			"pass",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("key", func(t *testing.T) {

		keyfiledir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		keyfile := path.Join(keyfiledir, "key")

		if err := ioutil.WriteFile(keyfile, []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA2cC73MsqoV11Xy0Elw7wDdU9HnduBEQ2lD4FSpWITZRkzufLjJpr
F//RuCU7HYlR6qBqDR+rpBfHUjNJoGYDDhjLtek8HsJY8DBayvikmGuWXOOlcue2s9GRJ4
r2VaXE2rs4Lb6UOHPbGsMFHHPdxeccHn7JyyMstlLCuCMTcWkVkjtFqI6xf6er/0YTGcr3
asl0TmVGMIU2zzDXTGJ0zY7+23hv8Hhle2R4rJ0jvGz93Gvi1WHckR+cXto81ZxtnHPMst
RWJ9jYbSoifbGPU2AZ8Hif9eb3JTk3JUNTwJMxXZMV9/InOFVyePBAxdM7b6lj8mTAnwQn
MS4xnj6UJtRl0GDp75GiwTkkjKfZhKEX3tnQn+tfKKbjNXKR6jpOoHaYKSeccsOxKi1OXV
Onlyk5KfoWrPCjKxd8iI/RhpJWe60psQg2Hitr33AKDg51wp9tADn3NRj3p4CW2v1U+62z
XU8zf3uvi5sl8XwPH5RAO7mT6smJCfuYiwE2hoCzAAAFiNuyf3Xbsn91AAAAB3NzaC1yc2
EAAAGBANnAu9zLKqFddV8tBJcO8A3VPR53bgRENpQ+BUqViE2UZM7ny4yaaxf/0bglOx2J
Ueqgag0fq6QXx1IzSaBmAw4Yy7XpPB7CWPAwWsr4pJhrllzjpXLntrPRkSeK9lWlxNq7OC
2+lDhz2xrDBRxz3cXnHB5+ycsjLLZSwrgjE3FpFZI7RaiOsX+nq/9GExnK92rJdE5lRjCF
Ns8w10xidM2O/tt4b/B4ZXtkeKydI7xs/dxr4tVh3JEfnF7aPNWcbZxzzLLUVifY2G0qIn
2xj1NgGfB4n/Xm9yU5NyVDU8CTMV2TFffyJzhVcnjwQMXTO2+pY/JkwJ8EJzEuMZ4+lCbU
ZdBg6e+RosE5JIyn2YShF97Z0J/rXyim4zVykeo6TqB2mCknnHLDsSotTl1Tp5cpOSn6Fq
zwoysXfIiP0YaSVnutKbEINh4ra99wCg4OdcKfbQA59zUY96eAltr9VPuts11PM397r4ub
JfF8Dx+UQDu5k+rJiQn7mIsBNoaAswAAAAMBAAEAAAGAdrrGNC97AR1KYCjVtd/pOEGq36
/TBvSCpfXjQLWj6lkdVkvBCtsvxZgxK6zxPLuhNMNez+US25gzkDhyzsiQpeETQg74PvVN
NTnIZ5+Hb6xKAkAF+E8rqYR9FwiIJE8MtQ8cJKUjgFx7fW4UnVz38W6AQIh1UxPMz2T00x
4c/duEbYVwB+Y2FhrAh6IXzBqFKW7Kwewqh047gmFpIzcT5PkxMU3MC1w6STuRKN1NnPH4
wXT568s+TsrjojxwqzBs+jsIcrCW/PiIQ6qOP2+yHW2xSaazqHyJd9Q20djybINq47D/qq
OPPTT1KJ3jlg5VPF0eUvHac4IGhAT2V8e721qC2aA2AWLunqE5/50yT/8NV87RSbgrmLbP
sEIblyu/Be/VYpXQQW1ODnZDlYDw9SeJQkR2NNr6O/kvFCIDItJEo3Tbc9cuuQ/bAxmDM2
cbqFCjTuTdB9RgMpqtcCzT2PvT5ZT1DepVk2DsdZGsgCMkU5KZBlZvuXDIQ85b0XTxAAAA
wQDbR4D2Cliwr6MsKrvuHTGm5fTvX7emq5DhoqQEPwWTvhz1RFd7tme2hnWZ4LqLVuCyee
hpIddwEAwYLkLkT4tPivvG46t7VuUEtLY0EYxXIdvCKsjPAlOv5UiI+u3TDu/dMXN78QwQ
I8kOM/9Nacwe61LcFGKTzfhd3sq9Z1O4fCYNfJ57RJDqxwe4T5aG6OCnMy/3DbepwFlmA0
0JKfverxTQHEWEuWYWooNCI+otHaZsMzRrkIiXCRQQm71sZkAAAADBAPB8vjyk7ieZA4sl
eFBvFZp5FDxAGeAsZ3Fk1a7gRtGks7tTR3/bavGwWCrhkIRYuvA/kisEX/rwJQ0TH5oaQf
AvxXSVxgvwCjwVfuph8hRkBpMzXVVLeEU4cHUaAz1PP+apLvAkBLMJRqhare05uhFUaK5X
f5VY5s+hbjGIV0PsnCcCPRmzhBPlOeVLN5f0L0fDjGD0Q35+3LkSvM6a3PYsR7urZf5Nh+
Z0oCmDnoAOmsuB32Zik7FCLfVu1c/7fwAAAMEA58yRn3xSXmNp6G5rxywkJZjB0ntXMeHO
afTM7+BgWvdvjj9+82bjPiz1hxq1VAxd8pvRzpi4SlosQD/2beWfv9FMyCY2UWgGhRyX1H
SvkI2NnTuyvyxWIBf5r4a1jYBegcJTcOY6fip+e24dZRRHfPkXFDA0phO80sLRgf3IXwHG
f0wffmyP4VWu8JylUkBlD2kRswA2GA0z2u/HUMGixyM/+lpwOPTunxJg4f1Em8yf0Q32kC
BdCjPlHSdvg+TNAAAADWJvbGlhbkB1YnVudHUBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
`), 0400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		if err := ioutil.WriteFile("/sshconfig_publickey/.ssh/authorized_keys", []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVzohqdRTuT6+SvaccRc9emivp74CyVrO1beiWrGOu0gWy6cocCkodFQXa0qi5vcYO5TX40+PvgwMlNYvQwLbntvnUxHI2H7UymBKQK2jy6Fjt+hBEvFBRbCiL029YRiJE3ffGMY2gs4rkv5lzXqMJmg2HqnwAns5oJWV1TpFV2FBo8NGvAOXcUa3Nuk/nCKtVurnap7GoZD2/CAhJxuxbW+7Y2cGst87EX4Esk8p8QF+Bi5RlD9As2ublc5bIMpXA4rrQKc5gRrDtqHojfWqtdrQqQlg1pBOLHye7lSRcfxhG7qY7xzvYnkWx23KO2tLb5WCupG+V7QRJFosYwutBAqppMpNS60WflE+mymUVf+ptLn3oRDFEalo1kJkymd6uyp+BPZgrGSTt+DzHTIwoJ9RowwBVTU2sKz13WhP+6TKf82IhyjOspeKjbOjLUII/tL4647/7X9VaOvvJ5Qt5sPAdcwk7nSPfkJEr/U9ChnUNKEn6H1eNm26dZpk7hiU=`), 0400); err != nil {
			t.Errorf("failed to write to authorized_keys: %v", err)
		}

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"anyuser",
			"-i",
			keyfile,
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})
}
