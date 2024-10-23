package e2e_test

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
)

const yamlConfigTemplate = `
version: "1.0"
pipes:
- from:
    - username: "password_simple"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
- from:
    - username: "^password_.*_regex$"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "user"
    known_hosts_data: 
    # github.com
    - fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
    - {{ .KnownHostsKey }}
    - {{ .KnownHostsPass }}
- from:
    - username: "^password_(.+?)_regex_expand$"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "$1"
    known_hosts_data: {{ .KnownHostsPass }}
- from:
    - username: "publickey_simple"
      authorized_keys: {{ .AuthorizedKeys_Simple }}
  to:
    host: host-publickey:2222
    username: "user"
    private_key: {{ .PrivateKey }}
    known_hosts_data: {{ .KnownHostsKey }}
- from:
    - username: ".*"
      username_regex_match: true
      authorized_keys: 
      - {{ .AuthorizedKeys_Simple }}
      - {{ .AuthorizedKeys_Catchall }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
- from:
    - username: "cert"
      trusted_user_ca_keys: {{ .TrustedUserCAKeys }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
`

func TestYaml(t *testing.T) {

	yamldir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	yamlfile, err := os.OpenFile(path.Join(yamldir, "config.yaml"), os.O_RDWR|os.O_CREATE, 0400)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	{
		// simple key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa_simple")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa_simple"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		// catch all key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa_catchall")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa_catchall"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		// upstream key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		if err := runCmdAndWait(
			"/bin/cp",
			path.Join(yamldir, "id_rsa.pub"),
			"/sshconfig_publickey/.ssh/authorized_keys",
		); err != nil {
			t.Errorf("failed to copy public key: %v", err)
		}

		// ssh ca
		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "ca_key"),
		); err != nil {
			t.Errorf("failed to generate ca key: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "user_ca_key"),
		); err != nil {
			t.Errorf("failed to generate user ca key: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-s",
			path.Join(yamldir, "ca_key"),
			"-I",
			"cert",
			"-n",
			"cert",
			"-V",
			"+1w",
			path.Join(yamldir, "user_ca_key.pub"),
		); err != nil {
			t.Errorf("failed to sign user ca key: %v", err)
		}

	}

	knownHostsKeyData, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-publickey",
	)

	if err != nil {
		t.Errorf("failed to run ssh-keyscan: %v", err)
	}

	knownHostsPassData, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-password",
	)

	if err != nil {
		t.Errorf("failed to run ssh-keyscan : %v", err)
	}
	if err := template.Must(template.New("yaml").Parse(yamlConfigTemplate)).ExecuteTemplate(yamlfile, "yaml", struct {
		KnownHostsKey  string
		KnownHostsPass string
		PrivateKey     string

		AuthorizedKeys_Simple   string
		AuthorizedKeys_Catchall string

		TrustedUserCAKeys string
	}{
		KnownHostsKey:  base64.StdEncoding.EncodeToString(knownHostsKeyData),
		KnownHostsPass: base64.StdEncoding.EncodeToString(knownHostsPassData),
		PrivateKey:     path.Join(yamldir, "id_rsa"),

		AuthorizedKeys_Simple:   path.Join(yamldir, "id_rsa_simple.pub"),
		AuthorizedKeys_Catchall: path.Join(yamldir, "id_rsa_catchall.pub"),

		TrustedUserCAKeys: path.Join(yamldir, "ca_key.pub"),
	}); err != nil {
		t.Fatalf("Failed to write yaml file %v", err)
	}

	// dump config.yaml to stdout
	_ = runCmdAndWait("cat", "-n", path.Join(yamldir, "config.yaml"))

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/yaml",
		"--config",
		yamlfile.Name(),
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	t.Run("password_simple", func(t *testing.T) {
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
			"password_simple",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_regex", func(t *testing.T) {
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
			"password_XXX_regex",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_regex_expand", func(t *testing.T) {
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
			"password_user_regex_expand",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("publickey_simple", func(t *testing.T) {
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
			"publickey_simple",
			"-i",
			path.Join(yamldir, "id_rsa_simple"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("catch_all", func(t *testing.T) {
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
			"anyusername",
			"-i",
			path.Join(yamldir, "id_rsa_catchall"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("publickey_simple_withmultiple_keyfile", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		wrongkeydir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		wrongkeyfile := path.Join(wrongkeydir, "key")

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			wrongkeyfile,
		); err != nil {
			t.Errorf("failed to generate key: %v", err)
		}

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
			"publickey_simple",
			"-i",
			wrongkeyfile,
			"-i",
			path.Join(yamldir, "id_rsa_simple"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("ssh_cert", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			fmt.Sprintf("CertificateFile=%v", path.Join(yamldir, "user_ca_key-cert.pub")),
			"-p",
			piperport,
			"-l",
			"cert",
			"-i",
			path.Join(yamldir, "user_ca_key"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})
}
