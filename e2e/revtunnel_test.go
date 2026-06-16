package e2e_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRevtunnel exercises plugin/revtunnel end-to-end:
//
//  1. start sshpiperd with the revtunnel plugin
//  2. open `ssh -R 0:host-publickey:2222 -i <key> user@piper` to register a
//     tunnel; read the GUID + upstream public key from the session output
//  3. install the upstream public key on host-publickey's authorized_keys
//  4. run `ssh -i <same_key> <guid>@piper '<remote cmd>'` and verify the
//     command runs on host-publickey through the reverse tunnel
func TestRevtunnel(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"/sshpiperd/plugins/revtunnel",
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}
	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	keydir, err := os.MkdirTemp("", "revtunnel-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(keydir)

	// Write the registrar's identity key (same key used for both register and connect).
	registrarKeyPath := path.Join(keydir, "id_registrar")
	if err := os.WriteFile(registrarKeyPath, []byte(testprivatekey), 0o400); err != nil {
		t.Fatalf("write registrar key: %v", err)
	}

	// 1) Launch the registrar — uses pubkey auth with the test key.
	registrar, regStdin, regStdout, err := runCmd(
		"ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-i", registrarKeyPath,
		"-o", "ExitOnForwardFailure=yes",
		"-p", piperport,
		"-R", "0:host-publickey:2222",
		"user@127.0.0.1",
	)
	if err != nil {
		t.Fatalf("ssh -R: %v", err)
	}
	defer killCmd(registrar)
	_ = regStdin

	guid, upstreamPub, err := readRegistration(regStdout, 15*time.Second)
	if err != nil {
		t.Fatalf("read registration: %v", err)
	}
	t.Logf("registered guid=%s upstream_pub=%s", guid, strings.TrimSpace(upstreamPub))

	// Install the upstream public key on the target host.
	if err := os.WriteFile(authorizedKeysPath, []byte(upstreamPub+"\n"), 0o400); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	// 2) Connect through the tunnel using the registrar's own identity key.
	randtext := uuid.New().String()
	targetfile := uuid.New().String()
	remoteCmd := fmt.Sprintf(`sh -c "echo -n %s > /shared/%s"`, randtext, targetfile)

	c, _, _, err := runCmd(
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-i", registrarKeyPath,
		"-p", piperport,
		guid+"@127.0.0.1",
		remoteCmd,
	)
	if err != nil {
		t.Fatalf("ssh connect: %v", err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("ssh connect exit: %v", err)
	}

	time.Sleep(time.Second) // flush
	checkSharedFileContent(t, targetfile, randtext)
}

// readRegistration polls the registrar session's stdout until it has parsed
// the GUID and upstream public key emitted by plugin/revtunnel.
var (
	reGUID        = regexp.MustCompile(`^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	reUpstreamPub = regexp.MustCompile(`^echo '(ssh-[^ ']+ [^ ']+)' >> ~/\.ssh/authorized_keys$`)
)

func readRegistration(r io.Reader, timeout time.Duration) (guid, upstreamPub string, err error) {
	buf, ok := r.(*bytes.Buffer)
	if !ok {
		return "", "", fmt.Errorf("readRegistration: expected *bytes.Buffer, got %T", r)
	}

	deadline := time.Now().Add(timeout)
	for {
		guid, upstreamPub, ok := parseRegistration(buf.Bytes())
		if ok {
			return guid, upstreamPub, nil
		}
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("timed out after %s; partial data: guid=%q pub=%q", timeout, guid, upstreamPub)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func parseRegistration(data []byte) (guid, upstreamPub string, ok bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case reGUID.MatchString(line):
			guid = reGUID.FindStringSubmatch(line)[1]
		case reUpstreamPub.MatchString(line):
			upstreamPub = strings.TrimSpace(reUpstreamPub.FindStringSubmatch(line)[1])
		}
	}
	return guid, upstreamPub, guid != "" && upstreamPub != ""
}
