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
//  2. open `ssh -R 0:host-publickey:2222 user@piper` to register a tunnel;
//     read the GUID + private/public key block from the session output
//  3. publish the generated public key to host-publickey's authorized_keys
//  4. run `ssh -i <privkey> <guid>@piper '<remote cmd>'` and verify the
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
	privPath := path.Join(keydir, "id_revtunnel")

	// 1) Launch the registrar — interactive shell so our plugin can write
	// the registration block to stdout. Keep the process alive for the
	// entire test; the live ssh.Conn it holds is what the connect-side
	// flow uses to open forwarded-tcpip channels.
	registrar, regStdin, regStdout, err := runCmd(
		"ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PreferredAuthentications=none",
		"-o", "PubkeyAuthentication=no",
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

	guid, privPEM, pubAuthorized, err := readRegistration(regStdout, 15*time.Second)
	if err != nil {
		t.Fatalf("read registration: %v", err)
	}
	t.Logf("registered guid=%s pubkey=%s", guid, strings.TrimSpace(pubAuthorized))

	if err := os.WriteFile(privPath, []byte(privPEM), 0o400); err != nil {
		t.Fatalf("write privkey: %v", err)
	}
	if err := os.WriteFile(authorizedKeysPath, []byte(pubAuthorized+"\n"), 0o400); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	// 2) Connect through the tunnel and run a command on host-publickey.
	randtext := uuid.New().String()
	targetfile := uuid.New().String()
	remoteCmd := fmt.Sprintf(`sh -c "echo -n %s > /shared/%s"`, randtext, targetfile)

	c, _, _, err := runCmd(
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-i", privPath,
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
// the GUID, the OpenSSH-format public key, and the private key PEM block
// emitted by plugin/revtunnel. Because runCmd returns a *bytes.Buffer that
// reports io.EOF whenever it's drained, we re-scan from the start of buf
// each iteration (matching waitForStdoutContains's pattern) and slow-poll
// until the full block is present or we hit the timeout.
var (
	reGUID    = regexp.MustCompile(`GUID=([0-9a-fA-F-]{8,})`)
	rePub     = regexp.MustCompile(`PUBLIC_KEY=(.+)`)
	beginPriv = "-----BEGIN REVTUNNEL PRIVATE KEY-----"
	endPriv   = "-----END REVTUNNEL PRIVATE KEY-----"
)

func readRegistration(r io.Reader, timeout time.Duration) (guid, privPEM, pubAuthorized string, err error) {
	buf, ok := r.(*bytes.Buffer)
	if !ok {
		return "", "", "", fmt.Errorf("readRegistration: expected *bytes.Buffer, got %T", r)
	}

	deadline := time.Now().Add(timeout)
	for {
		guid, privPEM, pubAuthorized, ok := parseRegistration(buf.Bytes())
		if ok {
			return guid, privPEM, pubAuthorized, nil
		}
		if time.Now().After(deadline) {
			return "", "", "", fmt.Errorf("timed out after %s; partial data: guid=%q pub=%q priv-bytes=%d", timeout, guid, pubAuthorized, len(privPEM))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func parseRegistration(data []byte) (guid, privPEM, pubAuthorized string, ok bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)

	var privBuf bytes.Buffer
	inPriv := false
	gotEnd := false
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case inPriv:
			if line == endPriv {
				inPriv = false
				gotEnd = true
				continue
			}
			privBuf.WriteString(line)
			privBuf.WriteByte('\n')
		case line == beginPriv:
			inPriv = true
			privBuf.Reset()
			gotEnd = false
		case reGUID.MatchString(line):
			guid = reGUID.FindStringSubmatch(line)[1]
		case rePub.MatchString(line):
			pubAuthorized = strings.TrimSpace(rePub.FindStringSubmatch(line)[1])
		}
	}
	return guid, privBuf.String(), pubAuthorized, guid != "" && pubAuthorized != "" && gotEnd
}
