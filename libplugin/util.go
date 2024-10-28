package libplugin

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func AuthMethodTypeToName(a AuthMethod) string {
	switch a {
	case AuthMethod_NONE:
		return "none"
	case AuthMethod_PASSWORD:
		return "password"
	case AuthMethod_PUBLICKEY:
		return "publickey"
	case AuthMethod_KEYBOARD_INTERACTIVE:
		return "keyboard-interactive"
	}
	return ""
}

func AuthMethodFromName(n string) AuthMethod {
	switch n {
	case "none":
		return AuthMethod_NONE
	case "password":
		return AuthMethod_PASSWORD
	case "publickey":
		return AuthMethod_PUBLICKEY
	case "keyboard-interactive":
		return AuthMethod_KEYBOARD_INTERACTIVE
	}
	return -1
}

func ConfigStdioLogrus(p SshPiperPlugin, formatter logrus.Formatter, logger *logrus.Logger) {
	if logger == nil {
		logger = logrus.StandardLogger()
	}

	p.SetConfigLoggerCallback(func(w io.Writer, level string, tty bool) {
		logger.SetOutput(w)
		lv, _ := logrus.ParseLevel(level)
		logger.SetLevel(lv)

		if formatter != nil {
			logger.SetFormatter(formatter)
		}

		if tty {
			if formatter == nil {
				logger.SetFormatter(&logrus.TextFormatter{ForceColors: true})
			}
		}
	})
}

// SplitHostPortForSSH is the modified version of net.SplitHostPort but return port 22 is no port is specified
func SplitHostPortForSSH(addr string) (host string, port int, err error) {
	host = addr
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		host = h
		var parsedPort int64
		parsedPort, err = strconv.ParseInt(p, 10, 32)
		if err != nil {
			return
		}
		port = int(parsedPort)
	} else if host != "" {
		// test valid after concat :22
		if _, _, err = net.SplitHostPort(host + ":22"); err == nil {
			port = 22
		}
	}

	if host == "" {
		err = fmt.Errorf("empty addr")
	}

	return
}

// DialForSSH is the modified version of net.Dial, would add ":22" automaticlly
func DialForSSH(addr string) (net.Conn, error) {

	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}

func CreateNoneAuth() *Upstream_None {
	return &Upstream_None{
		None: &UpstreamNoneAuth{},
	}
}

func CreatePasswordAuth(password []byte) *Upstream_Password {
	return CreatePasswordAuthFromString(string(password))
}

func CreatePasswordAuthFromString(password string) *Upstream_Password {
	return &Upstream_Password{
		Password: &UpstreamPasswordAuth{
			Password: password,
		},
	}
}

func CreatePrivateKeyAuth(key []byte, optionalSignedCaPublicKey ...[]byte) *Upstream_PrivateKey {
	var caPublicKey []byte
	if len(optionalSignedCaPublicKey) > 0 {
		caPublicKey = optionalSignedCaPublicKey[0]
	}
	return &Upstream_PrivateKey{
		PrivateKey: &UpstreamPrivateKeyAuth{
			PrivateKey:  key,
			CaPublicKey: caPublicKey,
		},
	}
}

func CreateRemoteSignerAuth(meta string) *Upstream_RemoteSigner {
	return &Upstream_RemoteSigner{
		RemoteSigner: &UpstreamRemoteSignerAuth{
			Meta: meta,
		},
	}
}

func CreateNextPluginAuth(meta map[string]string) *Upstream_NextPlugin {
	return &Upstream_NextPlugin{
		NextPlugin: &UpstreamNextPluginAuth{
			Meta: meta,
		},
	}
}

func CreateRetryCurrentPluginAuth(meta map[string]string) *Upstream_RetryCurrentPlugin {
	return &Upstream_RetryCurrentPlugin{
		RetryCurrentPlugin: &UpstreamRetryCurrentPluginAuth{
			Meta: meta,
		},
	}
}

func VerifyHostKeyFromKnownHosts(knownhostsData io.Reader, hostname, netaddr string, key []byte) error {
	hostKeyCallback, err := knownhosts.NewFromReader(knownhostsData)
	if err != nil {
		return err
	}

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", netaddr)
	if err != nil {
		return err
	}

	return hostKeyCallback(hostname, addr, pub)
}
