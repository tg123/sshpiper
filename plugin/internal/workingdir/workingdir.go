package workingdir

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	log "github.com/sirupsen/logrus"
)

type Workingdir struct {
	Path        string
	NoCheckPerm bool
	Strict      bool
}

var (
	usernameRule *regexp.Regexp
)

const (
	userAuthorizedKeysFile = "authorized_keys"
	userKeyFile            = "id_rsa"
	userUpstreamFile       = "sshpiper_upstream"
	userKnownHosts         = "known_hosts"
)

func init() {
	// Base username validation on Debians default: https://sources.debian.net/src/adduser/3.113%2Bnmu3/adduser.conf/#L85
	// -> NAME_REGEX="^[a-z][-a-z0-9_]*\$"
	// The length is limited to 32 characters. See man 8 useradd: https://linux.die.net/man/8/useradd
	usernameRule, _ = regexp.Compile("^[a-z_][-a-z0-9_]{0,31}$")
}

func IsUsernameSecure(user string) bool {
	return usernameRule.MatchString(user)
}

func (w *Workingdir) Mapkey(pub []byte) ([]byte, error) {

	var rest []byte
	rest, err := w.readfile(userAuthorizedKeysFile)
	if err != nil {
		return nil, err
	}

	var authedPubkey ssh.PublicKey

	for len(rest) > 0 {
		authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)

		if err != nil {
			return nil, err
		}

		if bytes.Equal(authedPubkey.Marshal(), pub) {
			log.Infof("found mapping key %v", w.fullpath(userKeyFile))
			return w.readfile(userKeyFile)
		}
	}

	return nil, fmt.Errorf("no matching key found")
}

func (w *Workingdir) CreateUpstream() (*libplugin.Upstream, error) {

	data, err := w.readfile(userUpstreamFile)
	if err != nil {
		return nil, err
	}

	host, port, user, err := parseUpstreamFile(string(data))
	if err != nil {
		return nil, err
	}

	return &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		IgnoreHostKey: !w.Strict,
	}, nil
}

func (w *Workingdir) VerifyHostKey(hostname, netaddr string, key []byte) error {
	if !w.Strict {
		return nil
	}

	hostKeyCallback, err := knownhosts.New(w.fullpath(userKnownHosts))
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

func (w *Workingdir) checkPerm(file string) error {
	filename := path.Join(w.Path, file)
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if w.NoCheckPerm {
		return nil
	}

	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}

	return nil
}

func (w *Workingdir) fullpath(file string) string {
	return path.Join(w.Path, file)
}

func (w *Workingdir) readfile(file string) ([]byte, error) {
	if err := w.checkPerm(file); err != nil {
		return nil, err
	}

	return ioutil.ReadFile(w.fullpath(file))
}

func parseUpstreamFile(data string) (host string, port int, user string, err error) {
	r := bufio.NewReader(strings.NewReader(data))
	for {
		host, err = r.ReadString('\n')
		if err != nil {
			break
		}

		host = strings.TrimSpace(host)

		if host != "" && host[0] != '#' {
			break
		}
	}

	t := strings.SplitN(host, "@", 2)

	if len(t) > 1 {
		user = t[0]
		host = t[1]
	}

	host, port, err = libplugin.SplitHostPortForSSH(host)
	return
}
