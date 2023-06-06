package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"crypto/tls"
	"fmt"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type plugin struct {
	URL        string
	Insecure bool
}

type piperTo struct {
	User string
	Host string
	AuthorizedKeys string
	PrivateKey string
}

func newRestAuthPlugin() *plugin{
	return &plugin{}
}

func (p *plugin) supportedMethods() ([]string, error) {
	set := make(map[string]bool)

	set["publickey"] = true
	set["password"] = false

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}

func (p *plugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: p.Insecure}
	user := conn.User()
	resp, err := http.Get(p.URL + fmt.Sprintf("/%s", url.QueryEscape(user)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result map[string]interface{}
		json.Unmarshal([]byte(body), &result)

		to := piperTo{
			User:fmt.Sprint(result["user"]),
			Host:fmt.Sprint(result["host"]),
			AuthorizedKeys:fmt.Sprint(result["authorizedKeys"]),
			PrivateKey:fmt.Sprint(result["privateKey"]),
		}
		rest, err := p.strToByte(to.AuthorizedKeys, map[string]string{
			"DOWNSTREAM_USER": user,
		})
		if err != nil {
			return nil, err
		}
		var authedPubkey ssh.PublicKey
		for len(rest) > 0 {
			authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(authedPubkey.Marshal(), publicKey) {
				return p.createUpstream(conn, to)
			}
		}
	}else {
		return nil, err
	}
	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}

func (p *plugin) createUpstream(conn libplugin.ConnMetadata, to piperTo) (*libplugin.Upstream, error) {

	host, port, err := libplugin.SplitHostPortForSSH(to.Host)
	if err != nil {
		return nil, err
	}

	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      to.User,
		IgnoreHostKey: true,
	}

	data, err := p.strToByte(to.PrivateKey, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   to.User,
	})
	if err != nil {
		return nil, err
	}

	if data != nil {
		u.Auth = libplugin.CreatePrivateKeyAuth(data)
		return u, nil
	}

	return nil, fmt.Errorf("no password or private key found")
}

func (p *plugin) strToByte(str string, vars map[string]string) ([]byte, error) {
	return []byte(str), nil
}