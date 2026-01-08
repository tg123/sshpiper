package skel

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type testConn struct {
	user string
	id   string
}

func (c testConn) User() string              { return c.user }
func (c testConn) RemoteAddr() string        { return "" }
func (c testConn) UniqueID() string          { return c.id }
func (c testConn) GetMeta(key string) string { return "" }

type testPipe struct {
	froms []SkelPipeFrom
}

func (p testPipe) From() []SkelPipeFrom { return p.froms }

type passwordFrom struct {
	to        SkelPipeTo
	password  []byte
	testError error
}

func (f *passwordFrom) MatchConn(conn libplugin.ConnMetadata) (SkelPipeTo, error) {
	return f.to, nil
}

func (f *passwordFrom) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	if f.testError != nil {
		return false, f.testError
	}
	return bytes.Equal(password, f.password), nil
}

type publicKeyFrom struct {
	to         SkelPipeTo
	authorized []byte
	trusted    []byte
}

func (f *publicKeyFrom) MatchConn(conn libplugin.ConnMetadata) (SkelPipeTo, error) {
	return f.to, nil
}

func (f *publicKeyFrom) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return f.authorized, nil
}

func (f *publicKeyFrom) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return f.trusted, nil
}

type passwordTo struct {
	host       string
	user       string
	ignore     bool
	knownHosts []byte
	override   []byte
}

func (t *passwordTo) Host(conn libplugin.ConnMetadata) string { return t.host }
func (t *passwordTo) User(conn libplugin.ConnMetadata) string { return t.user }
func (t *passwordTo) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return t.ignore
}
func (t *passwordTo) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return t.knownHosts, nil
}
func (t *passwordTo) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return t.override, nil
}

type privateKeyTo struct {
	host       string
	user       string
	ignore     bool
	knownHosts []byte
	priv       []byte
	cert       []byte
}

func (t *privateKeyTo) Host(conn libplugin.ConnMetadata) string { return t.host }
func (t *privateKeyTo) User(conn libplugin.ConnMetadata) string { return t.user }
func (t *privateKeyTo) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return t.ignore
}
func (t *privateKeyTo) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return t.knownHosts, nil
}
func (t *privateKeyTo) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	return t.priv, t.cert, nil
}

func TestSupportedMethodsReturnsAll(t *testing.T) {
	p := NewSkelPlugin(func(conn libplugin.ConnMetadata) ([]SkelPipe, error) {
		return []SkelPipe{
			testPipe{froms: []SkelPipeFrom{&passwordFrom{to: &passwordTo{}}}},
			testPipe{froms: []SkelPipeFrom{&publicKeyFrom{to: &privateKeyTo{}}}},
		}, nil
	})

	methods, err := p.SupportedMethods(testConn{user: "user", id: "id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := make(map[string]bool)
	for _, m := range methods {
		found[m] = true
	}

	if !found["password"] || !found["publickey"] {
		t.Fatalf("expected both password and publickey methods, got %v", methods)
	}
}

func TestPasswordCallbackUsesOriginalPassword(t *testing.T) {
	conn := testConn{user: "bob", id: "pass-id"}
	target := &passwordTo{host: "target.example:2022"}
	from := &passwordFrom{to: target, password: []byte("secret")}

	p := NewSkelPlugin(func(conn libplugin.ConnMetadata) ([]SkelPipe, error) {
		return []SkelPipe{testPipe{froms: []SkelPipeFrom{from}}}, nil
	})

	up, err := p.PasswordCallback(conn, []byte("secret"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if up.Host != "target.example" || up.Port != 2022 {
		t.Fatalf("unexpected upstream target %s:%d", up.Host, up.Port)
	}

	if up.UserName != "bob" {
		t.Fatalf("expected username fallback to conn user, got %q", up.UserName)
	}

	pass := up.GetPassword()
	if pass == nil || pass.Password != "secret" {
		t.Fatalf("expected password auth with original password, got %#v", up.Auth)
	}
}

func TestPublicKeyCallbackAuthorizedKey(t *testing.T) {
	conn := testConn{user: "alice", id: "pub-id"}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("unable to create public key: %v", err)
	}

	target := &privateKeyTo{
		host: "example.com:2200",
		user: "upstream-user",
		priv: []byte("private-key"),
		cert: []byte("ca-cert"),
	}

	from := &publicKeyFrom{
		to:         target,
		authorized: ssh.MarshalAuthorizedKey(pub),
	}

	p := NewSkelPlugin(func(conn libplugin.ConnMetadata) ([]SkelPipe, error) {
		return []SkelPipe{testPipe{froms: []SkelPipeFrom{from}}}, nil
	})

	up, err := p.PublicKeyCallback(conn, pub.Marshal())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if up.Host != "example.com" || up.Port != 2200 {
		t.Fatalf("unexpected upstream target %s:%d", up.Host, up.Port)
	}

	if up.UserName != "upstream-user" {
		t.Fatalf("unexpected upstream user %q", up.UserName)
	}

	priv := up.GetPrivateKey()
	if priv == nil {
		t.Fatalf("expected private key auth, got %#v", up.Auth)
	}
	if !bytes.Equal(priv.PrivateKey, []byte("private-key")) || !bytes.Equal(priv.CaPublicKey, []byte("ca-cert")) {
		t.Fatalf("unexpected private key auth data: %+v", priv)
	}
}

func TestVerifyHostKeyCallbackUsesKnownHosts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("unable to create public key: %v", err)
	}

	host := "[127.0.0.1]:22"
	knownLine := knownhosts.Line([]string{host}, pub)

	target := &passwordTo{
		knownHosts: []byte(knownLine),
	}

	conn := testConn{user: "bob", id: "verify-id"}

	p := NewSkelPlugin(nil)
	p.cache.SetDefault(conn.UniqueID(), target)

	if err := p.VerifyHostKeyCallback(conn, host, "127.0.0.1:22", pub.Marshal()); err != nil {
		t.Fatalf("expected host key verification success, got %v", err)
	}
}
