// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"

	"github.com/tg123/sshpiper/ssh"
	"github.com/tg123/sshpiper/ssh/testdata"
)

func init() {
	if !testing.Verbose() {
		logger = log.New(ioutil.Discard, "", 0)
	}
}

func buildWorkingDir(users []string, t *testing.T) {
	config.WorkingDir = ""
	dir, err := ioutil.TempDir(os.TempDir(), "sshpiperd_workingdir")

	if err != nil {
		t.Fatalf("setup temp dir:%v", err)
	}

	config.WorkingDir = dir

	for _, u := range users {
		os.Mkdir(config.WorkingDir+"/"+u, os.ModePerm)
	}

	t.Logf("switch workingdir to %v", config.WorkingDir)
}

func cleanupWorkdir(t *testing.T) {
	if config.WorkingDir == "" {
		return
	}

	t.Logf("cleaning workingdir %v", config.WorkingDir)

	os.RemoveAll(config.WorkingDir)
}

func TestReadUserFile(t *testing.T) {
	user1 := "testuser1"
	user2 := "testuser2"

	buildWorkingDir([]string{user1, user2}, t)
	defer cleanupWorkdir(t)

	data1 := []byte("byte[] := data1")
	data2 := []byte("this is data2")

	f := userFile("f")

	err := ioutil.WriteFile(f.realPath(user1), data1, os.ModePerm)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	err = ioutil.WriteFile(f.realPath(user2), data2, os.ModePerm)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	d, err := f.read(user1)
	if err != nil || !bytes.Equal(d, data1) {
		t.Fatalf("read faild")
	}

	d, err = f.read(user2)
	if err != nil || bytes.Equal(d, data1) {
		t.Fatalf("reading wrong user file")
	}
}

func TestCheckPerm(t *testing.T) {
	user := "testuser"
	buildWorkingDir([]string{user}, t)
	defer cleanupWorkdir(t)

	f := userFile("perm")

	err := ioutil.WriteFile(f.realPath(user), nil, os.ModePerm)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	err = f.checkPerm(user)
	if err == nil {
		t.Fatalf("should fail when read 0777 user file")
	}

	err = os.Chmod(f.realPath(user), 0600)
	if err != nil {
		t.Fatalf("cant change file mode %v", err)
	}

	err = f.checkPerm(user)
	if err != nil {
		t.Fatalf("fail when read 0600 user file", err)
	}
}

type stubConnMetadata struct{ user string }

func (s stubConnMetadata) User() string {
	return s.user
}

func (s stubConnMetadata) SessionID() []byte     { return nil }
func (s stubConnMetadata) ClientVersion() []byte { return nil }
func (s stubConnMetadata) ServerVersion() []byte { return nil }
func (s stubConnMetadata) RemoteAddr() net.Addr  { return nil }
func (s stubConnMetadata) LocalAddr() net.Addr   { return nil }

func TestParseUpstreamFile(t *testing.T) {

	var addr, user string

	addr, user = parseUpstreamFile(`

a:123

`)

	if addr != "a:123" || user != "" {
		t.Fatalf("parse failed common with port")
	}

	addr, user = parseUpstreamFile(`
a:123
b:456
`)

	if addr != "a:123" || user != "" {
		t.Fatalf("parse multi line")
	}

	addr, user = parseUpstreamFile(`
host
`)

	if addr != "host:22" || user != "" {
		t.Fatalf("parse no port")
	}

	addr, user = parseUpstreamFile(`
user@github.com
`)

	if addr != "github.com:22" || user != "user" {
		t.Fatalf("parse no port with user")
	}

	addr, user = parseUpstreamFile(``)

	if addr != "" || user != "" {
		t.Fatalf("empty file")
	}

	addr, user = parseUpstreamFile(`
    
# comment
user@github.com
test@linode.com
`)

	if addr != "github.com:22" || user != "user" {
		t.Fatalf("multi line with comment")
	}
}

func TestFindUpstreamFromUserfile(t *testing.T) {
	user := "testuser"
	buildWorkingDir([]string{user}, t)
	defer cleanupWorkdir(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cant create fake server: %v", err)
	}
	defer listener.Close()

	go func() {
		c, err := listener.Accept()
		if err != nil {
			t.Errorf("fake server error %v", err)
			return
		}
		io.Copy(c, c)
		c.Close()
	}()

	addr := listener.Addr().String()
	t.Logf("fake server at %v", addr)

	err = ioutil.WriteFile(UserUpstreamFile.realPath(user), []byte(addr), 0777)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	t.Logf("testing file too open")
	_, _, err = findUpstreamFromUserfile(stubConnMetadata{user})
	if err == nil {
		t.Fatalf("should return err when file too open")
	}

	err = os.Chmod(UserUpstreamFile.realPath(user), 0400)
	if err != nil {
		t.Fatalf("cant change file mode %v", err)
	}

	t.Logf("testing conn dial to %v", addr)
	conn, _, err := findUpstreamFromUserfile(stubConnMetadata{user})
	if err != nil {
		t.Fatalf("findUpstreamFromUserfile failed %v", err)
	}
	defer conn.Close()

	d := []byte("hello")

	_, err = conn.Write(d)
	if err != nil {
		t.Fatalf("cant write to conn: %v", err)
	}

	b := make([]byte, len(d))
	_, err = conn.Read(b)

	if err != nil || !bytes.Equal(b, d) {
		t.Fatalf("conn to upstream does not work")
	}

	t.Logf("testing user not found")
	_, _, err = findUpstreamFromUserfile(stubConnMetadata{"nosuchuser"})
	if err == nil {
		t.Fatalf("should return err when finding nosuchuser")
	}
}

func TestMapPublicKeyFromUserfile(t *testing.T) {
	user := "testuser"
	buildWorkingDir([]string{user}, t)
	defer cleanupWorkdir(t)

	privateKey, _ := ssh.ParsePrivateKey(testdata.PEMBytes["rsa"])
	publicKey := privateKey.PublicKey()
	privateKey2, _ := ssh.ParsePrivateKey(testdata.PEMBytes["dsa"])

	_ = privateKey2

	err := ioutil.WriteFile(UserKeyFile.realPath(user), testdata.PEMBytes["rsa"], 0777)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	authKeys := ssh.MarshalAuthorizedKey(publicKey)
	err = ioutil.WriteFile(UserAuthorizedKeysFile.realPath(user), authKeys, 0777)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	t.Logf("testing file too open")

	// UserAuthorizedKeysFile
	_, err = mapPublicKeyFromUserfile(stubConnMetadata{user}, publicKey)
	if err == nil {
		t.Fatalf("should return err when file too open")
	}

	err = os.Chmod(UserAuthorizedKeysFile.realPath(user), 0600)
	if err != nil {
		t.Fatalf("cant change file mode %v", err)
	}

	// UserKeyFile
	_, err = mapPublicKeyFromUserfile(stubConnMetadata{user}, publicKey)
	if err == nil {
		t.Fatalf("should return err when file too open")
	}

	err = os.Chmod(UserKeyFile.realPath(user), 0600)
	if err != nil {
		t.Fatalf("cant change file mode %v", err)
	}

	t.Logf("testing user not found")
	_, err = mapPublicKeyFromUserfile(stubConnMetadata{"nosuchuser"}, publicKey)
	if err == nil {
		t.Fatalf("should return err when mapping from nosuchuser")
	}

	t.Logf("testing mapping signer")
	signer, err := mapPublicKeyFromUserfile(stubConnMetadata{user}, privateKey.PublicKey())
	if err != nil {
		t.Fatalf("error mapping key %v", err)
	}

	if !bytes.Equal(signer.PublicKey().Marshal(), privateKey.PublicKey().Marshal()) {
		t.Fatalf("id_rsa not the same")
	}

	t.Logf("testing not in UserAuthorizedKeysFile")

	authKeys = ssh.MarshalAuthorizedKey(privateKey2.PublicKey())
	err = ioutil.WriteFile(UserAuthorizedKeysFile.realPath(user), authKeys, 0600)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	signer, err = mapPublicKeyFromUserfile(stubConnMetadata{user}, privateKey.PublicKey())
	if signer != nil {
		t.Fatalf("should not map private key when public key not in UserAuthorizedKeysFile")
	}
}
