// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"bytes"
	//"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"testing"
)

func buildWorkingDir(users []string, t *testing.T) {
	WorkingDir = ""
	dir, err := ioutil.TempDir(os.TempDir(), "sshpiperd_workingdir")

	if err != nil {
		t.Fatalf("setup temp dir:%v", err)
	}

	WorkingDir = dir

	for _, u := range users {
		os.Mkdir(WorkingDir+"/"+u, os.ModePerm)
	}

	t.Logf("switch workingdir to %v", WorkingDir)
}

func cleanupWorkdir(t *testing.T) {
	if WorkingDir == "" {
		return
	}

	t.Logf("cleaning workingdir %v", WorkingDir)

	os.RemoveAll(WorkingDir)
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

	err = os.Chmod(f.realPath(user), 0400)
	if err != nil {
		t.Fatalf("cant change file mode %v", err)
	}

	err = f.checkPerm(user)
	if err != nil {
		t.Fatalf("fail when read 0400 user file", err)
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
		c, _ := listener.Accept()
		io.Copy(c, c)
		c.Close()
	}()

	addr := listener.Addr().String()
	t.Logf("fake server at %v", addr)

	err = ioutil.WriteFile(UserUpstreamFile.realPath(user), []byte(addr), 0400)
	if err != nil {
		t.Fatalf("cant create file: %v", err)
	}

	t.Logf("testing conn dial to %v", addr)
	conn, err := findUpstreamFromUserfile(stubConnMetadata{user})

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
	_, err = findUpstreamFromUserfile(stubConnMetadata{"nosuchuser"})
	if err == nil {
		t.Fatalf("should return err when finding nosuchuser")
	}

}
