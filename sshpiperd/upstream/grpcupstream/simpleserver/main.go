package main

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"unsafe"

	"github.com/jessevdk/go-flags"
	"github.com/tg123/remotesigner/grpcsigner"
	"github.com/tg123/sshpiper/sshpiperd/upstream/grpcupstream"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type args struct {
	ListenAddr string `short:"l" long:"listen" default:"0.0.0.0"`
	Port       uint   `short:"p" long:"port" default:"2233"`
	server
}

func main() {
	var c args

	if _, err := flags.Parse(&c); err != nil {
		log.Fatalf("parse args %v", err)
	}

	addr := fmt.Sprintf("%v:%v", c.ListenAddr, c.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen on %v failed %v", addr, err)
	}

	if _, ok := grpcupstream.MapAuthReply_Authtype_value[c.ToType]; !ok {
		log.Fatalf("totype [%v] not allowed", c.ToType)
	}

	s := grpc.NewServer()
	grpcupstream.RegisterUpstreamRegistryServer(s, &c.server)

	if c.PrivateKey != "" {
		gs, err := grpcsigner.NewSignerServer(func(string) crypto.Signer {
			b, err := ioutil.ReadFile(c.PrivateKey)
			if err != nil {
				log.Fatalf("private key [%v] load failed %v", c.PrivateKey, err)
			}

			private, err := ssh.ParsePrivateKey(b)
			if err != nil {
				log.Fatalf("private key [%v] parse failed %v", c.PrivateKey, err)
			}

			field := reflect.ValueOf(private).Elem().FieldByName("signer")
			signer := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(crypto.Signer)

			log.Printf("remote signing with %v", c.PrivateKey)
			return signer
		})
		if err != nil {
			log.Fatalf("start grpc signer failed %v", err)
		}

		grpcsigner.RegisterSignerServer(s, gs)
	}

	log.Printf("serving on %v", addr)
	panic(s.Serve(l))
}
