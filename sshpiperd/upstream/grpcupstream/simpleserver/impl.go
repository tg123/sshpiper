package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/tg123/sshpiper/sshpiperd/upstream/grpcupstream"
)

type server struct {
	grpcupstream.UnimplementedUpstreamRegistryServer

	ToType         string `long:"totype" default:"PASSTHROUGH"`
	ToAddr         string `long:"toaddr"`
	MappedUserName string `long:"mappeduser"`
	Password       string `long:"password"`
	PrivateKey     string `long:"privatekey"`
}

func (s *server) FindUpstream(_ context.Context, request *grpcupstream.FindUpstreamRequest) (*grpcupstream.FindUpstreamReply, error) {
	log.Printf("mapping [%v@%v] to [%v@%v]", request.UserName, request.FromAddr, s.MappedUserName, s.ToAddr)
	return &grpcupstream.FindUpstreamReply{
		ToAddr:         s.ToAddr,
		MappedUserName: s.MappedUserName,
	}, nil
}

func (s *server) VerifyHostKey(context.Context, *grpcupstream.VerifyHostKeyRequest) (*grpcupstream.VerifyHostKeyReply, error) {
	return &grpcupstream.VerifyHostKeyReply{
		Verified: true,
	}, nil
}

func (s *server) MapAuth(_ context.Context, request *grpcupstream.MapAuthRequest) (*grpcupstream.MapAuthReply, error) {
	totype := grpcupstream.MapAuthReply_Authtype(grpcupstream.MapAuthReply_Authtype_value[s.ToType])
	log.Printf("mapping auth [%v] to [%v]", request.AuthType, totype)

	// add your own auth here
	switch totype {
	case grpcupstream.MapAuthReply_PASSTHROUGH, grpcupstream.MapAuthReply_DISCARD, grpcupstream.MapAuthReply_NONE:
		return &grpcupstream.MapAuthReply{
			MappedAuthType: totype,
		}, nil
	case grpcupstream.MapAuthReply_PASSWORD:
		return &grpcupstream.MapAuthReply{
			MappedAuthType:  grpcupstream.MapAuthReply_PASSWORD,
			MappedAuthParam: []byte(s.Password),
		}, nil
	case grpcupstream.MapAuthReply_PRIVATEKEY:

		b, err := ioutil.ReadFile(s.PrivateKey)
		if err != nil {
			return nil, err
		}

		return &grpcupstream.MapAuthReply{
			MappedAuthType:  grpcupstream.MapAuthReply_PRIVATEKEY,
			MappedAuthParam: b,
		}, nil

	case grpcupstream.MapAuthReply_REMOTESIGNER:
		return &grpcupstream.MapAuthReply{
			MappedAuthType:  grpcupstream.MapAuthReply_REMOTESIGNER,
			MappedAuthParam: []byte(s.PrivateKey),
		}, nil
	}

	return nil, fmt.Errorf("unsupported to type")
}
