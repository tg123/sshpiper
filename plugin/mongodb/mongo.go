package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/tg123/sshpiper/libplugin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
)

type MongoDoc struct {
	ID              string `bson:"_id"`
	Username        string `bson:"username"`
	Password        string `bson:"password"`
	PublicKey       string `bson:"publicKey"`
	PrivateKey      string `bson:"privateKey"`
	KnownHosts      string `bson:"knownHosts"`
	UserForUpstream string `bson:"userForUpstream"`
	HostForUpstream string `bson:"hostForUpstream"`
	IgnoreHostkey   bool   `bson:"ignoreHostkey"`
}

type mongoPlugin struct {
	URI        string
	Database   string
	Collection string

	client   *mongo.Client
	collection *mongo.Collection
}

func newMongoPlugin() *mongoPlugin {
	return &mongoPlugin{}
}

func (p *mongoPlugin) connect() error {
	client, err := mongo.NewClient(options.Client().ApplyURI(p.URI))
	if err != nil {
		return err
	}

	ctx := context.TODO()
	err = client.Connect(ctx)
	if err != nil {
		return err
	}

	p.client = client
	p.collection = client.Database(p.Database).Collection(p.Collection)

	return nil
}

func (p *mongoPlugin) loadRecord(user string) (MongoDoc, error) {

	var record MongoDoc
	err := p.collection.FindOne(context.TODO(), bson.M{"_id": user}).Decode(&record)

	return record, err
}

func (p *mongoPlugin) hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

func (p *mongoPlugin) verifyPassword(password, hashedPassword string) bool {
	return p.hashPassword(password) == hashedPassword
}

func (p *mongoPlugin) verifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	record, err := p.loadRecord(conn.User())
	if err != nil {
		return err
	}

	return libplugin.VerifyHostKeyFromKnownHosts(bytes.NewReader([]byte(record.KnownHosts)), hostname, netaddr, key)
}
func (p *mongoPlugin) supportedMethods() ([]string, error) {
	return []string{"publickey", "password"}, nil
}
func (p *mongoPlugin) createUpstream(conn libplugin.ConnMetadata, password string) (*libplugin.Upstream, error) {

	record, err := p.loadRecord(conn.User())
	if err != nil {
		return nil, err
	}

	host, port, err := net.SplitHostPort(record.HostForUpstream)
	if err != nil {
		return nil, err
	}
	portNumber, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return nil, err
	}
	
	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(portNumber),
		UserName:      record.UserForUpstream,
		IgnoreHostKey: record.IgnoreHostkey,
	}

	if password != "" {
		u.Auth = libplugin.CreatePasswordAuth([]byte(password))
	} else if record.PrivateKey != "" {
		u.Auth = libplugin.CreatePrivateKeyAuth([]byte(record.PrivateKey))
	} else {
		return nil, fmt.Errorf("no authentication method for user [%v]", conn.User())
	}

	return u, nil
}
func (p *mongoPlugin) findAndCreateUpstream(conn libplugin.ConnMetadata, pwd string, pubKey []byte) (*libplugin.Upstream, error) {

	record, err := p.loadRecord(conn.User())
	if err != nil {
		return nil, err
	}

	if pubKey != nil { 
		userPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
		if err != nil { 
			return nil, err
		}
		if !bytes.Equal(pubKey, userPubKey.Marshal()) { 
			return nil, fmt.Errorf("provided public key for user [%v] does not match stored public key", conn.User())
		}
	} else { 
		if !p.verifyPassword(pwd, record.Password) {
			return nil, fmt.Errorf("invalid password for user [%v]", conn.User())
		}
	}

	return p.createUpstream(conn, pwd)
}