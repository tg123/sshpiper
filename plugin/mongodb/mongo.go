package main

import (
	"bytes"
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/tg123/sshpiper/libplugin"
	"time"
	"fmt"
	"github.com/patrickmn/go-cache"
	"go.mongodb.org/mongo-driver/bson"
)


type FromDoc struct {
	Username           string `bson:"username"`
	UsernameRegexMatch bool   `bson:"username_regex_match,omitempty"`
	AuthorizedKeys     string `bson:"authorized_keys,omitempty"`
	AuthorizedKeysData string `bson:"authorized_keys_data,omitempty"`
}

type ToDoc struct {
	Username       string `bson:"username,omitempty"`
	Host           string `bson:"host"`
	Password       string `bson:"password,omitempty"`
	PrivateKey     string `bson:"private_key,omitempty"`
	PrivateKeyData string `bson:"private_key_data,omitempty"`
	KnownHosts     string `bson:"known_hosts,omitempty"`
	KnownHostsData string `bson:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool   `bson:"ignore_hostkey,omitempty"`
}

type MongoDoc struct {
	ID   string    `bson:"_id"`
	From []FromDoc `bson:"from"`
	To   ToDoc     `bson:"to"`
}

type mongoPlugin struct {
	URI        string
	Database   string
	Collection string

	client     *mongo.Client
	collection *mongo.Collection
	cache      *cache.Cache
}

func newMongoPlugin() *mongoPlugin {
	return &mongoPlugin{
		cache: cache.New(1*time.Minute, 10*time.Minute),
	}
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


func (p *mongoPlugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	var mongoDoc MongoDoc

	filter := bson.D{{}}

	if err := p.collection.FindOne(context.Background(), filter).Decode(&mongoDoc); err != nil {
		return nil, err
	}

	from := mongoDoc.From[0] 
	to := mongoDoc.To

	if from.Username == conn.User() {
		if publicKey == nil && password != "" {
			return p.createUpstream(conn, to, password)
		}
	}

	return nil, errors.New("cannot find a matching document")
}

func (p *mongoPlugin) createUpstream(conn libplugin.ConnMetadata, toDoc ToDoc, originPassword string) (*libplugin.Upstream, error) {
	host, port, err := libplugin.SplitHostPortForSSH(toDoc.Host)
	if err != nil {
		return nil, err
	}

	upstream := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      toDoc.Username,
		IgnoreHostKey: toDoc.IgnoreHostkey,
	}

	pass := toDoc.Password
	if pass == "" {
		pass = originPassword
	}

	if pass != "" {
		upstream.Auth = libplugin.CreatePasswordAuth([]byte(pass))
		return upstream, nil
	}

	return nil, fmt.Errorf("no password or private key found")
}

func (p *mongoPlugin) verifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	item, found := p.cache.Get(conn.UniqueID())

	if !found {
		return errors.New("connection expired")
	}

	toDoc := item.(*ToDoc)

	if toDoc.KnownHostsData == "" {
		return errors.New("known hosts data is missing")
	}

	knownHosts := []byte(toDoc.KnownHostsData)
	return libplugin.VerifyHostKeyFromKnownHosts(bytes.NewBuffer(knownHosts), hostname, netaddr, key)
}

func (p *mongoPlugin) supportedMethods() ([]string, error) {
	filter := bson.D{{}}

	cursor, err := p.collection.Find(context.Background(), filter)
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for cursor.Next(context.Background()) {
		var mongoDoc MongoDoc
		err := cursor.Decode(&mongoDoc)
		if err != nil {
			return nil, err
		}

		if mongoDoc.From[0].AuthorizedKeysData != "" || mongoDoc.From[0].AuthorizedKeys != "" {
			set["publickey"] = true
		} else {
			set["password"] = true
		}
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	cursor.Close(context.Background())

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}