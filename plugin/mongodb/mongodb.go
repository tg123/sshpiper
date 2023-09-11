//go:build full || e2e

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/patrickmn/go-cache"
	"github.com/tg123/sshpiper/libplugin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
	"regexp"
	"time"
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

type mongoDBPlugin struct {
	URI        string
	Database   string
	Collection string

	client     *mongo.Client
	collection *mongo.Collection
	cache      *cache.Cache
}

func newMongoDBPlugin() *mongoDBPlugin {
	return &mongoDBPlugin{
		cache: cache.New(1*time.Minute, 10*time.Minute),
	}
}

func (p *mongoDBPlugin) connect() error {
	if p.client != nil {
		if err := p.client.Ping(context.TODO(), nil); err == nil {
			return nil 
		}
	}

	ctx := context.TODO()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(p.URI))
	if err != nil {
		return err
	}

	p.client = client
	p.collection = client.Database(p.Database).Collection(p.Collection)

	return nil
}

func (p *mongoDBPlugin) supportedMethods() ([]string, error) {
	if err := p.connect(); err != nil {
		return nil, err
	}
	filter := bson.D{}

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

		for _, from := range mongoDoc.From {
			if from.AuthorizedKeysData != "" || from.AuthorizedKeys != "" {
				set["publickey"] = true // found authorized_keys, so we support publickey
			} else {
				set["password"] = true // no authorized_keys, so we support password
			}
		}
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	_ = cursor.Close(context.Background())

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}

func (p *mongoDBPlugin) verifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	if err := p.connect(); err != nil {
		return err
	}
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

func (p *mongoDBPlugin) createUpstream(conn libplugin.ConnMetadata, toDoc ToDoc, originPassword string) (*libplugin.Upstream, error) {

	host, port, err := libplugin.SplitHostPortForSSH(toDoc.Host)
	if err != nil {
		return nil, err
	}

	u := &libplugin.Upstream{
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
		u.Auth = libplugin.CreatePasswordAuth([]byte(pass))
		return u, nil
	}

	if toDoc.PrivateKeyData != "" {
		privateKey, err := base64.StdEncoding.DecodeString(toDoc.PrivateKeyData)
		if err != nil {
			return nil, fmt.Errorf("error decoding private key: %v", err)
		}

		u.Auth = libplugin.CreatePrivateKeyAuth(privateKey)
		return u, nil
	}
	return nil, fmt.Errorf("no password or private key found")
}

func (p *mongoDBPlugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	if err := p.connect(); err != nil {
		return nil, err
	}
	var mongoDocs []MongoDoc

	user := conn.User()
	filter := bson.D{{Key: "from.username", Value: user}}

	cursor, err := p.collection.Find(context.Background(), filter)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(context.Background(), &mongoDocs); err != nil {
		return nil, err
	}

	for _, mongoDoc := range mongoDocs {
		for _, from := range mongoDoc.From {
			matched := from.Username == user

			if from.UsernameRegexMatch {
				matched, _ = regexp.MatchString(from.Username, user)
			}

			if !matched {
				continue
			}

			if publicKey == nil && password != "" {
				return p.createUpstream(conn, mongoDoc.To, password)
			}

			if from.AuthorizedKeysData != "" {
				authorizedKeysB64 := []byte(from.AuthorizedKeysData)
				var authedPubkey ssh.PublicKey

				for len(authorizedKeysB64) > 0 {
					authedPubkey, _, _, authorizedKeysB64, err = ssh.ParseAuthorizedKey(authorizedKeysB64)

					if err != nil {
						return nil, err
					}

					if bytes.Equal(authedPubkey.Marshal(), publicKey) {
						return p.createUpstream(conn, mongoDoc.To, "")
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("cannot find a matching document for username [%v] found", user)
}
