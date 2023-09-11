package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"testing"
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

const mongoDocumentTemplate = `[{
	"from": [
	  {
		"username": "password_simple"
	  }
	],
	"to": {
	  "username": "user",
	  "host": "host-password:2222",
	  "ignore_hostkey": true
	}
  },
  {
	"from": [
	  {
		"username": "password_.*_regex",
		"username_regex_match": true
	  }
	],
	"to": {
	  "username": "user",
	  "host": "host-password:2222",
	  "ignore_hostkey": true
	}
  }]`

const mongoURI = "mongodb://mongodb:27017"
const mongoDataBase = "sshpiper_test"
const mongoCollection = "config"

func TestMongoDB(t *testing.T) {
	// Connect to MongoDB
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		t.Fatalf("Failed to connect to DB: %v", err)
	}
	defer func() {
		ctx := context.Background()
		if err := client.Database(mongoDataBase).Drop(ctx); err != nil {
			t.Errorf("Could not drop test database: %v", err)
		}
		if err := client.Disconnect(ctx); err != nil {
			t.Errorf("Could not disconnect from DB %v", err)
		}
	}()

	// Check and Create Database (if not exists)
	if err := client.Database(mongoDataBase).CreateCollection(context.Background(), mongoCollection); err != nil {
		t.Fatalf("Failed to create collection: %v", err)
	}

	// Insert dummy data
	var docs []bson.M
	err = json.Unmarshal([]byte(mongoDocumentTemplate), &docs)
	if err != nil {
		t.Fatalf("Invalid dummy data: %v", err)
	}

	collection := client.Database(mongoDataBase).Collection(mongoCollection)
	var interfaces []interface{}
	for _, d := range docs {
		interfaces = append(interfaces, d)
	}

	_, err = collection.InsertMany(context.Background(), interfaces)
	if err != nil {
		t.Fatalf("Failed to insert document: %v", err)
	}

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/mongodb",
		"--uri",
		mongoURI,
		"--database",
		mongoDataBase,
		"--collection",
		mongoCollection,
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	t.Run("password_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"password_simple",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_regex", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"password_XXX_regex",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})
}
