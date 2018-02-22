package sshkey

import (
	"fmt"
	"testing"
)

func StubPasswordPrompt(prompt string) (password string, err error) {
	return "foo bar", nil
}

type pubTest struct {
	FileName    string
	Fingerprint string
	Type        Type
	Size        int
}

var pubTests = []pubTest{
	pubTest{
		FileName:    "testdata/test_rsa.pub",
		Fingerprint: "d3:86:5e:77:d4:b7:52:fb:61:39:38:43:31:bb:a2:76",
		Type:        KEY_RSA,
		Size:        2048,
	},
	pubTest{
		FileName:    "testdata/test2_rsa.pub",
		Fingerprint: "a8:02:c1:3f:d8:08:16:84:5f:82:4f:08:6c:2e:98:5b",
		Type:        KEY_RSA,
		Size:        2048,
	},
	pubTest{
		FileName:    "testdata/test_ecdsa.pub",
		Fingerprint: "04:12:2a:3f:e6:ef:da:05:ad:86:72:44:e2:bb:45:d9",
		Type:        KEY_ECDSA,
		Size:        256,
	},
	pubTest{
		FileName:    "testdata/test2_ecdsa.pub",
		Fingerprint: "1f:7f:1d:f1:72:b5:f9:21:dd:38:bf:d0:68:80:85:78",
		Type:        KEY_ECDSA,
		Size:        256,
	},
	pubTest{
		FileName:    "testdata/test_dsa.pub",
		Fingerprint: "a0:21:8c:1c:f4:4f:45:b4:1c:2a:a9:47:4b:7f:ba:f0",
		Type:        KEY_DSA,
		Size:        1024,
	},
	pubTest{
		FileName:    "testdata/test2_dsa.pub",
		Fingerprint: "04:65:87:9f:ae:6d:d6:56:6d:b3:a9:e6:4f:d7:e9:25",
		Type:        KEY_DSA,
		Size:        1024,
	},
}

var fingerprintList map[string]string
var privList = []string{
	"testdata/test_rsa",
	"testdata/test2_rsa",
	"testdata/test_ecdsa",
	"testdata/test2_ecdsa",
	"testdata/test_dsa",
	"testdata/test2_dsa",
}

func init() {
	PasswordPrompt = StubPasswordPrompt
}

func TestLoadPublicKeys(t *testing.T) {
	for _, tc := range pubTests {
		pub, err := LoadPublicKeyFile(tc.FileName, true)
		if err != nil {
			fmt.Println(tc.FileName)
			fmt.Println(err.Error())
			t.FailNow()
		}
		fpr, err := FingerprintPretty(pub, 0)
		if err != nil {
			fmt.Println(tc.FileName)
			fmt.Println(err.Error())
			t.FailNow()
		}
		if fpr != tc.Fingerprint {
			fmt.Printf("sshkey: bad fingerprint %s\n\texpected: %s\n",
				fpr, tc.Fingerprint)
			t.FailNow()
		} else if pub.Size() != tc.Size {
			fmt.Println(tc.FileName)
			fmt.Printf("sshkey: bad key size %d bits: expected %d bits\n",
				pub.Size(), tc.Size)
			t.FailNow()
		}
	}
}

func TestLoadPrivateKeys(t *testing.T) {
	for _, keyFile := range privList {
		_, _, err := LoadPrivateKeyFile(keyFile)
		if err != nil {
			fmt.Println(keyFile)
			fmt.Println(err.Error())
			t.FailNow()
		}
	}
}
