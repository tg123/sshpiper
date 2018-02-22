package sshkey

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
	"strings"
)

var (
	ErrInvalidDigest         = fmt.Errorf("sshkey: invalid digest algorithm")
	ErrInvalidKeySize        = fmt.Errorf("sshkey: invalid private key size")
	ErrInvalidPrivateKey     = fmt.Errorf("sshkey: invalid private key")
	ErrInvalidPublicKey      = fmt.Errorf("sshkey: invalid public key")
	ErrUnsupportedPublicKey  = fmt.Errorf("sshkey: unsupported public key type")
	ErrUnsupportedPrivateKey = fmt.Errorf("sshkey: unsupported private key type")
)

// PRNG contains the random data source to be used in key generation. It
// defaults to crypto/rand.Reader.
var PRNG io.Reader = rand.Reader

// Representation of type of SSH Key
type Type int

// Representation of an SSH public key in the library.
type SSHPublicKey struct {
	Type    Type
	Key     interface{}
	Comment string
}

// Given a private key and comment, NewPublic will return a new SSHPublicKey.
func NewPublic(priv interface{}, comment string) *SSHPublicKey {
	pub := new(SSHPublicKey)
	switch priv.(type) {
	case *rsa.PrivateKey:
		rsapub := &priv.(*rsa.PrivateKey).PublicKey
		pub.Type = KEY_RSA
		pub.Key = rsapub
		pub.Comment = comment
	case *ecdsa.PrivateKey:
		ecpub := &priv.(*ecdsa.PrivateKey).PublicKey
		pub.Type = KEY_ECDSA
		pub.Key = ecpub
		pub.Comment = comment
	case *dsa.PrivateKey:
		dsapub := &priv.(*dsa.PrivateKey).PublicKey
		pub.Type = KEY_DSA
		pub.Key = dsapub
		pub.Comment = comment
	default:
		return nil
	}

	return pub
}

// These constants are used as the key type in the SSHPublicKey.
const (
	KEY_UNSUPPORTED Type = iota - 1
	KEY_ECDSA
	KEY_RSA
	KEY_DSA
)

var pubkeyRegexp = regexp.MustCompile("(?m)^[a-z0-9-]+ (\\S+).*$")
var commentRegexp = regexp.MustCompile("(?m)^[a-z0-9-]+ (\\S+) (\\S*)$")

// fetchKey retrieves the raw data for a key, either via file or an HTTP get.
func fetchKey(name string, local bool) (kb []byte, err error) {
	if local {
		kb, err = ioutil.ReadFile(name)
	} else {
		var resp *http.Response
		resp, err = http.Get(name)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		kb, err = ioutil.ReadAll(resp.Body)
	}
	return
}

// LoadPublicKey loads an OpenSSH public key from a file or via HTTP. If
// local is false, the key will be fetched over HTTP.
func LoadPublicKeyFile(name string, local bool) (key *SSHPublicKey, err error) {
	kb64, err := fetchKey(name, local)
	return UnmarshalPublic(kb64)
}

// UnmarshalPublic decodes a byte slice containing an OpenSSH public key
// into an public key. It supports RSA and ECDSA keys.
func UnmarshalPublic(raw []byte) (key *SSHPublicKey, err error) {
	kb64 := pubkeyRegexp.ReplaceAll(raw, []byte("$1"))
	kb := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	i, err := base64.StdEncoding.Decode(kb, kb64)
	if err != nil {
		return
	}
	kb = kb[:i]

	key = new(SSHPublicKey)
	if commentRegexp.Match(raw) {
		key.Comment = string(commentRegexp.ReplaceAll(raw, []byte("$3")))
		key.Comment = strings.TrimSpace(key.Comment)
	}

	switch {
	case bytes.HasPrefix(raw, []byte("ssh-rsa")):
		key.Type = KEY_RSA
		key.Key, err = parseRSAPublicKey(kb)
	case bytes.HasPrefix(raw, []byte("ecdsa")):
		key.Type = KEY_ECDSA
		key.Key, err = parseECDSAPublicKey(kb)
	case bytes.HasPrefix(raw, []byte("ssh-dss")):
		key.Type = KEY_DSA
		key.Key, err = parseDSAPublicKey(kb)
	default:
		key.Type = KEY_UNSUPPORTED
		err = ErrUnsupportedPublicKey
	}
	return
}

// Load an OpenSSH private key from a file.
func LoadPrivateKeyFile(name string) (key interface{}, keytype Type, err error) {
	kb, err := fetchKey(name, true)
	return UnmarshalPrivate(kb)
}

// Load an OpenSSH private key from a byte slice.
func UnmarshalPrivate(raw []byte) (key interface{}, keytype Type, err error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		err = ErrInvalidPrivateKey
		return
	} else {
		raw := block.Bytes
		if block.Headers != nil && len(block.Headers) != 0 {
			if dekInfo, ok := block.Headers["DEK-Info"]; ok {
				raw, err = decrypt(raw, dekInfo)
				if err != nil {
					return
				}
			}
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			keytype = KEY_RSA
			key, err = x509.ParsePKCS1PrivateKey(raw)
			if err == nil && key.(*rsa.PrivateKey).PublicKey.N.BitLen() < 2047 {
				fmt.Printf("[-] warning: SSH key is a weak key (consider ")
				fmt.Printf("upgrading to a 2048+ bit key.")
			} else if err != nil {
				err = ErrInvalidPrivateKey
			}
		case "EC PRIVATE KEY":
			keytype = KEY_ECDSA
			key, err = x509.ParseECPrivateKey(raw)
			if err != nil {
				err = ErrInvalidPrivateKey
			}
		case "DSA PRIVATE KEY":
			keytype = KEY_DSA
			k := struct {
				Version int
				P       *big.Int
				Q       *big.Int
				G       *big.Int
				Priv    *big.Int
				Pub     *big.Int
			}{}

			var rest []byte
			rest, err = asn1.Unmarshal(raw, &k)

			if err != nil {
				err = ErrInvalidPrivateKey
				return
			} else if len(rest) > 0 {
				err = ErrInvalidPrivateKey
				return
			}

			key = &dsa.PrivateKey{
				PublicKey: dsa.PublicKey{
					Parameters: dsa.Parameters{
						P: k.P,
						Q: k.Q,
						G: k.G,
					},
					Y: k.Priv,
				},
				X: k.Pub,
			}

			if key.(*dsa.PrivateKey).PublicKey.P.BitLen() < 1023 {
				fmt.Printf("[-] warning: SSH key is a weak key (consider ")
				fmt.Printf("upgrading to a 1023+ bit key.")
			}
		default:
			err = ErrUnsupportedPrivateKey
			return
		}
	}
	return
}

func parseRSAPublicKey(raw []byte) (key *rsa.PublicKey, err error) {
	buf := bytes.NewBuffer(raw)
	var algorithm, exponent, modulus []byte
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, algorithm)
	if err != nil {
		return
	}
	if string(algorithm) != "ssh-rsa" {
		err = ErrInvalidPublicKey
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	exponent = make([]byte, length)
	_, err = io.ReadFull(buf, exponent)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	modulus = make([]byte, length)
	_, err = io.ReadFull(buf, modulus)
	if err != nil {
		return
	}

	key = new(rsa.PublicKey)
	key.N = new(big.Int).SetBytes(modulus)
	key.E = int(new(big.Int).SetBytes(exponent).Int64())
	if key.N.BitLen() < 2047 {
		fmt.Printf("[-] warning: SSH key is a weak key (consider ")
		fmt.Println("upgrading to a 2048+ bit key).")
	}
	return
}

func parseECDSAPublicKey(raw []byte) (key *ecdsa.PublicKey, err error) {
	buf := bytes.NewBuffer(raw)
	var algorithm, curveName, public []byte
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, algorithm)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	curveName = make([]byte, length)
	_, err = io.ReadFull(buf, curveName)
	if err != nil {
		return
	}

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}
	public = make([]byte, length)
	_, err = io.ReadFull(buf, public)
	if err != nil {
		return
	}

	key = new(ecdsa.PublicKey)
	var curve elliptic.Curve
	switch string(curveName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		err = ErrUnsupportedPublicKey
		return
	}

	key.X, key.Y = elliptic.Unmarshal(curve, public)
	if key.X == nil {
		err = ErrInvalidPublicKey
		return
	}
	key.Curve = curve
	return
}

func parseDSAPublicKey(raw []byte) (key *dsa.PublicKey, err error) {
	buf := bytes.NewBuffer(raw)
	var algorithm []byte
	var length int32

	err = binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return
	}

	algorithm = make([]byte, length)
	_, err = io.ReadFull(buf, algorithm)
	if err != nil {
		return
	}

	if string(algorithm) != "ssh-dss" {
		err = ErrInvalidPublicKey
		return
	}

	parseInt := func(in io.Reader) (*big.Int, error) {
		var length int32
		if err := binary.Read(in, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		val := make([]byte, length)
		if _, err := io.ReadFull(in, val); err != nil {
			return nil, err
		}

		return new(big.Int).SetBytes(val), nil
	}

	key = new(dsa.PublicKey)

	key.P, err = parseInt(buf)
	if err != nil {
		return
	}

	key.Q, err = parseInt(buf)
	if err != nil {
		return
	}

	key.G, err = parseInt(buf)
	if err != nil {
		return
	}

	key.Y, err = parseInt(buf)
	if err != nil {
		return
	}

	return

}

func uint32ToBlob(n uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, n)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func curveName(curve elliptic.Curve) []byte {
	switch curve {
	case elliptic.P256():
		return []byte("nistp256")
	case elliptic.P384():
		return []byte("nistp384")
	case elliptic.P521():
		return []byte("nistp521")
	default:
		return nil
	}
}

func publicToBlob(pub *SSHPublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)

	switch pub.Key.(type) {
	case *rsa.PublicKey:
		rsapub := pub.Key.(*rsa.PublicKey)
		tag1 := uint32ToBlob(7) // 7 characters for 'ssh-rsa'
		if tag1 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag1)
		buf.Write([]byte("ssh-rsa"))

		E := big.NewInt(int64(rsapub.E)).Bytes()
		tag2 := uint32ToBlob(uint32(len(E)))
		if tag2 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag2)
		buf.Write(E)

		N := rsapub.N.Bytes()
		tag3 := uint32ToBlob(uint32(len(N) + 1))
		if tag3 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag3)
		buf.Write([]byte{0})
		buf.Write(N)
	case *ecdsa.PublicKey:
		ecpub := pub.Key.(*ecdsa.PublicKey)
		cname := curveName(ecpub.Curve)
		if cname == nil {
			return nil, ErrInvalidPublicKey
		}
		algo := []byte(fmt.Sprintf("ecdsa-sha2-%s", string(cname)))
		tag1 := uint32ToBlob(uint32(len(algo)))
		if tag1 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag1)
		buf.Write(algo)

		tag2 := uint32ToBlob(uint32(len(cname)))
		if tag2 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag2)
		buf.Write(cname)

		pubkey := elliptic.Marshal(ecpub.Curve, ecpub.X, ecpub.Y)
		if pubkey == nil {
			return nil, ErrInvalidPublicKey
		}
		tag3 := uint32ToBlob(uint32(len(pubkey)))
		if tag3 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag3)
		buf.Write(pubkey)
	case *dsa.PublicKey:
		dsapub := pub.Key.(*dsa.PublicKey)
		tag1 := uint32ToBlob(7) // 7 characters for 'ssh-rsa'
		if tag1 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag1)
		buf.Write([]byte("ssh-dss"))

		P := dsapub.P.Bytes()
		tag2 := uint32ToBlob(uint32(len(P) + 1))
		if tag2 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag2)
		buf.Write([]byte{0})
		buf.Write(P)

		Q := dsapub.Q.Bytes()
		tag3 := uint32ToBlob(uint32(len(Q) + 1))
		if tag3 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag3)
		buf.Write([]byte{0})
		buf.Write(Q)

		G := dsapub.G.Bytes()
		tag4 := uint32ToBlob(uint32(len(G)))
		if tag4 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag4)
		buf.Write(G)

		Y := dsapub.Y.Bytes()
		tag5 := uint32ToBlob(uint32(len(Y)))
		if tag5 == nil {
			return nil, ErrInvalidPublicKey
		}
		buf.Write(tag5)
		buf.Write(Y)

	default:
		return nil, ErrInvalidPublicKey
	}

	return buf.Bytes(), nil
}

// Given a private key and a (possibly empty) password, returns a byte
// slice containing a PEM-encoded private key in the appropriate
// OpenSSH format.
func MarshalPrivate(priv interface{}, password string) (out []byte, err error) {
	var (
		keytype Type
		der     []byte
		btype   string
	)

	switch priv.(type) {
	case *rsa.PrivateKey:
		keytype = KEY_RSA
		der = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
		if der == nil {
			err = ErrInvalidPrivateKey
			return
		}
		btype = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keytype = KEY_ECDSA
		der, err = marshalECDSAKey(priv.(*ecdsa.PrivateKey))
		btype = "EC PRIVATE KEY"
	case *dsa.PrivateKey:
		keytype = KEY_DSA

		dsakey := priv.(*dsa.PrivateKey)
		k := struct {
			Version int
			P       *big.Int
			Q       *big.Int
			G       *big.Int
			Priv    *big.Int
			Pub     *big.Int
		}{
			Version: 1,
			P:       dsakey.PublicKey.P,
			Q:       dsakey.PublicKey.Q,
			G:       dsakey.PublicKey.G,
			Priv:    dsakey.PublicKey.Y,
			Pub:     dsakey.X,
		}
		der, err = asn1.Marshal(k)
		if err != nil {
			return
		}
		btype = "DSA PRIVATE KEY"
	default:
		err = ErrInvalidPrivateKey
		return
	}

	if password != "" {
		out, err = encrypt(der, keytype, password)
		return
	}
	var block pem.Block
	block.Type = btype
	block.Bytes = der
	out = pem.EncodeToMemory(&block)
	return
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func marshalECDSAKey(priv *ecdsa.PrivateKey) (out []byte, err error) {
	var eckey ecPrivateKey

	eckey.Version = 1
	eckey.PrivateKey = priv.D.Bytes()
	switch priv.PublicKey.Curve {
	case elliptic.P256():
		eckey.NamedCurveOID = oidNamedCurveP256
	case elliptic.P384():
		eckey.NamedCurveOID = oidNamedCurveP384
	case elliptic.P521():
		eckey.NamedCurveOID = oidNamedCurveP521
	default:
		err = ErrInvalidPrivateKey
	}

	pkey := elliptic.Marshal(priv.PublicKey.Curve, priv.PublicKey.X,
		priv.PublicKey.Y)
	if pkey == nil {
		err = ErrInvalidPrivateKey
		return
	}

	eckey.PublicKey = asn1.BitString{
		BitLength: len(pkey) * 8,
		Bytes:     pkey,
	}
	out, err = asn1.Marshal(eckey)
	return
}

// MarshalPublic returns a byte slice containing an OpenSSH public key built
// from the SSHPublicKey.
func MarshalPublic(pub *SSHPublicKey) (out []byte) {
	blob, err := publicToBlob(pub)
	if err != nil {
		return nil
	}
	encodedBlob := base64.StdEncoding.EncodeToString(blob)

	var algo string

	switch pub.Type {
	case KEY_RSA:
		algo = "ssh-rsa"
	case KEY_ECDSA:
		algo = fmt.Sprintf("ecdsa-sha2-%s",
			curveName(pub.Key.(*ecdsa.PublicKey).Curve))
	default:
		return nil
	}

	out = []byte(fmt.Sprintf("%s %s %s", algo, encodedBlob, pub.Comment))
	return
}

// Return the bitsize of the underlying public key.
func (key *SSHPublicKey) Size() int {
	switch key.Type {
	case KEY_RSA:
		return key.Key.(*rsa.PublicKey).N.BitLen()
	case KEY_ECDSA:
		return key.Key.(*ecdsa.PublicKey).Curve.Params().BitSize
	case KEY_DSA:
		return key.Key.(*dsa.PublicKey).P.BitLen()
	default:
		return 0
	}
}

// Generates a compatible OpenSSH private key. The key is in the
// raw Go key format. To convert this to a PEM encoded key, see
// MarshalPrivate.
func GenerateKey(keytype Type, size int) (key interface{}, err error) {
	switch keytype {
	case KEY_RSA:
		if size < 2048 {
			return nil, ErrInvalidKeySize
		}
		var rsakey *rsa.PrivateKey
		rsakey, err = rsa.GenerateKey(PRNG, size)
		if err != nil {
			return
		}
		key = rsakey
	case KEY_ECDSA:
		var eckey *ecdsa.PrivateKey
		switch size {
		case 256:
			eckey, err = ecdsa.GenerateKey(elliptic.P256(), PRNG)
		case 384:
			eckey, err = ecdsa.GenerateKey(elliptic.P384(), PRNG)
		case 521:
			eckey, err = ecdsa.GenerateKey(elliptic.P521(), PRNG)
		default:
			return nil, ErrInvalidKeySize
		}
		key = eckey
	case KEY_DSA:
		var sizes dsa.ParameterSizes
		switch size {
		case 1024:
			sizes = dsa.L1024N160
		case 2048:
			sizes = dsa.L2048N256
		case 3072:
			sizes = dsa.L3072N256
		default:
			err = ErrInvalidKeySize
			return
		}

		params := dsa.Parameters{}
		err = dsa.GenerateParameters(&params, rand.Reader, sizes)
		if err != nil {
			return
		}

		dsakey := &dsa.PrivateKey{
			PublicKey: dsa.PublicKey{
				Parameters: params,
			},
		}
		err = dsa.GenerateKey(dsakey, rand.Reader)
		if err != nil {
			return
		}
		key = dsakey
	}

	return
}

// Return the fingerprint of the key in a raw format.
func Fingerprint(pub *SSHPublicKey, hashalgo crypto.Hash) (fpr []byte, err error) {
	var h hash.Hash

	// The default algorithm for OpenSSH appears to be MD5.
	if hashalgo == 0 {
		hashalgo = crypto.MD5
	}

	switch hashalgo {
	case crypto.MD5:
		h = md5.New()
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	default:
		return nil, ErrInvalidDigest
	}

	blob, err := publicToBlob(pub)
	if err != nil {
		return nil, err
	}
	h.Write(blob)

	return h.Sum(nil), nil
}

// Return a string containing a printable form of the key's fingerprint.
func FingerprintPretty(pub *SSHPublicKey, hashalgo crypto.Hash) (fpr string, err error) {
	fprBytes, err := Fingerprint(pub, hashalgo)
	if err != nil {
		return
	}

	for _, v := range fprBytes {
		fpr += fmt.Sprintf("%02x:", v)
	}
	fpr = fpr[:len(fpr)-1]
	return
}
