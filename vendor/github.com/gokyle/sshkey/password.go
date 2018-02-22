package sshkey

// This file contains utillity functions for decrypting password protecting keys
// and password protecting keys.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

// The PasswordPrompt function is the function that is called to prompt the user for
// a password.
var PasswordPrompt func(prompt string) (password string, err error) = DefaultPasswordPrompt

var (
	ErrInvalidDEK      = fmt.Errorf("sshkey: invalid DEK info")
	ErrUnableToDecrypt = fmt.Errorf("sshkey: unable to decrypt key")
)

func decrypt(raw []byte, dekInfo string) (key []byte, err error) {
	dekInfoMap := strings.Split(dekInfo, ",")
	if len(dekInfoMap) != 2 {
		return nil, ErrInvalidDEK
	}
	algo := dekInfoMap[0]
	iv, err := hex.DecodeString(dekInfoMap[1])
	if err != nil {
		return
	}

	password, err := PasswordPrompt("SSH key password: ")
	if err != nil {
		return
	}
	aeskey, err := opensshKDF(iv, []byte(password))
	if err != nil {
		return
	}

	switch algo {
	case "AES-128-CBC":
		key, err = aesCBCdecrypt(aeskey, iv, raw)
	default:
		err = ErrUnableToDecrypt
	}
	return
}

func opensshKDF(iv []byte, password []byte) (key []byte, err error) {
	hash := md5.New()
	hash.Write(password)
	hash.Write(iv[:8])
	key = hash.Sum(nil)
	return
}

// DefaultPasswordPrompt is a simple (but echoing) password entry function
// that takes a prompt and reads the password.
func DefaultPasswordPrompt(prompt string) (password string, err error) {
	fmt.Printf(prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	password = strings.TrimSpace(line)
	return
}

func aesCBCdecrypt(aeskey, iv, ct []byte) (key []byte, err error) {
	c, err := aes.NewCipher(aeskey)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	key = make([]byte, len(ct))
	cbc.CryptBlocks(key, ct)
	key = sshUnpad(key)
	return
}

// PKCS #5 padding scheme
func sshUnpad(padded []byte) (unpadded []byte) {
	paddedLen := len(padded)
	var padnum int = int(padded[paddedLen-1])
	stop := len(padded) - padnum
	return padded[:stop]
}

func sshPad(unpadded []byte) (padded []byte) {
	padLen := ((len(unpadded) + 15) / 16) * 16

	padded = make([]byte, padLen)
	padding := make([]byte, padLen-len(unpadded))
	for i := 0; i < len(padding); i++ {
		padding[i] = byte(len(padding))
	}

	copy(padded, unpadded)
	copy(padded[len(unpadded):], padding)
	return
}

func generateIV() (iv []byte, err error) {
	iv = make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	return
}

func aesCBCencrypt(aeskey, key, iv []byte) (ct []byte, err error) {
	c, err := aes.NewCipher(aeskey)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	ct = sshPad(key)
	cbc.CryptBlocks(ct, ct)
	return
}

func encryptKey(key []byte, password string) (cryptkey, iv []byte, err error) {
	iv, err = generateIV()
	if err != nil {
		return
	}

	aeskey, err := opensshKDF(iv, []byte(password))
	if err != nil {
		return
	}

	cryptkey, err = aesCBCencrypt(aeskey, key, iv)
	return
}

func encrypt(key []byte, keytype Type, password string) (out []byte, err error) {
	cryptkey, iv, err := encryptKey(key, password)
	if err != nil {
		return
	}

	var block pem.Block
	switch keytype {
	case KEY_RSA:
		block.Type = "RSA PRIVATE KEY"
	case KEY_ECDSA:
		block.Type = "EC PRIVATE KEY"
	case KEY_DSA:
		block.Type = "DSA PRIVATE KEY"
	default:
		err = ErrInvalidPrivateKey
		return
	}
	block.Bytes = cryptkey
	block.Headers = make(map[string]string)
	block.Headers["Proc-Type"] = "4,ENCRYPTED"
	block.Headers["DEK-Info"] = fmt.Sprintf("AES-128-CBC,%X", iv)
	out = pem.EncodeToMemory(&block)
	return
}
