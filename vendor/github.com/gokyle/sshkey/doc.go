/*
Package sshkey provides Go handling of OpenSSH keys. It handles RSA
(protocol 2 only) and ECDSA keys, and aims to provide interoperability
between OpenSSH and Go programs.

The package can import public and private keys using the LoadPublicKey
and LoadPrivateKey functions; the LoadPublicKeyFile and LoadPrivateKeyfile
functions are wrappers around these functions to load the key from
a file. For example:

    // true tells LoadPublicKey to load the file locally; if false, it
    // will try to load the key over HTTP.
    pub, err := LoadPublicKeyFile("/home/user/.ssh/id_ecdsa.pub", true)
    if err != nil {
        fmt.Println(err.Error())
        return
    }

In this example, the ECDSA key is in pub.Key. In order to be used in functions
that require a *ecdsa.PublicKey type, it must be typecast:

    ecpub := pub.Key.(*ecdsa.PublicKey)

The SSHPublicKey can be marshalled to OpenSSH format by using
MarshalPublicKey.

The package also provides support for generating new keys. The
GenerateSSHKey function can be used to generate a new key in the
appropriate Go package format (e.g. *ecdsa.PrivateKey). This key
can be marshalled into a PEM-encoded OpenSSH key using the
MarshalPrivate function.
*/
package sshkey
