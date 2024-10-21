package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"time"

	gocache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"github.com/tg123/sshpiper/libplugin"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	sshpiper "github.com/tg123/sshpiper/plugin/kubernetes/generated/clientset/versioned"
	piperlister "github.com/tg123/sshpiper/plugin/kubernetes/generated/listers/sshpiper/v1beta1"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type plugin struct {
	k8sclient corev1.CoreV1Interface
	lister    piperlister.PipeLister
	stop      chan<- struct{}
	cache     *gocache.Cache
}

func newKubernetesPlugin(allNamespaces bool, kubeConfigPath string) (*plugin, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	loader.ExplicitPath = kubeConfigPath
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loader,
		&clientcmd.ConfigOverrides{},
	)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	ns, _, err := kubeConfig.Namespace()
	if err != nil {
		return nil, err
	}
	if allNamespaces {
		ns = metav1.NamespaceAll
	}

	k8sclient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	piperclient, err := sshpiper.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	listWatcher := cache.NewListWatchFromClient(piperclient.SshpiperV1beta1().RESTClient(), "pipes", ns, fields.Everything())
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	lister := piperlister.NewPipeLister(store)
	reflector := cache.NewReflector(listWatcher, &piperv1beta1.Pipe{}, store, 0)

	stop := make(chan struct{})
	go reflector.Run(stop)

	return &plugin{
		k8sclient: k8sclient.CoreV1(),
		lister:    lister,
		stop:      stop,
		cache:     gocache.New(1*time.Minute, 10*time.Minute),
	}, nil
}

func (p *plugin) Stop() {
	p.stop <- struct{}{}
}

func (p *plugin) list() ([]*piperv1beta1.Pipe, error) {
	return p.lister.List(labels.Everything())
}

func (p *plugin) supportedMethods() ([]string, error) {
	pipes, err := p.list()
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for _, pipe := range pipes {
		for _, from := range pipe.Spec.From {
			if from.AuthorizedKeysData != "" || from.AuthorizedKeysFile != "" {
				set["publickey"] = true // found authorized_keys, so we support publickey
			} else {
				set["password"] = true // no authorized_keys, so we support password
			}

			if from.HtpasswdData != "" || from.HtpasswdFile != "" {
				set["password"] = true // found htpasswd, so we support password
			}
		}
	}

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}

func (p *plugin) verifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	item, found := p.cache.Get(conn.UniqueID())

	if !found {
		return fmt.Errorf("connection expired")
	}

	pipe := item.(*piperv1beta1.Pipe)
	to := pipe.Spec.To

	data, err := base64.StdEncoding.DecodeString(to.KnownHostsData)
	if err != nil {
		return err
	}

	return libplugin.VerifyHostKeyFromKnownHosts(bytes.NewBuffer(data), hostname, netaddr, key)
}

func (p *plugin) createUpstream(conn libplugin.ConnMetadata, pipe *piperv1beta1.Pipe, originPassword string) (*libplugin.Upstream, error) {
	to := pipe.Spec.To
	host, port, err := libplugin.SplitHostPortForSSH(to.Host)
	if err != nil {
		return nil, err
	}

	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      to.Username,
		IgnoreHostKey: to.IgnoreHostkey,
	}

	if to.PrivateKeySecret.Name != "" {
		log.Debugf("mapping to %v private key using secret %v", to.Host, to.PrivateKeySecret.Name)
		secret, err := p.k8sclient.Secrets(pipe.Namespace).Get(context.Background(), to.PrivateKeySecret.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		anno := pipe.GetAnnotations()
		var publicKey []byte
		var privateKey []byte

		for _, k := range []string{anno["privatekey_field_name"], "ssh-privatekey", "privatekey"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found private key in secret %v/%v", to.PrivateKeySecret.Name, k)
				privateKey = data
				break
			}
		}

		for _, k := range []string{anno["publickey_field_name"], "ssh-publickey-cert", "publickey-cert", "ssh-publickey", "publickey"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found publickey key cert in secret %v/%v", to.PrivateKeySecret.Name, k)
				publicKey = data
				break
			}
		}

		if privateKey != nil {
			u.Auth = libplugin.CreatePrivateKeyAuth(privateKey, publicKey)
			p.cache.Set(conn.UniqueID(), pipe, gocache.DefaultExpiration)
			return u, nil
		}
	} else if to.PasswordSecret.Name != "" {
		log.Debugf("mapping to %v password using secret %v", to.Host, to.PasswordSecret.Name)
		secret, err := p.k8sclient.Secrets(pipe.Namespace).Get(context.Background(), to.PasswordSecret.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		anno := pipe.GetAnnotations()
		for _, k := range []string{anno["password_field_name"], "password"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found password in secret %v/%v", to.PasswordSecret.Name, k)
				u.Auth = libplugin.CreatePasswordAuth(data)
				p.cache.Set(conn.UniqueID(), pipe, gocache.DefaultExpiration)
				return u, nil
			}
		}
	} else if originPassword != "" {
		log.Debugf("mapping to %v using user input password", to.Host)
		u.Auth = libplugin.CreatePasswordAuth([]byte(originPassword))
		p.cache.Set(conn.UniqueID(), pipe, gocache.DefaultExpiration)
		return u, nil
	}

	return nil, fmt.Errorf("no password or private key found")
}

func loadStringAndFile(base64orraw string, filepath string) ([][]byte, error) {

	all := make([][]byte, 0, 2)

	if base64orraw != "" {
		data, err := base64.StdEncoding.DecodeString(base64orraw)
		if err != nil {
			data = []byte(base64orraw)
		}

		all = append(all, data)
	}

	if filepath != "" {
		data, err := os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}

		all = append(all, data)
	}

	return all, nil
}

func (p *plugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	user := conn.User()

	pipes, err := p.list()
	if err != nil {
		return nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.Spec.From {
			matched := from.Username == user

			if from.UsernameRegexMatch {
				matched, _ = regexp.MatchString(from.Username, user)
			}

			if !matched {
				continue
			}

			if publicKey == nil && password != "" {

				pwds, err := loadStringAndFile(from.HtpasswdData, from.HtpasswdFile)
				if err != nil {
					return nil, err
				}

				pwdmatched := len(pwds) == 0

				for _, data := range pwds {
					log.Debugf("try to match password using htpasswd")
					auth, err := htpasswd.NewFromReader(bytes.NewReader(data), htpasswd.DefaultSystems, nil)
					if err != nil {
						return nil, err
					}

					if auth.Match(user, password) {
						pwdmatched = true
					}
				}

				if pwdmatched {
					return p.createUpstream(conn, pipe, password)
				}
			}

			log.Debugf("try to match public using authorized key")
			pubkeydata, err := loadStringAndFile(from.AuthorizedKeysData, from.AuthorizedKeysFile)
			if err != nil {
				return nil, err
			}

			for _, rest := range pubkeydata {
				var authedPubkey ssh.PublicKey
				for len(rest) > 0 {
					authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
					if err != nil {
						return nil, err
					}

					if subtle.ConstantTimeCompare(authedPubkey.Marshal(), publicKey) == 1 {
						return p.createUpstream(conn, pipe, "")
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}
