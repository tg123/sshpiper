package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"github.com/tg123/sshpiper/libplugin"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	sshpiper "github.com/tg123/sshpiper/plugin/kubernetes/generated/clientset/versioned"
	piperlister "github.com/tg123/sshpiper/plugin/kubernetes/generated/listers/sshpiper/v1beta1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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

func newKubernetesPlugin() (*plugin, error) {
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
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
			if from.AuthorizedKeysData != "" {
				set["publickey"] = true // found authorized_keys, so we support publickey
			} else {
				set["password"] = true // no authorized_keys, so we support password
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

	hostKeyCallback, err := knownhosts.NewFromReader(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", netaddr)
	if err != nil {
		return err
	}

	return hostKeyCallback(hostname, addr, pub)
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

	if originPassword != "" {
		u.Auth = libplugin.CreatePasswordAuth([]byte(originPassword))
		p.cache.Set(conn.UniqueID(), pipe, gocache.DefaultExpiration)
		return u, nil
	}

	secret, err := p.k8sclient.Secrets(pipe.Namespace).Get(context.Background(), to.PrivateKeySecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	anno := pipe.GetAnnotations()
	k := anno["privatekey_field_name"]
	if k == "" {
		k = "privatekey"
	}

	data := secret.Data[k]
	if data != nil {
		u.Auth = libplugin.CreatePrivateKeyAuth(data)
		p.cache.Set(conn.UniqueID(), pipe, gocache.DefaultExpiration)
		return u, nil
	}

	return nil, fmt.Errorf("no password or private key found")
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
				return p.createUpstream(conn, pipe, password)
			}

			rest, err := base64.StdEncoding.DecodeString(from.AuthorizedKeysData)
			if err != nil {
				return nil, err
			}

			var authedPubkey ssh.PublicKey
			for len(rest) > 0 {
				authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return nil, err
				}

				if bytes.Equal(authedPubkey.Marshal(), publicKey) {
					return p.createUpstream(conn, pipe, "")
				}
			}
		}
	}

	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}
