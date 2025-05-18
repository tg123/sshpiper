package main

import (
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	sshpiper "github.com/tg123/sshpiper/plugin/kubernetes/generated/clientset/versioned"
	piperlister "github.com/tg123/sshpiper/plugin/kubernetes/generated/listers/sshpiper/v1beta1"
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
	}, nil
}

func (p *plugin) Stop() {
	p.stop <- struct{}{}
}

func (p *plugin) list() ([]*piperv1beta1.Pipe, error) {
	return p.lister.List(labels.Everything())
}
