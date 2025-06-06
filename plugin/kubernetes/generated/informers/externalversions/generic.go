// Code generated by informer-gen. DO NOT EDIT.

package externalversions

import (
	fmt "fmt"

	v1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=sshpiper, Version=v1beta1
	case v1beta1.SchemeGroupVersion.WithResource("pipes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Sshpiper().V1beta1().Pipes().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
