package v1beta1

import (
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/apimachinery/pkg/runtime"
  "k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "pockost.com"
const GroupVersion = "v1beta1"

var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: GroupVersion}

func Kind(kind string) schema.GroupKind {
  return SchemeGroupVersion.WithKind(kind).GroupKind()
}

func Resource(resource string) schema.GroupResource {
  return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
  SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
  localSchemeBuilder = &SchemeBuilder
  AddToScheme   = localSchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
  scheme.AddKnownTypes(SchemeGroupVersion,
    &SshPipe{},
    &SshPipeList{},
  )

  metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
  return nil
}
