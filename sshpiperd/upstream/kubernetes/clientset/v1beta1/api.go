package v1beta1

import (
  "github.com/tg123/sshpiper/sshpiperd/upstream/kubernetes/api/types/v1beta1"
  "k8s.io/apimachinery/pkg/runtime/schema"
  "k8s.io/client-go/kubernetes/scheme"
  "k8s.io/client-go/rest"
)

type SshPipeV1Beta1Interface interface {
  SshPipes(namespace string) SshPipeInterface
}

type SshPipeV1Beta1Client struct {
  restClient rest.Interface
}

func NewForConfig(c *rest.Config) (*SshPipeV1Beta1Client, error) {
  config := *c
  config.ContentConfig.GroupVersion = &schema.GroupVersion{Group: v1beta1.GroupName, Version: v1beta1.GroupVersion}
  config.APIPath = "/apis"
  config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
  config.UserAgent = rest.DefaultKubernetesUserAgent()

  client, err := rest.RESTClientFor(&config)
  if err != nil {
    return nil, err
  }

  return &SshPipeV1Beta1Client{restClient: client}, nil
}

func (c *SshPipeV1Beta1Client) SshPipes(namespace string) SshPipeInterface{
  return &sshPipeClient{
    restClient: c.restClient,
    ns:         namespace,
  }
}
