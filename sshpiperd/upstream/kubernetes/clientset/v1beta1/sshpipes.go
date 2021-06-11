package v1beta1

import (
  "context"
  "time"
  "github.com/tg123/sshpiper/sshpiperd/upstream/kubernetes/api/types/v1beta1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/apimachinery/pkg/watch"
  "k8s.io/client-go/kubernetes/scheme"
  "k8s.io/client-go/rest"
)

type SshPipeInterface interface {
  List(ctx context.Context, opts metav1.ListOptions) (*v1beta1.SshPipeList, error)
  Get(ctx context.Context, name string, options metav1.GetOptions) (*v1beta1.SshPipe, error)
  Create(ctx context.Context, sshpipe *v1beta1.SshPipe, opts metav1.CreateOptions) (*v1beta1.SshPipe, error)
  Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
  // ...
}

type sshPipeClient struct {
  restClient rest.Interface
  ns         string
}

func (c *sshPipeClient) List(ctx context.Context, opts metav1.ListOptions) (result *v1beta1.SshPipeList, err error) {
  var timeout time.Duration
  if opts.TimeoutSeconds != nil {
    timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
  }
  result = &v1beta1.SshPipeList{}
  err = c.restClient.Get().
    Namespace(c.ns).
    Resource("sshpipes").
    VersionedParams(&opts, scheme.ParameterCodec).
    Timeout(timeout).
    Do(ctx).
    Into(result)

  return
}

func (c *sshPipeClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1beta1.SshPipe, error) {
  result := v1beta1.SshPipe{}
  err := c.restClient.
    Get().
    Namespace(c.ns).
    Resource("sshpipes").
    Name(name).
    VersionedParams(&opts, scheme.ParameterCodec).
    Do(ctx).
    Into(&result)

  return &result, err
}

func (c *sshPipeClient) Create(ctx context.Context, sshpipe *v1beta1.SshPipe, opts metav1.CreateOptions) (result *v1beta1.SshPipe, err error) {
  result = &v1beta1.SshPipe{}
  err = c.restClient.Post().
    Namespace(c.ns).
    Resource("sshpipes").
    VersionedParams(&opts, scheme.ParameterCodec).
    Body(sshpipe).
    Do(ctx).
    Into(result)
  return
}

func (c *sshPipeClient) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
  var timeout time.Duration
  if opts.TimeoutSeconds != nil {
    timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
  }
  opts.Watch = true
  return c.restClient.Get().
    Namespace(c.ns).
    Resource("sshpipes").
    VersionedParams(&opts, scheme.ParameterCodec).
    Timeout(timeout).
    Watch(ctx)
}
