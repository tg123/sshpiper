package kubernetes

import (
  "context"
  "fmt"
  "net"
  //"path/filepath"
  "strings"

  "github.com/tg123/sshpiper/sshpiperd/upstream"
  "golang.org/x/crypto/ssh"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/client-go/kubernetes"
  "k8s.io/client-go/rest"
  //"k8s.io/client-go/util/homedir"
  //"k8s.io/client-go/tools/clientcmd"

)

type pipeConfig struct {
  Username      string `kubernetes:"username"`
  UpstreamHost  string `kubernetes:"upstream_host"`
}

type createPipeCtx struct {
  pipe             pipeConfig
  conn             ssh.ConnMetadata
  challengeContext ssh.AdditionalChallengeContext
}

func (p *plugin) getClientSet() (*kubernetes.Clientset, error) {
  /*
  var kubeconfig string
  home := homedir.HomeDir()
  kubeconfig = filepath.Join(home, ".kube", "config")

  // use the current context in kubeconfig
  config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
  if err != nil {
    return nil, err
  }
  */
  config, err := rest.InClusterConfig()
  if err != nil {
    return nil, err
  }

  // create the clientset
  clientset, err := kubernetes.NewForConfig(config)
  if err != nil {
    return nil, err
  }

  return clientset, nil
}

func (p *plugin) getConfig(clientset *kubernetes.Clientset) ([]pipeConfig, error) {
  labelSelector := fmt.Sprintf("pockost.com/test")

  listOptions := metav1.ListOptions{
    LabelSelector: labelSelector,
  }

  pods, err := clientset.CoreV1().Pods("").List(context.TODO(), listOptions)
  if err != nil {
    return nil, err
  }
  var config []pipeConfig
  for _, pod := range pods.Items {
    accounts := strings.Split(pod.Labels["pockost.com/test"], ".")
    for _, account := range accounts {
      user := strings.Split(account, "_")
      config = append(
        config,
        pipeConfig{
          Username: user[0],
          UpstreamHost: fmt.Sprintf("%s:%d", pod.Status.PodIP, 2222),
        },
      )
    }

  }

  return config, nil
}

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (*ssh.AuthPipe, error) {
  hostKeyCallback := ssh.InsecureIgnoreHostKey()

  a := &ssh.AuthPipe{
    User: pipe.Username,
    UpstreamHostKeyCallback: hostKeyCallback,
  }

  a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
    return ssh.AuthPipeTypePassThrough, nil, nil
  }

  return a, nil
}

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
  user := conn.User()

  clientset, err := p.getClientSet()
  if err != nil {
    return nil, nil, err
  }

  // Get config from k8s
  config, err := p.getConfig(clientset)
  if err != nil {
    return nil, nil, err
  }

  // Retreive corresponding configuration
  for _, pipe := range config {
    matched := pipe.Username == user

    if matched {
      c, err := upstream.DialForSSH(pipe.UpstreamHost)
      if err != nil {
        return nil, nil, err
      }

      a, err := p.createAuthPipe(pipe, conn, challengeContext)
      if err != nil {
        return nil, nil, err
      }

      logger.Printf("Forwarding connection to [%v] for user [%v]", pipe.UpstreamHost, pipe.Username)
      return c, a, nil
    }
  }

  return nil, nil, fmt.Errorf("username not [%v] found", user)
}
