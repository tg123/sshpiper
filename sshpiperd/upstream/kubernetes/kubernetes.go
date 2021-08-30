package kubernetes

import (
	"context"
	"fmt"
	"net"
	//"path/filepath"
	//"strings"
	"bytes"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	//"k8s.io/client-go/util/homedir"
	//"k8s.io/client-go/tools/clientcmd"
	sshpipeclientset "github.com/saturncloud/sshpipe-k8s-lib/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
)

type pipeConfig struct {
	Username     string `kubernetes:"username"`
	TargetUser   string `kubernetes:"username"`
	UpstreamHost string `kubernetes:"upstream_host"`
	Namespace string `kubernetes:"namespace"`
	SecretName string `kubernetes:"secret_name"`
}

type createPipeCtx struct {
	pipe             pipeConfig
	conn             ssh.ConnMetadata
	challengeContext ssh.AdditionalChallengeContext
}

func (p *plugin) getClientSet() (*sshpipeclientset.Clientset, *kubernetes.Clientset, error) {
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
		return nil, nil, err
	}

	// create the clientset
	clientset, err := sshpipeclientset.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	k8sclient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	return clientset, k8sclient, nil
}

func (p *plugin) getConfig(clientset *sshpipeclientset.Clientset) ([]pipeConfig, error) {
	listOptions := metav1.ListOptions{}

	pipes, err := clientset.PockostV1beta1().SshPipes("").List(context.TODO(), listOptions)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	var config []pipeConfig
	for _, pipe := range pipes.Items {
		var targetHost string
		namespace := pipe.ObjectMeta.Namespace
		targetNamespace := pipe.Spec.Target.Namespace
		if targetNamespace == "" {
			targetNamespace = namespace
		}
		targetHost = fmt.Sprintf("%s.%s", pipe.Spec.Target.Name, targetNamespace)
		mappedUser := pipe.Spec.Target.User
		secretName := pipe.Spec.SecretName

		for _, username := range pipe.Spec.Users {
			var targetUser string = mappedUser
			if targetUser == "" {
				targetUser = username
			}

			config = append(
				config,
				pipeConfig{
					Username:       username,
					TargetUser:     targetUser,
					UpstreamHost:   targetHost,
					Namespace:      namespace,
					SecretName:     secretName,
				},
			)
		}
	}

	return config, nil
}

func (p *plugin) mapPublicKeyFromPipe(conn ssh.ConnMetadata, key ssh.PublicKey, k8sclient *kubernetes.Clientset, pipe pipeConfig) (signer ssh.Signer, err error) {
	user := conn.User()

	defer func() { // print error when func exit
		if err != nil {
			p.logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
		}
	}()

	secret, err := k8sclient.CoreV1().Secrets(pipe.Namespace).Get(context.TODO(), pipe.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var authorizedKeys []byte = secret.Data["authorizedKeys"]

	var authedPubkey ssh.PublicKey

	authedPubkey, _, _, authorizedKeys, err = ssh.ParseAuthorizedKey(authorizedKeys)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(authedPubkey.Marshal(), key.Marshal()) {
		var privateKey []byte = secret.Data["privateKey"]

		var private ssh.Signer
		private, err = ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, err
		}

		// in log may see this twice, one is for query the other is real sign again
		p.logger.Printf("auth succ, using mapped private key for user [%v] from [%v]", user, conn.RemoteAddr())
		return private, nil
	}

	p.logger.Printf("public key auth failed user [%v] from [%v]", conn.User(), conn.RemoteAddr())

	return nil, nil
}

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext, k8sclient *kubernetes.Clientset) (*ssh.AuthPipe, error) {
	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	a := &ssh.AuthPipe{
		User:                    pipe.TargetUser,
		UpstreamHostKeyCallback: hostKeyCallback,
	}

	a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	if pipe.SecretName != "" {
		a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			signer, err := p.mapPublicKeyFromPipe(conn, key, k8sclient, pipe)

			if err != nil || signer == nil {
				// try one
				return ssh.AuthPipeTypeNone, nil, nil
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
		}
	}

	return a, nil
}

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	user := conn.User()

	clientset, k8sclient, err := p.getClientSet()
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

			a, err := p.createAuthPipe(pipe, conn, challengeContext, k8sclient)
			if err != nil {
				return nil, nil, err
			}

			p.logger.Printf("Forwarding connection to [%v] for user [%v]", pipe.UpstreamHost, pipe.TargetUser)
			return c, a, nil
		}
	}

	return nil, nil, fmt.Errorf("username not [%v] found", user)
}
