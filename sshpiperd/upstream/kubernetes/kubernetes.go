package kubernetes

import (
	"context"
	"fmt"
	"net"

	//"path/filepath"
	//"strings"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	//"k8s.io/client-go/util/homedir"
	//"k8s.io/client-go/tools/clientcmd"
	sshpipeclientset "github.com/pockost/sshpipe-k8s-lib/pkg/client/clientset/versioned"
)

type pipeConfig struct {
	Username     string `kubernetes:"username"`
	UpstreamHost string `kubernetes:"upstream_host"`
}

// type createPipeCtx struct {
// 	pipe             pipeConfig
// 	conn             ssh.ConnMetadata
// 	challengeContext ssh.AdditionalChallengeContext
// }

func (p *plugin) getClientSet() (*sshpipeclientset.Clientset, error) {

	// var kubeconfig string
	// home := homedir.HomeDir()
	// kubeconfig = filepath.Join(home, ".kube", "config")

	// // use the current context in kubeconfig
	// config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	// if err != nil {
	// 	return nil, err
	// }
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	// create the clientset
	clientset, err := sshpipeclientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func (p *plugin) getConfig(clientset *sshpipeclientset.Clientset, sshPipeName string) (pipeConfig, error) {
	listOptions := metav1.ListOptions{}

	pipes, err := clientset.PockostV1beta1().SshPipes("").List(context.TODO(), listOptions)
	if err != nil {
		return pipeConfig{}, err
	}

	if err != nil {
		return pipeConfig{}, err
	}

	for _, pipe := range pipes.Items {
		if pipe.Name == sshPipeName {
			targetHost := fmt.Sprintf("%s.%s", pipe.Spec.Target.Name, pipe.ObjectMeta.Namespace)
			return pipeConfig{
				Username:     pipe.Spec.Users[0],
				UpstreamHost: targetHost,
			}, nil
		}
	}

	return pipeConfig{}, fmt.Errorf("sshPipe [%s] not found", sshPipeName)
}

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (*ssh.AuthPipe, error) {
	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	a := &ssh.AuthPipe{
		User:                    pipe.Username,
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
	pipeConfig, err := p.getConfig(clientset, user)
	if err != nil {
		return nil, nil, err
	}

	// Retreive corresponding configuration
	c, err := upstream.DialForSSH(pipeConfig.UpstreamHost)
	if err != nil {
		return nil, nil, err
	}

	a, err := p.createAuthPipe(pipeConfig, conn, challengeContext)
	if err != nil {
		return nil, nil, err
	}

	p.logger.Printf("SSH Pipe [%s] forwarding connection to [%s] with user [%s]", user, pipeConfig.UpstreamHost, pipeConfig.Username)
	return c, a, nil
}
