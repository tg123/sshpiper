package kubernetes

import (
	"context"
	"fmt"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Return All pipes inside upstream
func (p *plugin) ListPipe() ([]upstream.Pipe, error) {
	pipes := []upstream.Pipe{}
	clientset, err := p.getClientSet()
	if err != nil {
		return nil, err
	}
	pipeList, err := clientset.PockostV1beta1().SshPipes("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, p := range pipeList.Items {
		targetHost := fmt.Sprintf("%s.%s", p.Spec.Target.Name, p.ObjectMeta.Namespace)
		pipes = append(pipes, upstream.Pipe{
			Username:         p.Name,
			UpstreamUsername: p.Spec.Users[0],
			Host:             targetHost,
			Port:             22,
		})
	}
	return pipes, nil
}

// Create a pipe inside upstream
func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	return nil
}

// Remove a pipe from upstream
func (p *plugin) RemovePipe(name string) error {
	clientset, err := p.getClientSet()
	if err != nil {
		return err
	}
	pipeList, err := clientset.PockostV1beta1().SshPipes("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, p := range pipeList.Items {
		if p.Name == name {
			return clientset.PockostV1beta1().SshPipes(p.ObjectMeta.Namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
		}
	}

	return fmt.Errorf("SSH Pipe [%s] not found", name)
}
