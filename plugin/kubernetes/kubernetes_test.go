package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeConn struct {
	user string
}

func (f fakeConn) User() string        { return f.user }
func (fakeConn) RemoteAddr() string    { return "" }
func (fakeConn) UniqueID() string      { return "" }
func (fakeConn) GetMeta(string) string { return "" }

func TestLoadStringAndFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "data")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	inline := base64.StdEncoding.EncodeToString([]byte("inline"))
	parts, err := loadStringAndFile(inline, path)
	if err != nil {
		t.Fatalf("loadStringAndFile returned error: %v", err)
	}

	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}

	if string(parts[0]) != "inline" {
		t.Fatalf("unexpected inline part: %q", string(parts[0]))
	}

	if string(parts[1]) != "from-file" {
		t.Fatalf("unexpected file part: %q", string(parts[1]))
	}
}

func TestMatchConnRegexPrivateKey(t *testing.T) {
	pipe := &piperv1beta1.Pipe{
		Spec: piperv1beta1.PipeSpec{
			From: []piperv1beta1.FromSpec{{
				Username:           "user(.*)",
				UsernameRegexMatch: true,
			}},
			To: piperv1beta1.ToSpec{
				Username:         "dest$1",
				Host:             "example",
				PrivateKeySecret: corev1.LocalObjectReference{Name: "ignored"},
			},
		},
	}

	w := &skelpipeFromWrapper{
		plugin: &plugin{},
		pipe:   pipe,
		from:   &pipe.Spec.From[0],
		to:     &pipe.Spec.To,
	}

	to, err := w.MatchConn(fakeConn{user: "user123"})
	if err != nil {
		t.Fatalf("MatchConn returned error: %v", err)
	}

	priv, ok := to.(*skelpipeToPrivateKeyWrapper)
	if !ok {
		t.Fatalf("expected private key wrapper, got %T", to)
	}

	if priv.username != "dest123" {
		t.Fatalf("unexpected mapped username: %q", priv.username)
	}
}

func TestAuthorizedKeysFromSecretWithAnnotation(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "authkeys",
			Namespace: "ns",
		},
		Data: map[string][]byte{
			"custom-key": []byte("secret-key"),
		},
	}

	client := fake.NewClientset(secret)

	pipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Annotations: map[string]string{
				"sshpiper.com/authorizedkeys_field_name": "custom-key",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			From: []piperv1beta1.FromSpec{{
				AuthorizedKeysData:   base64.StdEncoding.EncodeToString([]byte("inline")),
				AuthorizedKeysSecret: corev1.LocalObjectReference{Name: "authkeys"},
			}},
			To: piperv1beta1.ToSpec{},
		},
	}

	w := &skelpipePublicKeyWrapper{
		skelpipeFromWrapper: skelpipeFromWrapper{
			plugin: &plugin{k8sclient: client.CoreV1()},
			pipe:   pipe,
			from:   &pipe.Spec.From[0],
			to:     &pipe.Spec.To,
		},
	}

	keys, err := w.AuthorizedKeys(fakeConn{})
	if err != nil {
		t.Fatalf("AuthorizedKeys returned error: %v", err)
	}

	expected := "inline\nsecret-key"
	if string(keys) != expected {
		t.Fatalf("unexpected authorized keys: %q (expected %q)", string(keys), expected)
	}
}

func TestPrivateKeySkipsPublicKeyWhenDisabled(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "keys",
			Namespace: "ns",
		},
		Data: map[string][]byte{
			"ssh-privatekey": []byte("private"),
			"ssh-publickey":  []byte("public"),
		},
	}

	client := fake.NewClientset(secret)

	pipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Annotations: map[string]string{
				"no_ca_publickey": "true",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			To: piperv1beta1.ToSpec{
				Host:             "example",
				PrivateKeySecret: corev1.LocalObjectReference{Name: "keys"},
			},
		},
	}

	w := &skelpipeToPrivateKeyWrapper{
		skelpipeToWrapper: skelpipeToWrapper{
			plugin: &plugin{k8sclient: client.CoreV1()},
			pipe:   pipe,
			to:     &pipe.Spec.To,
		},
	}

	priv, pub, err := w.PrivateKey(fakeConn{})
	if err != nil {
		t.Fatalf("PrivateKey returned error: %v", err)
	}

	if string(priv) != "private" {
		t.Fatalf("unexpected private key: %q", string(priv))
	}

	if pub != nil {
		t.Fatalf("public key should be nil when disabled, got %q", string(pub))
	}
}

func TestOverridePasswordRespectsAnnotation(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "password",
			Namespace: "ns",
		},
		Data: map[string][]byte{
			"custom": []byte("pwd"),
		},
	}

	client := fake.NewClientset(secret)

	pipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Annotations: map[string]string{
				"password_field_name": "custom",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			To: piperv1beta1.ToSpec{
				Host:           "example",
				PasswordSecret: corev1.LocalObjectReference{Name: "password"},
			},
		},
	}

	w := &skelpipeToPasswordWrapper{
		skelpipeToWrapper: skelpipeToWrapper{
			plugin: &plugin{k8sclient: client.CoreV1()},
			pipe:   pipe,
			to:     &pipe.Spec.To,
		},
	}

	pw, err := w.OverridePassword(fakeConn{})
	if err != nil {
		t.Fatalf("OverridePassword returned error: %v", err)
	}

	if string(pw) != "pwd" {
		t.Fatalf("unexpected password: %q", string(pw))
	}
}

func TestParseKubectlExecTarget(t *testing.T) {
	pipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Annotations: map[string]string{
				"sshpiper.com/kubectl_sshd_cmd": "/bin/ash",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			To: piperv1beta1.ToSpec{
				Host: "ops/demo-pod/app",
			},
		},
	}

	target, err := parseKubectlExecTarget(pipe, &pipe.Spec.To)
	if err != nil {
		t.Fatalf("parseKubectlExecTarget returned error: %v", err)
	}

	if target.Namespace != "ops" || target.Pod != "demo-pod" || target.Container != "app" || target.Default != "/bin/ash" {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestMatchConnKubectlExecUsesGeneratedPrivateKey(t *testing.T) {
	pipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pipe",
			Namespace: "default",
			Annotations: map[string]string{
				"sshpiper.com/kubectl_exec_cmd": "true",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			From: []piperv1beta1.FromSpec{{
				Username: "kubectl",
			}},
			To: piperv1beta1.ToSpec{
				Host: "demo-pod",
			},
		},
	}

	w := &skelpipeFromWrapper{
		plugin: &plugin{
			kubeExecPipeToKey:   make(map[string]string),
			kubeExecPrivateKeys: make(map[string]string),
			kubeExecTargets:     make(map[string]kubectlExecTarget),
		},
		pipe: pipe,
		from: &pipe.Spec.From[0],
		to:   &pipe.Spec.To,
	}

	to, err := w.MatchConn(fakeConn{user: "kubectl"})
	if err != nil {
		t.Fatalf("MatchConn returned error: %v", err)
	}

	priv, ok := to.(*skelpipeToPrivateKeyWrapper)
	if !ok {
		t.Fatalf("expected private key wrapper, got %T", to)
	}

	if !strings.Contains(priv.Host(fakeConn{}), ":") {
		t.Fatalf("expected loopback bridge host:port, got %q", priv.Host(fakeConn{}))
	}

	privateKey, publicKey, err := priv.PrivateKey(fakeConn{})
	if err != nil {
		t.Fatalf("PrivateKey returned error: %v", err)
	}
	if len(privateKey) == 0 {
		t.Fatalf("expected generated private key")
	}
	if publicKey != nil {
		t.Fatalf("expected no public key cert for generated key")
	}
}

func TestSyncKubectlExecStateRemovesDeletedAndDisabledPipes(t *testing.T) {
	p := &plugin{
		kubeExecPipeToKey: map[string]string{
			"default/kept":    "pub-kept",
			"default/deleted": "pub-deleted",
			"default/off":     "pub-off",
		},
		kubeExecPrivateKeys: map[string]string{
			"default/kept":    "priv-kept",
			"default/deleted": "priv-deleted",
			"default/off":     "priv-off",
		},
		kubeExecTargets: map[string]kubectlExecTarget{
			"pub-kept":    {Namespace: "default", Pod: "old"},
			"pub-deleted": {Namespace: "default", Pod: "old"},
			"pub-off":     {Namespace: "default", Pod: "old"},
		},
	}

	enabledPipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kept",
			Namespace: "default",
			Annotations: map[string]string{
				"sshpiper.com/kubectl_exec_cmd": "true",
			},
		},
		Spec: piperv1beta1.PipeSpec{
			To: piperv1beta1.ToSpec{Host: "new-pod"},
		},
	}

	disabledPipe := &piperv1beta1.Pipe{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "off",
			Namespace: "default",
		},
		Spec: piperv1beta1.PipeSpec{
			To: piperv1beta1.ToSpec{Host: "ignored"},
		},
	}

	p.syncKubectlExecState([]*piperv1beta1.Pipe{enabledPipe, disabledPipe})

	if _, ok := p.kubeExecPipeToKey["default/deleted"]; ok {
		t.Fatalf("deleted pipe entry should be removed")
	}
	if _, ok := p.kubeExecPipeToKey["default/off"]; ok {
		t.Fatalf("disabled pipe entry should be removed")
	}

	if got := p.kubeExecTargets["pub-kept"].Pod; got != "new-pod" {
		t.Fatalf("expected updated target pod for kept pipe, got %q", got)
	}
}
